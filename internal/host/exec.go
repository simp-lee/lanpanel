// Package host provides host execution and file mutation primitives.
package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
)

type Command struct {
	Name  string
	Args  []string
	Dir   string
	Env   map[string]string
	Stdin []byte

	DisplayName string
	DisplayArgs []string
}

func (command Command) String() string {
	name := command.Name
	args := command.Args
	if strings.TrimSpace(command.DisplayName) != "" {
		name = command.DisplayName
		args = command.DisplayArgs
	}

	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellToken(name))
	for _, arg := range args {
		parts = append(parts, shellToken(arg))
	}
	return strings.Join(parts, " ")
}

type Result struct {
	Command  Command
	Stdout   string
	Stderr   string
	ExitCode int
}

type Runner interface {
	Run(ctx context.Context, command Command) (Result, error)
}

type PrivilegeStrategy int

const (
	PrivilegeDirect PrivilegeStrategy = iota
	PrivilegeSudo
)

func (strategy PrivilegeStrategy) RequiresSudo() bool {
	return strategy == PrivilegeSudo
}

type Executor struct {
	runner    Runner
	env       map[string]string
	privilege PrivilegeStrategy
}

func NewExecutor(runner Runner, env map[string]string) Executor {
	if runner == nil {
		runner = OSRunner{}
	}

	return Executor{runner: runner, env: cloneEnv(env)}
}

func (executor Executor) WithPrivilege(privilege PrivilegeStrategy) Executor {
	executor.privilege = privilege
	return executor
}

func (executor Executor) Run(ctx context.Context, command Command) (Result, error) {
	if strings.TrimSpace(command.Name) == "" {
		return Result{}, fmt.Errorf("host command name is required")
	}

	command.Args = append([]string(nil), command.Args...)
	command.Stdin = append([]byte(nil), command.Stdin...)
	command.DisplayArgs = append([]string(nil), command.DisplayArgs...)
	command.Env = mergeEnv(executor.env, command.Env)
	if executor.privilege.RequiresSudo() {
		command = executor.privilege.wrap(command)
	}
	return executor.runner.Run(ctx, command)
}

func (executor Executor) AptGet(ctx context.Context, args ...string) (Result, error) {
	return executor.Run(ctx, Command{
		Name: "apt-get",
		Args: append([]string(nil), args...),
		Env: map[string]string{
			"DEBIAN_FRONTEND": "noninteractive",
		},
	})
}

func (executor Executor) Dpkg(ctx context.Context, args ...string) (Result, error) {
	return executor.Run(ctx, Command{Name: "dpkg", Args: append([]string(nil), args...)})
}

func (executor Executor) Systemctl(ctx context.Context, args ...string) (Result, error) {
	return executor.Run(ctx, Command{Name: "systemctl", Args: append([]string(nil), args...)})
}

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, command Command) (Result, error) {
	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	if command.Dir != "" {
		cmd.Dir = command.Dir
	}
	cmd.Env = buildEnvironment(command.Env)
	if len(command.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(command.Stdin)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := Result{
		Command:  command,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode(err),
	}
	if err != nil {
		return result, &CommandError{Result: result, Err: err}
	}

	return result, nil
}

type CommandError struct {
	Result Result
	Err    error
}

func (err *CommandError) Error() string {
	if err == nil {
		return ""
	}
	if errors.Is(err.Err, exec.ErrNotFound) {
		return fmt.Sprintf("%s is not available on this host", err.Result.Command.Name)
	}
	if err.Result.ExitCode > 0 {
		return fmt.Sprintf("%s exited with status %d", err.Result.Command.String(), err.Result.ExitCode)
	}
	return fmt.Sprintf("%s failed: %v", err.Result.Command.String(), err.Err)
}

func (err *CommandError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

func CommandMissing(result Result, err error, commandNames ...string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) {
		names := normalizedCommandNames(commandNames...)
		if len(names) == 0 {
			return true
		}
		attemptedNames := normalizedCommandNames(result.Command.Name)
		var commandErr *CommandError
		if errors.As(err, &commandErr) {
			attemptedNames = append(attemptedNames, normalizedCommandNames(commandErr.Result.Command.Name)...)
		}
		return hasAnyCommandName(attemptedNames, names)
	}

	names := normalizedCommandNames(commandNames...)
	if len(names) == 0 {
		names = normalizedCommandNames(result.Command.DisplayName, result.Command.Name)
	}

	messages := []string{err.Error(), result.Stdout, result.Stderr}
	var commandErr *CommandError
	if errors.As(err, &commandErr) {
		messages = append(messages, commandErr.Result.Stdout, commandErr.Result.Stderr)
		if len(names) == 0 {
			names = normalizedCommandNames(commandErr.Result.Command.DisplayName, commandErr.Result.Command.Name)
		}
	}

	for _, message := range messages {
		text := strings.ToLower(strings.TrimSpace(message))
		if text == "" {
			continue
		}
		for _, name := range names {
			switch {
			case strings.Contains(text, name) && strings.Contains(text, "command not found"):
				return true
			case strings.Contains(text, name) && strings.Contains(text, "executable file not found"):
				return true
			case strings.Contains(text, "unable to execute") && strings.Contains(text, name) && strings.Contains(text, "no such file or directory"):
				return true
			case strings.Contains(text, "env:") && strings.Contains(text, name) && strings.Contains(text, "no such file or directory"):
				return true
			}
		}
	}

	return false
}

func hasAnyCommandName(values []string, candidates []string) bool {
	for _, value := range values {
		for _, candidate := range candidates {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func ProxyEnv(httpProxy string, httpsProxy string, noProxy string) map[string]string {
	env := map[string]string{}
	setProxyEnv(env, "http_proxy", normalizeProxyURLForExternalCommands(httpProxy))
	setProxyEnv(env, "https_proxy", normalizeProxyURLForExternalCommands(httpsProxy))
	setProxyEnv(env, "no_proxy", noProxy)
	if len(env) == 0 {
		return nil
	}
	return env
}

func setProxyEnv(env map[string]string, key string, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	env[key] = trimmed
	env[strings.ToUpper(key)] = trimmed
}

func normalizeProxyURLForExternalCommands(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	parsedURL, err := url.Parse(trimmed)
	if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
		return trimmed
	}

	// Go's httpproxy accepts host[:port], but apt and curl expect proxy env
	// values to be explicit URLs.
	return "http://" + trimmed
}

func buildEnvironment(extra map[string]string) []string {
	base := make(map[string]string)
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		base[key] = value
	}
	for key, value := range extra {
		base[key] = value
	}

	keys := make([]string, 0, len(base))
	for key := range base {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+base[key])
	}
	return env
}

func cloneEnv(env map[string]string) map[string]string {
	if len(env) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(env))
	maps.Copy(cloned, env)
	return cloned
}

func mergeEnv(base map[string]string, overrides map[string]string) map[string]string {
	if len(base) == 0 && len(overrides) == 0 {
		return nil
	}
	merged := cloneEnv(base)
	if merged == nil {
		merged = map[string]string{}
	}
	maps.Copy(merged, overrides)
	return merged
}

func (strategy PrivilegeStrategy) wrap(command Command) Command {
	if !strategy.RequiresSudo() || command.Name == "sudo" {
		return command
	}

	displayName := command.DisplayName
	displayArgs := append([]string(nil), command.DisplayArgs...)
	if strings.TrimSpace(displayName) == "" {
		displayName = command.Name
		displayArgs = append([]string(nil), command.Args...)
	}

	args := []string{"-n"}
	if len(command.Env) > 0 {
		args = append(args, "env")
		args = append(args, envAssignments(command.Env)...)
	}
	args = append(args, command.Name)
	args = append(args, command.Args...)

	return Command{
		Name:        "sudo",
		Args:        args,
		Dir:         command.Dir,
		Stdin:       append([]byte(nil), command.Stdin...),
		DisplayName: displayName,
		DisplayArgs: displayArgs,
	}
}

func envAssignments(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}

	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	assignments := make([]string, 0, len(keys))
	for _, key := range keys {
		assignments = append(assignments, key+"="+env[key])
	}
	return assignments
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}

	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitErr.ExitCode()
	}

	return -1
}

func shellToken(value string) string {
	if value == "" {
		return `""`
	}
	if strings.ContainsAny(value, " \t\n\"'") {
		return strconvQuote(value)
	}
	return value
}

func normalizedCommandNames(commandNames ...string) []string {
	normalized := make([]string, 0, len(commandNames))
	seen := map[string]struct{}{}
	for _, commandName := range commandNames {
		trimmed := strings.ToLower(strings.TrimSpace(commandName))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func strconvQuote(value string) string {
	replacer := strings.NewReplacer(`\\`, `\\\\`, `"`, `\\"`)
	return `"` + replacer.Replace(value) + `"`
}
