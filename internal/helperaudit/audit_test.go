package helperaudit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrivilegedProcessBoundary(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve audit source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if err := Run(root); err != nil {
		t.Fatal(err)
	}
}

func TestSemanticProcessBypasses(t *testing.T) {
	tests := []struct {
		name          string
		errorContains string
		mutate        func(t *testing.T, root string)
	}{
		{
			name: "aliased import outside boundary",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/other/other.go", `package other
import process "os/exec"
func bypass() { _ = process.Command("/bin/echo") }
`)
			},
		},
		{
			name: "nested helperaudit package name",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/other/internal/helperaudit/bypass.go", `package helperaudit
import "os/exec"
func bypass() { _ = exec.Command("/bin/echo") }
`)
			},
		},
		{
			name: "command constructor function alias",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `command := exec.Command(launcher.self, "child-executor")`, `constructor := exec.Command
	command := constructor(launcher.self, "child-executor")`)
			},
		},
		{
			name: "unix exec function alias",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `func ExecuteBootstrap() error {
	profile := Profile{}
	argv := append([]string{profile.Executable}, profile.Arguments...)
	return unix.Exec(profile.Executable, argv, profile.Environment)
}`, `func ExecuteBootstrap() error {
	profile := Profile{}
	argv := append([]string{profile.Executable}, profile.Arguments...)
	launch := unix.Exec
	return launch(profile.Executable, argv, profile.Environment)
}`)
			},
		},
		{
			name: "selector passed as argument",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/other/other.go", `package other
import "os/exec"
func accept(any) {}
func bypass() { accept(exec.Command) }
`)
			},
		},
		{
			name: "selector stored in field",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/other/other.go", `package other
import "os/exec"
var holder = struct{ launch any }{launch: exec.Command}
`)
			},
		},
		{
			name: "function alias from skipped audit package",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/helperaudit/alias.go", `package helperaudit
import "golang.org/x/sys/unix"
var Execute = unix.Exec
`)
				writeFixtureFile(t, root, "internal/other/other.go", `package other
import audit "fixture/internal/helperaudit"
func bypass() error { return audit.Execute("/bin/echo", []string{"echo"}, nil) }
`)
			},
		},
		{
			name: "Cmd imported type alias",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/helperaudit/alias.go", `package helperaudit
import "os/exec"
type Command = exec.Cmd
`)
				writeFixtureFile(t, root, "internal/other/other.go", `package other
import audit "fixture/internal/helperaudit"
func bypass() error { command := audit.Command{Path: "/bin/echo"}; return command.Run() }
`)
			},
		},
		{
			name: "Cmd composite literal",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/other/other.go", `package other
import "os/exec"
var command = exec.Cmd{}
`)
			},
		},
		{
			name: "Cmd new construction",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/other/other.go", `package other
import "os/exec"
var command = new(exec.Cmd)
`)
			},
		},
		{
			name: "method value",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `if err := command.Start(); err != nil {`, `run := command.Run
	_ = run
	if err := command.Start(); err != nil {`)
			},
		},
		{
			name: "pipe method",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `if err := command.Start(); err != nil {`, `_, _ = command.StdinPipe()
	if err := command.Start(); err != nil {`)
			},
		},
		{
			name: "method expression",
			mutate: func(t *testing.T, root string) {
				writeFixtureFile(t, root, "internal/other/other.go", `package other
import "os/exec"
var run = (*exec.Cmd).Run
`)
			},
		},
		{
			name: "reflection escape",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `"os/exec"`, `"os/exec"
	"reflect"`)
				replaceFixture(t, root, "internal/child/executor_linux.go", `if err := command.Start(); err != nil {`, `reflect.ValueOf(command).MethodByName("Run").Call(nil)
	if err := command.Start(); err != nil {`)
			},
		},
		{
			name: "command alias",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `if err := command.Start(); err != nil {`, `other := command
	_ = other
	if err := command.Start(); err != nil {`)
			},
		},
		{
			name:          "missing child configuration",
			errorContains: "census mismatch for child Env",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `	command.Env = []string{}
`, ``)
			},
		},
		{
			name:          "missing child extra files",
			errorContains: "census mismatch for child ExtraFiles",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `	command.ExtraFiles = []*os.File{instructionRead, inputRead}
`, "\t_, _ = instructionRead, inputRead\n")
			},
		},
		{
			name:          "missing child process attributes",
			errorContains: "census mismatch for child SysProcAttr",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
`, "\t_ = syscall.SIGKILL\n")
			},
		},
		{
			name:          "missing child output",
			errorContains: "census mismatch for child output",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `	command.Stdout, command.Stderr = stdout, stderr
`, "\t_, _ = stdout, stderr\n")
			},
		},
		{
			name:          "missing build directory",
			errorContains: "census mismatch for generator build Dir",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/qualification/generator_linux.go", `	command.Dir = root
`, ``)
			},
		},
		{
			name:          "missing build environment",
			errorContains: "census mismatch for generator build Env",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/qualification/generator_linux.go", `	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOENV=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off"}
`, "\t_ = os.Getenv\n")
			},
		},
		{
			name: "shadowed launcher argument",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `func (launcher *Launcher) RunInvocation() error {`, `func (receiver *Launcher) RunInvocation() error {
	launcher := &Launcher{self: "/bin/echo"}`)
			},
		},
		{
			name: "mutable command path",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `command.Env = []string{}`, `command.Env = []string{}
	command.Path = "/bin/echo"`)
			},
		},
		{
			name: "mutable arguments alias",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `command.Env = []string{}`, `command.Env = []string{}
	arguments := command.Args
	arguments[0] = "/bin/echo"`)
			},
		},
		{
			name: "Git arguments without append",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/qualification/generator_linux.go", `exec.Command("git", append([]string{"-C", root}, arguments...)...)`, `exec.Command("git", arguments...)`)
			},
		},
		{
			name: "unapproved launch method",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `if err := command.Start(); err != nil {`, `if err := command.Run(); err != nil {
		return err
	}
	if err := command.Start(); err != nil {`)
			},
		},
		{
			name: "shadowed Go executable",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/qualification/generator_linux.go", `command := exec.Command(goBinary, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -X main.version="+releaseTag, "-o", destination, "./cmd/lanpanel")
	command.Dir = root
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOENV=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off"}
	_, err = command.CombinedOutput()
	return err`, `{
		goBinary := root + "/fake-go"
		command := exec.Command(goBinary, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -X main.version="+releaseTag, "-o", destination, "./cmd/lanpanel")
		command.Dir = root
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOENV=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off"}
		_, err = command.CombinedOutput()
		return err
	}`)
			},
		},
		{
			name: "reassigned Go executable",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/qualification/generator_linux.go", `if err != nil {
		return err
	}
	command := exec.Command(goBinary`, `if err != nil {
		return err
	}
	goBinary = root + "/fake-go"
	command := exec.Command(goBinary`)
			},
		},
		{
			name:          "launcher receiver type alias",
			errorContains: "outside the fixed boundary",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `type Launcher struct{ self string }`, `type AlternateLauncher struct{ self string }
type Launcher = AlternateLauncher`)
			},
		},
		{
			name: "decoy launcher receiver",
			mutate: func(t *testing.T, root string) {
				replaceFixture(t, root, "internal/child/executor_linux.go", `type Launcher struct{ self string }`, `type Launcher struct{ self string }
type Other struct{ self string }`)
				replaceFixture(t, root, "internal/child/executor_linux.go", `(launcher *Launcher) RunInvocation`, `(launcher *Other) RunInvocation`)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := writeAuditFixture(t)
			test.mutate(t, root)
			err := Run(root)
			if err == nil {
				t.Fatal("semantic process bypass passed the audit")
			}
			if test.errorContains != "" && !strings.Contains(err.Error(), test.errorContains) {
				t.Fatalf("unexpected audit error: %v", err)
			}
		})
	}
}

func TestImportAliasesDoNotChangeApprovedBoundary(t *testing.T) {
	root := writeAuditFixture(t)
	for _, path := range []string{"internal/child/executor_linux.go", "internal/qualification/generator_linux.go"} {
		replaceFixture(t, root, path, `"os/exec"`, `process "os/exec"`)
		replaceAllFixture(t, root, path, "exec.", "process.")
	}
	replaceFixture(t, root, "internal/child/executor_linux.go", `"golang.org/x/sys/unix"`, `kernel "golang.org/x/sys/unix"`)
	replaceAllFixture(t, root, "internal/child/executor_linux.go", "unix.Exec", "kernel.Exec")
	replaceFixture(t, root, "internal/process/managed_exec_linux.go", `"golang.org/x/sys/unix"`, `kernel "golang.org/x/sys/unix"`)
	replaceFixture(t, root, "internal/process/managed_exec_linux.go", "unix.Exec", "kernel.Exec")
	if err := Run(root); err != nil {
		t.Fatalf("approved import aliases changed the semantic boundary: %v", err)
	}
}

func TestAuditBuildEnvironmentIsFixed(t *testing.T) {
	root := writeAuditFixture(t)
	t.Setenv("GO111MODULE", "off")
	t.Setenv("GOOS", "windows")
	t.Setenv("GOARCH", "arm64")
	t.Setenv("GOAMD64", "v3")
	t.Setenv("GOEXPERIMENT", "ambient-experiment")
	t.Setenv("GOFLAGS", "-tags=ambient")
	t.Setenv("GONOPROXY", "*")
	t.Setenv("GOPRIVATE", "*")
	t.Setenv("GOROOT", "/ambient/old-go")
	if err := Run(root); err != nil {
		t.Fatalf("ambient Go settings changed package loading: %v", err)
	}
	observed := map[string]string{}
	for _, entry := range offlineGoEnvironment() {
		name, value, _ := strings.Cut(entry, "=")
		observed[name] = value
	}
	for name, expected := range map[string]string{
		"CGO_ENABLED": "0", "GO111MODULE": "on", "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GOENV": "off", "GOEXPERIMENT": "", "GOFLAGS": "",
		"GONOPROXY": "", "GOPRIVATE": "", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off",
	} {
		value, present := observed[name]
		if !present || value != expected {
			t.Fatalf("%s=%q (present=%t), want %q", name, value, present, expected)
		}
	}
	selected := map[string]string{}
	for _, entry := range goToolchainEnvironment() {
		name, value, _ := strings.Cut(entry, "=")
		selected[name] = value
	}
	if _, present := observed["GOROOT"]; present {
		t.Fatalf("offline package environment retained GOROOT: %#v", observed)
	}
	if selected["GOTOOLCHAIN"] != "auto" || selected["GOPROXY"] != "off" || selected["GOSUMDB"] != "sum.golang.org" {
		t.Fatalf("toolchain selection environment = %#v", selected)
	}
	if _, present := selected["GOROOT"]; present {
		t.Fatalf("toolchain selection environment retained GOROOT: %#v", selected)
	}
}

func TestAuditUsesFixedLinuxAMD64Files(t *testing.T) {
	root := writeAuditFixture(t)
	t.Setenv("GOOS", "windows")
	t.Setenv("GOARCH", "arm64")
	t.Setenv("GOAMD64", "v3")
	writeFixtureFile(t, root, "internal/other/tagged.go", `//go:build linux && amd64 && !amd64.v2

package other

import "os/exec"

func bypass() { _ = exec.Command("/bin/echo") }
`)
	if err := Run(root); err == nil {
		t.Fatal("ambient platform settings excluded the fixed Linux/amd64 file")
	}
}

func TestUnrelatedSelectorsAreIgnored(t *testing.T) {
	root := writeAuditFixture(t)
	writeFixtureFile(t, root, "internal/other/other.go", `package other
type localAPI struct{}
func (localAPI) Command(string) {}
func harmless() { var exec localAPI; run := exec.Command; run("value") }
`)
	if err := Run(root); err != nil {
		t.Fatalf("unrelated selector was treated as a process API: %v", err)
	}
}

func writeAuditFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod": `module fixture

go 1.26

require golang.org/x/sys v0.0.0
replace golang.org/x/sys => ./third_party/xsys
`,
		"third_party/xsys/go.mod": `module golang.org/x/sys

go 1.26
`,
		"third_party/xsys/unix/unix.go": `package unix
func Exec(string, []string, []string) error { return nil }
func ForkExec(string, []string, any) (int, error) { return 0, nil }
`,
		"internal/helperproto/types.go": `package helperproto
type Request struct {
	SchemaVersion string
	RequestID string
	Operation string
	Target string
	IntentGeneration uint64
	Deadline string
	InputDigest string
	Action string
	Resource string
}
`,
		"internal/child/executor_linux.go": `package child
import (
	"bytes"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)
type Launcher struct{ self string }
type Profile struct{ Executable string; Arguments, Environment []string }
func (launcher *Launcher) RunInvocation() error {
	instructionRead, inputRead := new(os.File), new(os.File)
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	command := exec.Command(launcher.self, "child-executor")
	command.Env = []string{}
	command.ExtraFiles = []*os.File{instructionRead, inputRead}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Start(); err != nil {
		return err
	}
	return nil
}
func ExecuteBootstrap() error {
	profile := Profile{}
	argv := append([]string{profile.Executable}, profile.Arguments...)
	return unix.Exec(profile.Executable, argv, profile.Environment)
}
func ExecutePersistentProfile() error {
	profile := Profile{}
	argv := append([]string{profile.Executable}, profile.Arguments...)
	return unix.Exec(profile.Executable, argv, profile.Environment)
}
`,
		"internal/process/managed_exec_linux.go": `package process
import "golang.org/x/sys/unix"
type Service struct{ Executable string; Arguments []string }
type Authority struct{ Service Service }
func Execute() error {
	authority := Authority{}
	environment := []string{"LANG=C", "LC_ALL=C"}
	argv := append([]string{authority.Service.Executable}, authority.Service.Arguments...)
	return unix.Exec(authority.Service.Executable, argv, environment)
}
`,
		"internal/qualification/generator_linux.go": `package qualification
import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)
func requireExactCleanCommit(root, expected string) error {
	commands := [][]string{{"diff", "--quiet", "HEAD", "--"}, {"diff", "--cached", "--quiet", "HEAD", "--"}}
	for _, arguments := range commands {
		command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
		if err := command.Run(); err != nil {
			return fmt.Errorf("unclean")
		}
	}
	untracked := exec.Command("git", "-C", root, "ls-files", "--others", "--exclude-standard", "-z")
	output, err := untracked.Output()
	if err != nil || len(output) != 0 {
		return fmt.Errorf("untracked")
	}
	head := exec.Command("git", "-C", root, "rev-parse", "--verify", "HEAD")
	output, err = head.Output()
	if err != nil || strings.TrimSpace(string(output)) != expected {
		return fmt.Errorf("head")
	}
	return nil
}
func buildCandidate(root, releaseTag, destination string) error {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		return err
	}
	command := exec.Command(goBinary, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -X main.version="+releaseTag, "-o", destination, "./cmd/lanpanel")
	command.Dir = root
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOENV=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off"}
	_, err = command.CombinedOutput()
	return err
}
`,
		"cmd/app/main.go": "package main\nfunc main() {}\n",
	}
	for path, content := range files {
		writeFixtureFile(t, root, path, content)
	}
	return root
}

func replaceFixture(t *testing.T, root, path, oldText, newText string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), oldText) != 1 {
		t.Fatalf("fixture replacement in %s is not unique", path)
	}
	if err := os.WriteFile(fullPath, []byte(strings.Replace(string(data), oldText, newText, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func replaceAllFixture(t *testing.T, root, path, oldText, newText string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), oldText) {
		t.Fatalf("fixture replacement in %s was not found", path)
	}
	if err := os.WriteFile(fullPath, []byte(strings.ReplaceAll(string(data), oldText, newText)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFixtureFile(t *testing.T, root, path, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
