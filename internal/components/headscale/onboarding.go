package headscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lanpanel/internal/host"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultUserName             = "lanpanel"
	DefaultPreAuthKeyExpiration = 24 * time.Hour
	MaxPreAuthKeyExpiration     = DefaultPreAuthKeyExpiration
)

var safeUserNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
var sensitiveAuthKeyPattern = regexp.MustCompile(`(?:(?:tskey|hskey|authkey)-|mkey:)[^\s]+`)

type OnboardingOptions struct {
	UserName   string
	Expiration time.Duration
}

type OnboardingPlan struct {
	UserName   string
	Expiration time.Duration
}

type User struct {
	ID   string
	Name string
}

type UserNotFoundError struct {
	UserName string
}

func (err UserNotFoundError) Error() string {
	return fmt.Sprintf("headscale user %q was not found in users list output", err.UserName)
}

type cliUser struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}

type Onboarding struct {
	executor              host.Executor
	readinessTimeout      time.Duration
	readinessPollInterval time.Duration
}

func NewOnboarding(executor host.Executor) Onboarding {
	return Onboarding{
		executor:              executor,
		readinessTimeout:      30 * time.Second,
		readinessPollInterval: time.Second,
	}
}

func NewOnboardingPlan(options OnboardingOptions) (OnboardingPlan, error) {
	userName := strings.TrimSpace(options.UserName)
	if userName == "" {
		userName = DefaultUserName
	}
	if !safeUserNamePattern.MatchString(userName) {
		return OnboardingPlan{}, fmt.Errorf("headscale user name %q must use letters, digits, dot, underscore, or dash and start with a letter or digit", userName)
	}

	expiration := options.Expiration
	if expiration == 0 {
		expiration = DefaultPreAuthKeyExpiration
	}
	if expiration < time.Hour {
		return OnboardingPlan{}, fmt.Errorf("preauthkey expiration must be at least 1h")
	}
	if expiration > MaxPreAuthKeyExpiration {
		return OnboardingPlan{}, fmt.Errorf("preauthkey expiration must be at most %s", durationForCLI(MaxPreAuthKeyExpiration))
	}

	return OnboardingPlan{
		UserName:   userName,
		Expiration: expiration,
	}, nil
}

func HeadscaleCommand(args ...string) host.Command {
	commandArgs := make([]string, 0, len(args)+2)
	commandArgs = append(commandArgs, "--config", ConfigPath)
	commandArgs = append(commandArgs, args...)
	return host.Command{Name: "headscale", Args: commandArgs}
}

func CreateUserCommand(userName string) host.Command {
	return HeadscaleCommand("users", "create", userName)
}

func ListUsersCommand() host.Command {
	return HeadscaleCommand("users", "list", "--output", "json")
}

func CreatePreAuthKeyCommand(userID string, plan OnboardingPlan) host.Command {
	args := []string{"preauthkeys", "create", "--user", strings.TrimSpace(userID), "--expiration", durationForCLI(plan.Expiration), "--reusable=false"}
	return HeadscaleCommand(args...)
}

func (onboarding Onboarding) CreatePreAuthKey(ctx context.Context, plan OnboardingPlan) (string, []host.Result, error) {
	userID, results, err := onboarding.ensureUser(ctx, plan.UserName)
	if err != nil {
		return "", results, err
	}

	keyResult, err := onboarding.executor.Run(ctx, CreatePreAuthKeyCommand(userID, plan))
	results = append(results, keyResult)
	if err != nil {
		return "", results, preAuthKeyCommandError(err)
	}
	key := strings.TrimSpace(keyResult.Stdout)
	if key == "" {
		return "", results, fmt.Errorf("headscale preauthkeys create returned an empty key")
	}
	return key, results, nil
}

func (onboarding Onboarding) EnsureUser(ctx context.Context, userName string) ([]host.Result, error) {
	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: userName})
	if err != nil {
		return nil, err
	}
	_, results, err := onboarding.ensureUser(ctx, plan.UserName)
	return results, err
}

func (onboarding Onboarding) ensureUser(ctx context.Context, userName string) (string, []host.Result, error) {
	results := []host.Result{}
	listResult, err := onboarding.listUsersWhenReady(ctx)
	results = append(results, listResult)
	if err != nil {
		return "", results, err
	}
	userID, err := FindUserID(listResult.Stdout, userName)
	if err == nil {
		return userID, results, nil
	}
	if !userWasNotFound(err) {
		return "", results, err
	}

	createUserResult, createErr := onboarding.executor.Run(ctx, CreateUserCommand(userName))
	results = append(results, createUserResult)
	if createErr != nil && !commandLooksLikeExistingUser(createUserResult, createErr) {
		return "", results, createErr
	}

	listResult, err = onboarding.listUsersWhenReady(ctx)
	results = append(results, listResult)
	if err != nil {
		return "", results, err
	}
	userID, err = FindUserID(listResult.Stdout, userName)
	if err != nil {
		return "", results, err
	}
	return userID, results, nil
}

func (onboarding Onboarding) listUsersWhenReady(ctx context.Context) (host.Result, error) {
	timeout := onboarding.readinessTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	interval := onboarding.readinessPollInterval
	if interval <= 0 {
		interval = time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastResult host.Result
	for {
		result, err := onboarding.executor.Run(ctx, ListUsersCommand())
		if err == nil {
			return result, nil
		}
		lastResult = result
		if !commandLooksLikeTransientHeadscaleCLIReadiness(result, err) {
			return result, err
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastResult, err
		case <-timer.C:
		}
	}
}

func FindUserID(output string, userName string) (string, error) {
	userName = strings.TrimSpace(userName)
	matches := []User{}
	users, err := ParseUsers(output)
	if err != nil {
		return "", err
	}
	for _, user := range users {
		if user.Name == userName {
			matches = append(matches, user)
		}
	}
	if len(matches) > 1 {
		ids := make([]string, 0, len(matches))
		for _, user := range matches {
			ids = append(ids, user.ID)
		}
		return "", fmt.Errorf("headscale user %q matched multiple user IDs: %s", userName, strings.Join(ids, ", "))
	}
	if len(matches) == 1 {
		return matches[0].ID, nil
	}
	return "", UserNotFoundError{UserName: userName}
}

func ParseUsers(output string) ([]User, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, fmt.Errorf("headscale users list returned empty JSON output")
	}

	var users []cliUser
	if err := json.Unmarshal([]byte(output), &users); err == nil {
		return convertCLIUsers(users), nil
	}

	var wrapped struct {
		Users []cliUser `json:"users"`
	}
	if err := json.Unmarshal([]byte(output), &wrapped); err == nil && wrapped.Users != nil {
		return convertCLIUsers(wrapped.Users), nil
	}

	return nil, fmt.Errorf("decode headscale users list JSON output")
}

func convertCLIUsers(cliUsers []cliUser) []User {
	users := make([]User, 0, len(cliUsers))
	for _, user := range cliUsers {
		name := strings.TrimSpace(user.Name)
		if user.ID == 0 || name == "" {
			continue
		}
		users = append(users, User{ID: strconv.FormatUint(user.ID, 10), Name: name})
	}
	return users
}

func commandLooksLikeExistingUser(result host.Result, err error) bool {
	text := strings.ToLower(strings.TrimSpace(result.Stdout + "\n" + result.Stderr + "\n" + err.Error()))
	if strings.Contains(text, "already") && strings.Contains(text, "exist") {
		return true
	}
	return strings.Contains(text, "unique constraint") && strings.Contains(text, "users") && strings.Contains(text, "name")
}

func commandLooksLikeTransientHeadscaleCLIReadiness(result host.Result, err error) bool {
	text := strings.ToLower(strings.TrimSpace(result.Stdout + "\n" + result.Stderr + "\n" + err.Error()))
	if text == "" {
		return false
	}
	switch {
	case strings.Contains(text, "could not connect"):
		return true
	case strings.Contains(text, "context deadline exceeded"):
		return true
	case strings.Contains(text, "connection refused"):
		return true
	case strings.Contains(text, "transport: error while dialing"):
		return true
	case strings.Contains(text, "connect: no such file or directory"):
		return true
	case strings.Contains(text, "no such file or directory") && strings.Contains(text, "headscale.sock"):
		return true
	case strings.Contains(text, "nil pointer") && strings.Contains(text, "newheadscalecliwithconfig"):
		return true
	default:
		return false
	}
}

func preAuthKeyCommandError(err error) error {
	if err == nil {
		return nil
	}
	message := maskSensitiveAuthKeys(err.Error())
	return errors.New(message)
}

func maskSensitiveAuthKeys(text string) string {
	return sensitiveAuthKeyPattern.ReplaceAllString(text, "<redacted>")
}

func userWasNotFound(err error) bool {
	var notFound UserNotFoundError
	return err != nil && errors.As(err, &notFound)
}

func durationForCLI(duration time.Duration) string {
	if duration%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(duration/time.Hour))
	}
	if duration%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(duration/time.Minute))
	}
	return duration.String()
}
