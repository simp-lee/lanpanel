package headscale

import (
	"context"
	"errors"
	"lanpanel/internal/host"
	"strings"
	"testing"
	"time"
)

func TestNewOnboardingPlanDefaultsAndValidatesUserName(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	if plan.UserName != DefaultUserName {
		t.Fatalf("UserName = %q, want %q", plan.UserName, DefaultUserName)
	}
	if plan.Expiration != DefaultPreAuthKeyExpiration {
		t.Fatalf("Expiration = %v, want %v", plan.Expiration, DefaultPreAuthKeyExpiration)
	}

	if _, err := NewOnboardingPlan(OnboardingOptions{UserName: "../bad"}); err == nil {
		t.Fatal("NewOnboardingPlan() error = nil, want invalid user name failure")
	}
	if _, err := NewOnboardingPlan(OnboardingOptions{Expiration: 30 * time.Minute}); err == nil {
		t.Fatal("NewOnboardingPlan() error = nil, want short expiration failure")
	}
	if _, err := NewOnboardingPlan(OnboardingOptions{Expiration: MaxPreAuthKeyExpiration + time.Hour}); err == nil {
		t.Fatal("NewOnboardingPlan() error = nil, want long expiration failure")
	}
}

func TestHeadscaleCommandsUseLocalConfigPath(t *testing.T) {
	t.Parallel()

	create := CreateUserCommand("lanpanel")
	if create.Name != "headscale" {
		t.Fatalf("Name = %q, want headscale", create.Name)
	}
	if got := strings.Join(create.Args, " "); got != "--config /etc/headscale/config.yaml users create lanpanel" {
		t.Fatalf("Args = %q", got)
	}

	list := ListUsersCommand()
	if got := strings.Join(list.Args, " "); got != "--config /etc/headscale/config.yaml users list --output json" {
		t.Fatalf("Args = %q", got)
	}

	plan, err := NewOnboardingPlan(OnboardingOptions{Expiration: MaxPreAuthKeyExpiration})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	keyCommand := CreatePreAuthKeyCommand("2", plan)
	if got := strings.Join(keyCommand.Args, " "); got != "--config /etc/headscale/config.yaml preauthkeys create --user 2 --expiration 24h --reusable=false" {
		t.Fatalf("Args = %q", got)
	}
}

func TestParseUsersRejectsNonJSONOutput(t *testing.T) {
	t.Parallel()

	output := `
ID | Name    | Created
1  | admin   | 2026-01-01
2  | lanpanel | 2026-01-02
`
	if _, err := FindUserID(output, "lanpanel"); err == nil {
		t.Fatal("FindUserID() error = nil, want non-JSON failure")
	}
}

func TestParseUsersFindsUserIDFromJSONOutput(t *testing.T) {
	t.Parallel()

	output := `[{"id":1,"name":"admin"},{"id":2,"name":"lanpanel","display_name":"Lanpanel Day 1"}]`
	userID, err := FindUserID(output, "lanpanel")
	if err != nil {
		t.Fatalf("FindUserID() error = %v", err)
	}
	if userID != "2" {
		t.Fatalf("userID = %q, want 2", userID)
	}
}

func TestFindUserIDRejectsAmbiguousJSONOutput(t *testing.T) {
	t.Parallel()

	output := `[{"id":2,"name":"lanpanel"},{"id":3,"name":"lanpanel"}]`
	_, err := FindUserID(output, "lanpanel")
	if err == nil {
		t.Fatal("FindUserID() error = nil, want ambiguous user failure")
	}
	if !strings.Contains(err.Error(), "matched multiple user IDs: 2, 3") {
		t.Fatalf("FindUserID() error = %q, want ambiguity detail", err.Error())
	}
}

func TestOnboardingCreatePreAuthKeyUsesUserIDAndReturnsKey(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	runner := &scriptedRunner{
		results: []host.Result{
			{Stdout: `[{"id":2,"name":"lanpanel"}]` + "\n"},
			{Stdout: "hskey-auth-example\n"},
		},
	}
	onboarding := NewOnboarding(host.NewExecutor(runner, nil))

	key, results, err := onboarding.CreatePreAuthKey(context.Background(), plan)
	if err != nil {
		t.Fatalf("CreatePreAuthKey() error = %v", err)
	}
	if key != "hskey-auth-example" {
		t.Fatalf("key = %q", key)
	}
	if len(results) != 2 || len(runner.commands) != 2 {
		t.Fatalf("results = %d commands = %d, want 2", len(results), len(runner.commands))
	}
	if got := strings.Join(runner.commands[0].Args, " "); !strings.Contains(got, "users list --output json") {
		t.Fatalf("first command args = %q, want users list", got)
	}
	if got := strings.Join(runner.commands[1].Args, " "); !strings.Contains(got, "preauthkeys create --user 2") {
		t.Fatalf("preauth command args = %q", got)
	}
	if got := strings.Join(runner.commands[1].Args, " "); strings.Contains(got, "--reusable ") || !strings.Contains(got, "--reusable=false") {
		t.Fatalf("preauth command args = %q, want explicit non-reusable key", got)
	}
}

func TestOnboardingCreatesMissingUserBeforePreAuthKey(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	runner := &scriptedRunner{
		results: []host.Result{
			{Stdout: `[]` + "\n"},
			{},
			{Stdout: `[{"id":2,"name":"lanpanel"}]` + "\n"},
			{Stdout: "hskey-auth-example\n"},
		},
	}
	onboarding := NewOnboarding(host.NewExecutor(runner, nil))

	if _, _, err := onboarding.CreatePreAuthKey(context.Background(), plan); err != nil {
		t.Fatalf("CreatePreAuthKey() error = %v", err)
	}
	if len(runner.commands) != 4 {
		t.Fatalf("commands = %d, want 4", len(runner.commands))
	}
	if got := strings.Join(runner.commands[1].Args, " "); !strings.Contains(got, "users create lanpanel") {
		t.Fatalf("create command args = %q", got)
	}
	if got := strings.Join(runner.commands[3].Args, " "); !strings.Contains(got, "preauthkeys create --user 2") {
		t.Fatalf("preauth command args = %q", got)
	}
}

func TestOnboardingEnsureUserDoesNotCreatePreAuthKey(t *testing.T) {
	t.Parallel()

	runner := &scriptedRunner{
		results: []host.Result{
			{Stdout: `[]` + "\n"},
			{},
			{Stdout: `[{"id":2,"name":"lanpanel"}]` + "\n"},
		},
	}
	onboarding := NewOnboarding(host.NewExecutor(runner, nil))

	results, err := onboarding.EnsureUser(context.Background(), "lanpanel")
	if err != nil {
		t.Fatalf("EnsureUser() error = %v", err)
	}
	if len(results) != 3 || len(runner.commands) != 3 {
		t.Fatalf("results = %d commands = %d, want 3", len(results), len(runner.commands))
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.Args, " "), "preauthkeys create") {
			t.Fatalf("EnsureUser command args = %q, must not create preauth key", strings.Join(command.Args, " "))
		}
	}
}

func TestOnboardingIgnoresExistingUserCreateFailure(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	runner := &scriptedRunner{
		results: []host.Result{
			{Stdout: `[]` + "\n"},
			{Stderr: "Cannot create user: failed to create user: creating user: UNIQUE constraint failed: users.name"},
			{Stdout: `[{"id":2,"name":"lanpanel"}]` + "\n"},
			{Stdout: "hskey-auth-example\n"},
		},
		errors: map[int]error{1: errors.New("exit status 1")},
	}
	onboarding := NewOnboarding(host.NewExecutor(runner, nil))

	if _, _, err := onboarding.CreatePreAuthKey(context.Background(), plan); err != nil {
		t.Fatalf("CreatePreAuthKey() error = %v", err)
	}
}

func TestOnboardingCommandErrorsOmitCommandOutput(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	runner := &scriptedRunner{
		results: []host.Result{
			{Stderr: "Cannot get users: database is locked\ntrace detail"},
		},
		errors: map[int]error{0: errors.New("exit status 1")},
	}
	onboarding := NewOnboarding(host.NewExecutor(runner, nil))

	_, _, err = onboarding.CreatePreAuthKey(context.Background(), plan)
	if err == nil {
		t.Fatal("CreatePreAuthKey() error = nil, want command failure")
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("CreatePreAuthKey() error = %q, want command failure", err.Error())
	}
	if strings.Contains(err.Error(), "Cannot get users: database is locked") {
		t.Fatalf("CreatePreAuthKey() error = %q, must not include stderr detail", err.Error())
	}
	if strings.Contains(err.Error(), "trace detail") {
		t.Fatalf("CreatePreAuthKey() error = %q, do not want multiline detail", err.Error())
	}
}

func TestOnboardingMasksPreAuthKeyCommandFailureOutput(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	secret := "hskey-auth-secret"
	runner := &scriptedRunner{
		results: []host.Result{
			{Stdout: `[{"id":2,"name":"lanpanel"}]` + "\n"},
			{Stdout: secret + "\n", Stderr: "created " + secret + " but failed\ntrace detail"},
		},
		errors: map[int]error{1: errors.New("exit status 1 with " + secret)},
	}
	onboarding := NewOnboarding(host.NewExecutor(runner, nil))

	_, _, err = onboarding.CreatePreAuthKey(context.Background(), plan)
	if err == nil {
		t.Fatal("CreatePreAuthKey() error = nil, want command failure")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("CreatePreAuthKey() error leaked auth key: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("CreatePreAuthKey() error = %q, want redacted key", err.Error())
	}
	for _, leak := range []string{"created ", "but failed", "trace detail"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("CreatePreAuthKey() error = %q, leaked command output %q", err.Error(), leak)
		}
	}
}

func TestOnboardingMasksMachineKeyCommandFailureOutput(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	secret := "mkey:abcdef0123456789"
	runner := &scriptedRunner{
		results: []host.Result{
			{Stdout: `[{"id":2,"name":"lanpanel"}]` + "\n"},
			{Stderr: "created " + secret + " but failed\ntrace detail"},
		},
		errors: map[int]error{1: errors.New("exit status 1 with " + secret)},
	}
	onboarding := NewOnboarding(host.NewExecutor(runner, nil))

	_, _, err = onboarding.CreatePreAuthKey(context.Background(), plan)
	if err == nil {
		t.Fatal("CreatePreAuthKey() error = nil, want command failure")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "mkey:") {
		t.Fatalf("CreatePreAuthKey() error leaked machine key: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("CreatePreAuthKey() error = %q, want redacted key", err.Error())
	}
	for _, leak := range []string{"created ", "but failed", "trace detail"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("CreatePreAuthKey() error = %q, leaked command output %q", err.Error(), leak)
		}
	}
}

func TestOnboardingRetriesTransientUsersListReadinessFailure(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	runner := &scriptedRunner{
		results: []host.Result{
			{Stderr: "Could not connect: context deadline exceeded"},
			{Stdout: `[{"id":2,"name":"lanpanel"}]` + "\n"},
			{Stdout: "hskey-auth-example\n"},
		},
		errors: map[int]error{0: errors.New("exit status 1")},
	}
	onboarding := Onboarding{
		executor:              host.NewExecutor(runner, nil),
		readinessTimeout:      time.Second,
		readinessPollInterval: time.Nanosecond,
	}

	key, _, err := onboarding.CreatePreAuthKey(context.Background(), plan)
	if err != nil {
		t.Fatalf("CreatePreAuthKey() error = %v", err)
	}
	if key != "hskey-auth-example" {
		t.Fatalf("key = %q", key)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("commands = %d, want retried users list plus preauth command", len(runner.commands))
	}
	if got := strings.Join(runner.commands[0].Args, " "); !strings.Contains(got, "users list --output json") {
		t.Fatalf("first command args = %q, want users list", got)
	}
	if got := strings.Join(runner.commands[1].Args, " "); !strings.Contains(got, "users list --output json") {
		t.Fatalf("second command args = %q, want users list retry", got)
	}
}

func TestOnboardingRetriesHeadscaleCLINilSocketPanic(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	runner := &scriptedRunner{
		results: []host.Result{
			{Stderr: "panic: runtime error: invalid memory address or nil pointer dereference\nlanpanel/vendor/github.com/juanfont/headscale/cmd/headscale/cli.newHeadscaleCLIWithConfig()"},
			{Stdout: `[{"id":2,"name":"lanpanel"}]` + "\n"},
			{Stdout: "hskey-auth-example\n"},
		},
		errors: map[int]error{0: errors.New("exit status 2")},
	}
	onboarding := Onboarding{
		executor:              host.NewExecutor(runner, nil),
		readinessTimeout:      time.Second,
		readinessPollInterval: time.Nanosecond,
	}

	key, _, err := onboarding.CreatePreAuthKey(context.Background(), plan)
	if err != nil {
		t.Fatalf("CreatePreAuthKey() error = %v", err)
	}
	if key != "hskey-auth-example" {
		t.Fatalf("key = %q", key)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("commands = %d, want retried users list plus preauth command", len(runner.commands))
	}
}

func TestOnboardingDoesNotRetryNonReadinessUsersListFailure(t *testing.T) {
	t.Parallel()

	plan, err := NewOnboardingPlan(OnboardingOptions{UserName: "lanpanel"})
	if err != nil {
		t.Fatalf("NewOnboardingPlan() error = %v", err)
	}
	runner := &scriptedRunner{
		results: []host.Result{
			{Stderr: "Error loading config file /etc/headscale/config.yaml"},
		},
		errors: map[int]error{0: errors.New("exit status 1")},
	}
	onboarding := Onboarding{
		executor:              host.NewExecutor(runner, nil),
		readinessTimeout:      time.Second,
		readinessPollInterval: time.Nanosecond,
	}

	_, _, err = onboarding.CreatePreAuthKey(context.Background(), plan)
	if err == nil {
		t.Fatal("CreatePreAuthKey() error = nil, want command failure")
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %d, want no retry", len(runner.commands))
	}
}

type scriptedRunner struct {
	commands []host.Command
	results  []host.Result
	errors   map[int]error
}

func (runner *scriptedRunner) Run(_ context.Context, command host.Command) (host.Result, error) {
	index := len(runner.commands)
	runner.commands = append(runner.commands, command)

	result := host.Result{Command: command}
	if index < len(runner.results) {
		result = runner.results[index]
		result.Command = command
	}
	if runner.errors != nil {
		if err := runner.errors[index]; err != nil {
			return result, err
		}
	}
	return result, nil
}
