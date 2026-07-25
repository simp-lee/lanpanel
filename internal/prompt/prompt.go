package prompt

type TextPrompt struct {
	Default  string
	Help     string
	Validate func(string) error
}

type ConfirmPrompt struct {
	Default bool
	Help    string
}

type SelectPrompt struct {
	Default string
	Help    string
	Options []string
}

type Prompter interface {
	Enabled() bool
	Text(label string, prompt TextPrompt) (string, error)
	Confirm(label string, prompt ConfirmPrompt) (bool, error)
	Select(label string, prompt SelectPrompt) (string, error)
}
