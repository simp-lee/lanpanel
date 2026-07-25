// Package output formats CLI responses and interactive prompts.
package output

import (
	"bufio"
	"fmt"
	"io"
	"lanpanel/internal/prompt"
	"os"
	"strconv"
	"strings"
)

type TextPrompt = prompt.TextPrompt
type ConfirmPrompt = prompt.ConfirmPrompt
type SelectPrompt = prompt.SelectPrompt
type Prompter = prompt.Prompter

type terminalPrompter struct {
	reader  *bufio.Reader
	writer  io.Writer
	enabled bool
}

func NewPrompter(input io.Reader, writer io.Writer) Prompter {
	return &terminalPrompter{
		reader:  bufio.NewReader(input),
		writer:  writer,
		enabled: isInteractiveTerminal(input) && isInteractiveTerminal(writer),
	}
}

func (prompter *terminalPrompter) Enabled() bool {
	return prompter != nil && prompter.enabled
}

func (prompter *terminalPrompter) Text(label string, prompt TextPrompt) (string, error) {
	if !prompter.Enabled() {
		return "", fmt.Errorf("prompt input is unavailable")
	}

	value, err := prompter.readLine(label, prompt.Default, prompt.Help)
	if err != nil {
		return "", err
	}
	if prompt.Validate != nil {
		if err := prompt.Validate(value); err != nil {
			return "", err
		}
	}
	return value, nil
}

func (prompter *terminalPrompter) Confirm(label string, prompt ConfirmPrompt) (bool, error) {
	if !prompter.Enabled() {
		return false, fmt.Errorf("prompt input is unavailable")
	}

	defaultValue := "y/N"
	if prompt.Default {
		defaultValue = "Y/n"
	}

	value, err := prompter.readLine(label, defaultValue, prompt.Help)
	if err != nil {
		return false, err
	}

	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", defaultValue:
		return prompt.Default, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be yes or no", label)
	}
}

func (prompter *terminalPrompter) Select(label string, prompt SelectPrompt) (string, error) {
	if !prompter.Enabled() {
		return "", fmt.Errorf("prompt input is unavailable")
	}
	if len(prompt.Options) == 0 {
		return "", fmt.Errorf("%s has no options", label)
	}

	optionsLabel := strings.Join(prompt.Options, "/")
	value, err := prompter.readLine(label+" ["+optionsLabel+"]", prompt.Default, prompt.Help)
	if err != nil {
		return "", err
	}

	if index, convErr := strconv.Atoi(strings.TrimSpace(value)); convErr == nil {
		if index >= 1 && index <= len(prompt.Options) {
			return prompt.Options[index-1], nil
		}
	}

	for _, option := range prompt.Options {
		if strings.EqualFold(strings.TrimSpace(value), option) {
			return option, nil
		}
	}

	return "", fmt.Errorf("%s must be one of: %s", label, strings.Join(prompt.Options, ", "))
}

func (prompter *terminalPrompter) readLine(label string, defaultValue string, help string) (string, error) {
	if _, err := fmt.Fprint(prompter.writer, label); err != nil {
		return "", err
	}
	if strings.TrimSpace(defaultValue) != "" {
		if _, err := fmt.Fprintf(prompter.writer, " [%s]", defaultValue); err != nil {
			return "", err
		}
	}
	if strings.TrimSpace(help) != "" {
		if _, err := fmt.Fprintf(prompter.writer, " (%s)", help); err != nil {
			return "", err
		}
	}
	if _, err := fmt.Fprint(prompter.writer, ": "); err != nil {
		return "", err
	}

	line, err := prompter.reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read prompt input: %w", err)
	}

	value := strings.TrimSpace(line)
	if value == "" {
		value = strings.TrimSpace(defaultValue)
	}
	return value, nil
}

func isInteractiveTerminal(stream interface{}) bool {
	file, ok := stream.(*os.File)
	if !ok {
		return false
	}

	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}
