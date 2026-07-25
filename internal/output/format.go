package output

import (
	"encoding/json"
	"fmt"
	"io"
	"lanpanel/internal/domain"
	"strings"
)

type Format string

const (
	FormatHuman Format = "human"
	FormatJSON  Format = "json"
)

type Field = domain.ResultField

type Response struct {
	Command         string   `json:"command"`
	Status          string   `json:"status"`
	Summary         string   `json:"summary"`
	Fields          []Field  `json:"fields,omitempty"`
	NextSteps       []string `json:"next_steps,omitempty"`
	OperationResult any      `json:"operation_result,omitempty"`
}

type Formatter struct {
	writer io.Writer
	format Format
}

func ParseFormat(value string) (Format, error) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return FormatHuman, nil
	}

	format := Format(trimmed)
	switch format {
	case FormatHuman, FormatJSON:
		return format, nil
	default:
		return "", fmt.Errorf("unsupported output format %q", value)
	}
}

func NewFormatter(writer io.Writer, format Format) Formatter {
	return Formatter{writer: writer, format: format}
}

func (formatter Formatter) Write(response Response) error {
	switch formatter.format {
	case FormatHuman:
		return writeHuman(formatter.writer, response)
	case FormatJSON:
		encoder := json.NewEncoder(formatter.writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(response)
	default:
		return fmt.Errorf("unsupported output format %q", formatter.format)
	}
}

func writeHuman(writer io.Writer, response Response) error {
	if _, err := fmt.Fprintf(writer, "lanpanel %s: %s\n", response.Command, response.Summary); err != nil {
		return err
	}

	if len(response.Fields) > 0 {
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
		for _, field := range response.Fields {
			if _, err := fmt.Fprintf(writer, "%s: %s\n", field.Label, field.Value); err != nil {
				return err
			}
		}
	}

	if len(response.NextSteps) > 0 {
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, "Next steps:"); err != nil {
			return err
		}
		for index, step := range response.NextSteps {
			if _, err := fmt.Fprintf(writer, "  %d. %s\n", index+1, step); err != nil {
				return err
			}
		}
	}

	return nil
}
