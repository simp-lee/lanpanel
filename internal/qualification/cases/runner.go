package cases

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
)

type ExecuteFunc func(ctx context.Context, name string, arguments ...string) ([]byte, error)

type RunConfig struct {
	Scope    string
	Packages []string
	Rows     []Row
	GoBinary string
	Execute  ExecuteFunc
}

type ExecutionRecord struct {
	Scope            string           `json:"scope"`
	ClauseID         string           `json:"clause_id"`
	CaseID           string           `json:"case_id"`
	Package          string           `json:"package"`
	Test             string           `json:"test"`
	VerificationMode VerificationMode `json:"verification_mode"`
	Status           StatusTriple     `json:"status"`
	Result           string           `json:"result"`
}

type goEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
}

func Run(ctx context.Context, config RunConfig, output io.Writer) error {
	rows := config.Rows
	if rows == nil {
		rows = Ledger()
	}
	selected, err := RowsForScope(rows, config.Scope)
	if err != nil {
		return err
	}
	packages, err := validatePackages(config.Packages)
	if err != nil {
		return err
	}
	packageSet := make(map[string]struct{}, len(packages))
	for _, pkg := range packages {
		packageSet[pkg] = struct{}{}
	}
	for _, row := range selected {
		if _, present := packageSet[row.Package]; !present {
			return fmt.Errorf("case %q owns package %q, which is absent from PKGS", row.CaseID, row.Package)
		}
	}
	goBinary := config.GoBinary
	if goBinary == "" {
		goBinary = "go"
	}
	execute := config.Execute
	if execute == nil {
		execute = executeCommand
	}
	importPaths := make(map[string]string, len(packages))
	for _, pkg := range packages {
		data, listErr := execute(ctx, goBinary, "list", "-f={{.ImportPath}}", pkg)
		if listErr != nil {
			return fmt.Errorf("resolve package %s: %w", pkg, listErr)
		}
		lines := strings.Fields(string(data))
		if len(lines) != 1 || strings.TrimSpace(lines[0]) == "" {
			return fmt.Errorf("resolve package %s: expected one import path, got %q", pkg, strings.TrimSpace(string(data)))
		}
		importPaths[pkg] = lines[0]
	}
	arguments := []string{"test", "-json", "-count=1"}
	arguments = append(arguments, packages...)
	data, testErr := execute(ctx, goBinary, arguments...)
	events, parseErr := parseGoEvents(data)
	if parseErr != nil {
		return parseErr
	}
	if testErr != nil {
		return fmt.Errorf("focused Go tests failed: %w", testErr)
	}
	type binding struct{ pkg, test string }
	terminal := map[binding][]string{}
	for _, event := range events {
		if event.Test == "" || (event.Action != "pass" && event.Action != "fail" && event.Action != "skip") {
			continue
		}
		key := binding{pkg: event.Package, test: event.Test}
		terminal[key] = append(terminal[key], event.Action)
	}
	records := make([]ExecutionRecord, 0, len(selected))
	for _, row := range selected {
		importPath := importPaths[row.Package]
		for _, event := range events {
			if event.Package == importPath && strings.HasPrefix(event.Test, row.Test+"/") {
				return fmt.Errorf("case %q test %s is a parent of descendant %s", row.CaseID, row.Test, event.Test)
			}
		}
		key := binding{pkg: importPath, test: row.Test}
		actions := terminal[key]
		if len(actions) != 1 || actions[0] != "pass" {
			return fmt.Errorf("case %q expected one passing terminal event for %s %s, got %v", row.CaseID, row.Package, row.Test, actions)
		}
		records = append(records, ExecutionRecord{
			Scope:            config.Scope,
			ClauseID:         row.ClauseID,
			CaseID:           row.CaseID,
			Package:          row.Package,
			Test:             row.Test,
			VerificationMode: row.VerificationMode,
			Status:           row.SuccessStatus,
			Result:           "passed",
		})
	}
	sort.Slice(records, func(left, right int) bool { return records[left].ClauseID < records[right].ClauseID })
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("record focused case %q: %w", record.CaseID, err)
		}
	}
	return nil
}

func validatePackages(packages []string) ([]string, error) {
	if len(packages) == 0 {
		return nil, fmt.Errorf("PKGS must enumerate at least one explicit package")
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(packages))
	for _, pkg := range packages {
		if err := validatePackage(pkg); err != nil {
			return nil, err
		}
		if _, duplicate := seen[pkg]; duplicate {
			return nil, fmt.Errorf("PKGS package %q is duplicated", pkg)
		}
		seen[pkg] = struct{}{}
		result = append(result, pkg)
	}
	return result, nil
}

func parseGoEvents(data []byte) ([]goEvent, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	events := make([]goEvent, 0)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event goEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("decode go test JSON event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read go test JSON events: %w", err)
	}
	return events, nil
}

func executeCommand(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	return command.CombinedOutput()
}
