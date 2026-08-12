// Package helperaudit provides the AST-enforced privileged process boundary audit.
package helperaudit

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var spawnCalls = map[string]bool{
	"exec.Command": true, "exec.CommandContext": true, "exec.LookPath": true,
	"os.StartProcess": true, "syscall.Exec": true, "syscall.ForkExec": true,
	"syscall.StartProcess": true, "unix.Exec": true, "unix.ForkExec": true,
}

var forbiddenExecutables = map[string]bool{"sh": true, "bash": true, "dash": true, "sudo": true, "doas": true, "pkexec": true, "su": true}

func Run(root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	files := []string{}
	for _, tree := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() && path == filepath.Join(root, "internal", "helperaudit") {
				return filepath.SkipDir
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	fileSet := token.NewFileSet()
	commandCalls := 0
	unixExecCalls := map[string]int{}
	for _, path := range files {
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		aliases := map[string]string{}
		for _, imported := range file.Imports {
			importPath, _ := strconv.Unquote(imported.Path.Value)
			name := filepath.Base(importPath)
			if imported.Name != nil {
				name = imported.Name.Name
			}
			base := filepath.Base(importPath)
			if name == "." && (base == "exec" || base == "os" || base == "syscall" || base == "unix") {
				return fmt.Errorf("dot-imported process API in %s", relative)
			}
			aliases[name] = base
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.BasicLit:
				if value.Kind == token.STRING {
					literal, _ := strconv.Unquote(value.Value)
					if forbiddenExecutables[filepath.Base(literal)] {
						err = fmt.Errorf("forbidden executable literal %q in %s", literal, relative)
						return false
					}
				}
			case *ast.CallExpr:
				name := selectorName(value.Fun)
				if prefix, suffix, found := strings.Cut(name, "."); found && aliases[prefix] != "" {
					name = aliases[prefix] + "." + suffix
				}
				if !spawnCalls[name] {
					return true
				}
				if relative != "internal/child/executor_linux.go" {
					err = fmt.Errorf("process API %s escaped child executor in %s", name, relative)
					return false
				}
				switch name {
				case "exec.Command":
					commandCalls++
					if len(value.Args) != 2 || expressionName(value.Args[0]) != "launcher.self" || stringLiteral(value.Args[1]) != "child-executor" {
						err = fmt.Errorf("child bootstrap command shape is not exact")
						return false
					}
				case "unix.Exec":
					function := enclosingFunction(file, value.Pos())
					unixExecCalls[function]++
					if (function != "ExecuteBootstrap" && function != "ExecutePersistentProfile") || len(value.Args) != 3 || expressionName(value.Args[0]) != "profile.Executable" {
						err = fmt.Errorf("profile exec shape is not exact")
						return false
					}
				default:
					err = fmt.Errorf("process API %s is not an allowed executor call", name)
					return false
				}
			}
			return err == nil
		})
		if err != nil {
			return err
		}
	}
	if commandCalls != 1 || unixExecCalls["ExecuteBootstrap"] != 1 || unixExecCalls["ExecutePersistentProfile"] != 1 || len(unixExecCalls) != 2 {
		return fmt.Errorf("child executor call census is command=%d exec=%v", commandCalls, unixExecCalls)
	}
	return auditRequestFields(filepath.Join(root, "internal", "helperproto", "types.go"))
}

func auditRequestFields(path string) error {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"SchemaVersion": true, "RequestID": true, "Operation": true, "Target": true, "IntentGeneration": true, "Deadline": true, "InputDigest": true, "Action": true}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "Request" {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				return fmt.Errorf("helper request is not a struct")
			}
			for _, field := range structure.Fields.List {
				for _, name := range field.Names {
					if !allowed[name.Name] {
						return fmt.Errorf("generic helper request field %q is not allowed", name.Name)
					}
				}
			}
			return nil
		}
	}
	return fmt.Errorf("helper request schema is missing")
}

func enclosingFunction(file *ast.File, position token.Pos) string {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Body != nil && function.Body.Pos() <= position && position < function.Body.End() {
			return function.Name.Name
		}
	}
	return ""
}

func selectorName(expression ast.Expr) string {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name + "." + selector.Sel.Name
}

func expressionName(expression ast.Expr) string {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	identifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return identifier.Name + "." + selector.Sel.Name
}

func stringLiteral(expression ast.Expr) string {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return ""
	}
	value, _ := strconv.Unquote(literal.Value)
	return value
}
