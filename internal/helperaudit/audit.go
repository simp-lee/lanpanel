// Package helperaudit provides the type-enforced privileged process boundary audit.
package helperaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

var processFunctions = map[string]bool{
	"os/exec.Command":                true,
	"os/exec.CommandContext":         true,
	"os/exec.LookPath":               true,
	"os.StartProcess":                true,
	"syscall.Exec":                   true,
	"syscall.ForkExec":               true,
	"syscall.StartProcess":           true,
	"golang.org/x/sys/unix.Exec":     true,
	"golang.org/x/sys/unix.ForkExec": true,
}

var syscallWrappers = map[string]bool{
	"golang.org/x/sys/unix.RawSyscall":        true,
	"golang.org/x/sys/unix.RawSyscall6":       true,
	"golang.org/x/sys/unix.RawSyscallNoError": true,
	"golang.org/x/sys/unix.Syscall":           true,
	"golang.org/x/sys/unix.Syscall6":          true,
	"golang.org/x/sys/unix.SyscallNoError":    true,
	"syscall.AllThreadsSyscall":               true,
	"syscall.AllThreadsSyscall6":              true,
	"syscall.RawSyscall":                      true,
	"syscall.RawSyscall6":                     true,
	"syscall.Syscall":                         true,
	"syscall.Syscall6":                        true,
}

var launchMethods = map[string]bool{
	"Start": true, "Run": true, "Output": true, "CombinedOutput": true,
}

var forbiddenExecutables = map[string]bool{
	"sh": true, "bash": true, "dash": true, "sudo": true, "doas": true, "pkexec": true, "su": true,
}

var expectedCensus = []struct {
	name string
	want int
}{
	{"child command", 1},
	{"child Start", 1},
	{"child Env", 1},
	{"child ExtraFiles", 1},
	{"child SysProcAttr", 1},
	{"child output", 1},
	{"child bootstrap exec", 1},
	{"child persistent exec", 1},
	{"managed exec", 1},
	{"generator git loop", 1},
	{"generator git loop Run", 1},
	{"generator untracked", 1},
	{"generator untracked Output", 1},
	{"generator head", 1},
	{"generator head Output", 1},
	{"generator go lookup", 1},
	{"generator build", 1},
	{"generator build output", 1},
	{"generator build Dir", 1},
	{"generator build Env", 1},
	{"raw SYS_BPF", 11},
	{"raw SYS_NEWFSTATAT", 1},
	{"raw SYS_PRCTL", 3},
}

type listedPackage struct {
	Dir        string
	ImportPath string
	Export     string
	GoFiles    []string
	CgoFiles   []string
	SFiles     []string
	SysoFiles  []string
	Incomplete bool
	Error      *struct{ Err string }
	Module     *struct{ Main bool }
}

type sourcePackage struct {
	importPath string
	files      []string
}

type fileAudit struct {
	file     *ast.File
	relative string
	parents  map[ast.Node]ast.Node
}

type auditState struct {
	counts              map[string]int
	commands            map[types.Object]string
	allowedProcessCalls map[*ast.CallExpr]bool
	goBinary            types.Object
}

// Run audits the fixed Linux production package set. Process APIs are
// identified by go/types object identity, not selector spelling.
func Run(root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	packages, exports, err := loadPackages(root)
	if err != nil {
		return err
	}

	fileSet := token.NewFileSet()
	lookup := func(importPath string) (io.ReadCloser, error) {
		exportPath := exports[importPath]
		if exportPath == "" {
			return nil, fmt.Errorf("type information for %s is unavailable", importPath)
		}
		return os.Open(exportPath)
	}
	state := auditState{
		counts:              make(map[string]int),
		commands:            make(map[types.Object]string),
		allowedProcessCalls: make(map[*ast.CallExpr]bool),
	}

	for _, packageInfo := range packages {
		files := make([]*ast.File, 0, len(packageInfo.files))
		audits := make([]fileAudit, 0, len(packageInfo.files))
		for _, path := range packageInfo.files {
			file, parseErr := parser.ParseFile(fileSet, path, nil, parser.ParseComments)
			if parseErr != nil {
				return parseErr
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			files = append(files, file)
			audits = append(audits, fileAudit{file: file, relative: filepath.ToSlash(relative), parents: parentNodes(file)})
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
		}
		configuration := types.Config{Importer: importer.ForCompiler(fileSet, "gc", lookup)}
		if _, typeErr := configuration.Check(packageInfo.importPath, fileSet, files, info); typeErr != nil {
			return fmt.Errorf("type-check %s: %w", packageInfo.importPath, typeErr)
		}
		for _, file := range audits {
			if err := auditForbiddenLiterals(file); err != nil {
				return err
			}
		}
		for _, file := range audits {
			if err := state.auditProcessReferences(file, info); err != nil {
				return err
			}
		}
		for _, file := range audits {
			if err := state.auditSyscallReferences(file, info); err != nil {
				return err
			}
		}
		for _, file := range audits {
			if err := state.auditCommandAssignments(file, info); err != nil {
				return err
			}
		}
		for _, file := range audits {
			if err := state.auditCommandMethods(file, info); err != nil {
				return err
			}
		}
		for _, file := range audits {
			if err := state.auditCommandValues(file, info); err != nil {
				return err
			}
		}
	}

	for _, expected := range expectedCensus {
		if state.counts[expected.name] != expected.want {
			return fmt.Errorf("fixed process boundary census mismatch for %s: got %d, want %d", expected.name, state.counts[expected.name], expected.want)
		}
	}
	return auditRequestFields(filepath.Join(root, "internal", "helperproto", "types.go"))
}

func loadPackages(root string) ([]sourcePackage, map[string]string, error) {
	goLauncher, err := exec.LookPath("go")
	if err != nil {
		return nil, nil, fmt.Errorf("locate go launcher: %w", err)
	}
	selection := exec.Command(goLauncher, "env", "GOROOT")
	selection.Dir = root
	selection.Env = goToolchainEnvironment()
	var selectionStderr bytes.Buffer
	selection.Stderr = &selectionStderr
	goroot, err := selection.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve selected go toolchain: %w: %s", err, strings.TrimSpace(selectionStderr.String()))
	}
	goBinary := filepath.Join(strings.TrimSpace(string(goroot)), "bin", "go")
	command := exec.Command(goBinary, "list", "-mod=readonly", "-buildvcs=false", "-json", "-export", "-deps", "./internal/...", "./cmd/...")
	command.Dir = root
	command.Env = offlineGoEnvironment()
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, nil, fmt.Errorf("load audit packages offline: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	exports := make(map[string]string)
	packages := []sourcePackage{}
	decoder := json.NewDecoder(&stdout)
	for {
		var item listedPackage
		if err := decoder.Decode(&item); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("decode go list output: %w", err)
		}
		if item.Error != nil || item.Incomplete {
			message := "package is incomplete"
			if item.Error != nil {
				message = item.Error.Err
			}
			return nil, nil, fmt.Errorf("load package %s: %s", item.ImportPath, message)
		}
		if item.Export != "" {
			exports[item.ImportPath] = item.Export
		}
		if item.Module == nil || !item.Module.Main || !insideModuleTree(root, item.Dir) || filepath.Clean(item.Dir) == filepath.Join(root, "internal", "helperaudit") {
			continue
		}
		if len(item.SFiles) != 0 || len(item.SysoFiles) != 0 {
			return nil, nil, fmt.Errorf("audited production package %s contains native source that go/types cannot prove", item.ImportPath)
		}
		files := append(append([]string(nil), item.GoFiles...), item.CgoFiles...)
		sort.Strings(files)
		for index := range files {
			files[index] = filepath.Join(item.Dir, files[index])
		}
		if len(files) != 0 {
			packages = append(packages, sourcePackage{importPath: item.ImportPath, files: files})
		}
	}
	if len(packages) == 0 {
		return nil, nil, fmt.Errorf("audited production packages are missing")
	}
	sort.Slice(packages, func(left, right int) bool { return packages[left].importPath < packages[right].importPath })
	return packages, exports, nil
}

func goToolchainEnvironment() []string {
	environment := fixedGoEnvironment("auto")
	for index, entry := range environment {
		if strings.HasPrefix(entry, "GOSUMDB=") {
			environment[index] = "GOSUMDB=sum.golang.org"
		}
	}
	return environment
}

func offlineGoEnvironment() []string { return fixedGoEnvironment("local") }

func fixedGoEnvironment(toolchain string) []string {
	overrides := map[string]string{
		"CGO_ENABLED": "0", "GO111MODULE": "on", "GOARCH": "amd64", "GOAMD64": "v1", "GOENV": "off", "GOEXPERIMENT": "", "GOFLAGS": "", "GOOS": "linux",
		"GONOPROXY": "", "GOPRIVATE": "", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": toolchain, "GOWORK": "off",
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := overrides[name]; name != "GOROOT" && !replaced {
			environment = append(environment, entry)
		}
	}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		environment = append(environment, name+"="+overrides[name])
	}
	return environment
}

func insideModuleTree(root, directory string) bool {
	relative, err := filepath.Rel(root, directory)
	return err == nil && !filepath.IsAbs(relative) && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func auditForbiddenLiterals(file fileAudit) error {
	for _, group := range file.file.Comments {
		for _, comment := range group.List {
			if comment.Text == "//go:linkname" || strings.HasPrefix(comment.Text, "//go:linkname ") || strings.HasPrefix(comment.Text, "//go:linkname\t") {
				return fmt.Errorf("production source %s uses go:linkname outside go/types identity", file.relative)
			}
		}
	}
	for _, imported := range file.file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err == nil && (path == "internal/helperaudit" || strings.HasSuffix(path, "/internal/helperaudit")) {
			return fmt.Errorf("production source %s imports the audit-only helperaudit package", file.relative)
		}
	}
	var auditErr error
	ast.Inspect(file.file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err == nil && forbiddenExecutables[filepath.Base(value)] {
			auditErr = fmt.Errorf("forbidden executable literal %q in %s", value, file.relative)
			return false
		}
		return true
	})
	return auditErr
}

func (state *auditState) auditProcessReferences(file fileAudit, info *types.Info) error {
	var auditErr error
	ast.Inspect(file.file, func(node ast.Node) bool {
		if auditErr != nil {
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if !ok || !processFunctions[objectKey(info.Uses[identifier])] {
			return true
		}
		expression := ast.Expr(identifier)
		if selector, ok := file.parents[identifier].(*ast.SelectorExpr); ok && selector.Sel == identifier {
			expression = selector
		}
		call, ok := file.parents[expression].(*ast.CallExpr)
		if !ok || call.Fun != expression {
			auditErr = fmt.Errorf("process API %s used as a function value in %s", objectKey(info.Uses[identifier]), file.relative)
			return false
		}
		if hasFunctionLiteralAncestor(call, file.parents) {
			auditErr = fmt.Errorf("process API call is hidden in a function literal in %s", file.relative)
			return false
		}
		auditErr = state.allowProcessCall(file, info, call, info.Uses[identifier])
		return auditErr == nil
	})
	return auditErr
}

func (state *auditState) auditSyscallReferences(file fileAudit, info *types.Info) error {
	var auditErr error
	ast.Inspect(file.file, func(node ast.Node) bool {
		if auditErr != nil {
			return false
		}
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		function, ok := info.Uses[identifier].(*types.Func)
		if !ok || function.Pkg() == nil || function.Parent() != function.Pkg().Scope() || !syscallWrappers[objectKey(function)] {
			return true
		}
		expression := ast.Expr(identifier)
		if selector, ok := file.parents[identifier].(*ast.SelectorExpr); ok && selector.Sel == identifier {
			expression = selector
		}
		call, ok := file.parents[expression].(*ast.CallExpr)
		if !ok || call.Fun != expression {
			auditErr = fmt.Errorf("syscall wrapper %s used as a function value in %s", objectKey(function), file.relative)
			return false
		}
		if hasFunctionLiteralAncestor(call, file.parents) {
			auditErr = fmt.Errorf("syscall wrapper call is hidden in a function literal in %s", file.relative)
			return false
		}
		auditErr = state.allowSyscallCall(file, info, call, function)
		return auditErr == nil
	})
	return auditErr
}

func (state *auditState) allowSyscallCall(file fileAudit, info *types.Info, call *ast.CallExpr, function types.Object) error {
	wrapper := objectKey(function)
	if len(call.Args) == 0 {
		return fmt.Errorf("syscall wrapper %s has no proven syscall number in %s", wrapper, file.relative)
	}
	numberObject := expressionObject(info, call.Args[0])
	number := objectKey(numberObject)
	if _, constant := numberObject.(*types.Const); !constant {
		return fmt.Errorf("syscall wrapper %s uses a dynamic or unproven syscall number in %s", wrapper, file.relative)
	}
	declaration := enclosingDeclaration(file.file, call.Pos())
	count := ""
	switch {
	case wrapper == "golang.org/x/sys/unix.Syscall" && number == "golang.org/x/sys/unix.SYS_BPF" && file.relative == "internal/process/listen_guard_linux.go" && declarationNameIs(declaration, "openOrCreateListenGuardMap", "verifyListenGuardMap", "ensureListenGuardLink", "verifyListenGuardLink", "updateListenGuardUID", "pinBPF", "getPinnedBPF"):
		count = "raw SYS_BPF"
	case wrapper == "golang.org/x/sys/unix.Syscall6" && number == "golang.org/x/sys/unix.SYS_NEWFSTATAT" && file.relative == "internal/safety/emergency_linux.go" && declarationNameIs(declaration, "rawLstat"):
		count = "raw SYS_NEWFSTATAT"
	case wrapper == "golang.org/x/sys/unix.Syscall6" && number == "golang.org/x/sys/unix.SYS_PRCTL" && file.relative == "internal/child/executor_linux.go" && declarationNameIs(declaration, "assertAppliedIdentity"):
		count = "raw SYS_PRCTL"
	default:
		return fmt.Errorf("raw syscall %s through %s is outside the fixed authority in %s", number, wrapper, file.relative)
	}
	state.counts[count]++
	return nil
}

func declarationNameIs(declaration *ast.FuncDecl, names ...string) bool {
	return declaration != nil && declaration.Recv == nil && slices.Contains(names, declaration.Name.Name)
}

func (state *auditState) allowProcessCall(file fileAudit, info *types.Info, call *ast.CallExpr, function types.Object) error {
	key := objectKey(function)
	declaration := enclosingDeclaration(file.file, call.Pos())
	args := expressionList(call.Args)
	count, commandKind := "", ""

	switch key {
	case "os/exec.Command":
		switch {
		case file.relative == "internal/child/executor_linux.go" && exactBoundaryDeclaration(declaration, "RunInvocation") && exactLauncherReceiver(declaration, info) && uniqueDeclarationNames(declaration, info, "launcher", "command", "instructionRead", "inputRead", "stdout", "stderr") && receiverObject(declaration, info, "launcher") == rootIdentifierObject(info, call.Args[0]) && !call.Ellipsis.IsValid() && args == `launcher.self, "child-executor"`:
			count, commandKind = "child command", "child"
		case file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "requireExactCleanCommit") && uniqueDeclarationNames(declaration, info, "root", "commands", "arguments", "command") && hasNamedParameters(declaration, info, "root") && exactGitLoop(declaration, info, call) && call.Ellipsis.IsValid() && args == `"git", append([]string{"-C", root}, arguments...)`:
			count, commandKind = "generator git loop", "git-loop"
		case file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "requireExactCleanCommit") && uniqueDeclarationNames(declaration, info, "root", "untracked") && hasNamedParameters(declaration, info, "root") && !call.Ellipsis.IsValid() && args == `"git", "-C", root, "ls-files", "--others", "--exclude-standard", "-z"`:
			count, commandKind = "generator untracked", "untracked"
		case file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "requireExactCleanCommit") && uniqueDeclarationNames(declaration, info, "root", "head") && hasNamedParameters(declaration, info, "root") && !call.Ellipsis.IsValid() && args == `"git", "-C", root, "rev-parse", "--verify", "HEAD"`:
			count, commandKind = "generator head", "head"
		case file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "buildCandidate") && uniqueDeclarationNames(declaration, info, "root", "releaseTag", "destination", "goBinary", "command") && hasNamedParameters(declaration, info, "root", "releaseTag", "destination") && !call.Ellipsis.IsValid() && args == `goBinary, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -X main.version=" + releaseTag, "-o", destination, "./cmd/lanpanel"` && identifierObject(info, call.Args[0]) == state.goBinary:
			count, commandKind = "generator build", "build"
		default:
			return fmt.Errorf("exec.Command is outside the fixed boundary in %s", file.relative)
		}
		object := assignedObject(call, file.parents, info)
		if object == nil || object.Name() != expectedCommandName(commandKind) {
			return fmt.Errorf("fixed command is not assigned to its exact local in %s", file.relative)
		}
		state.commands[object] = commandKind
	case "os/exec.LookPath":
		if file.relative != "internal/qualification/generator_linux.go" || !exactBoundaryDeclaration(declaration, "buildCandidate") || call.Ellipsis.IsValid() || args != `"go"` {
			return fmt.Errorf("exec.LookPath is outside the fixed boundary in %s", file.relative)
		}
		object := assignedObject(call, file.parents, info)
		if object == nil || object.Name() != "goBinary" {
			return fmt.Errorf("go lookup result is not assigned to goBinary")
		}
		state.goBinary = object
		count = "generator go lookup"
	case "golang.org/x/sys/unix.Exec":
		switch {
		case file.relative == "internal/child/executor_linux.go" && exactBoundaryDeclaration(declaration, "ExecuteBootstrap") && uniqueDeclarationNames(declaration, info, "profile", "argv") && args == `profile.Executable, argv, profile.Environment`:
			count = "child bootstrap exec"
		case file.relative == "internal/child/executor_linux.go" && exactBoundaryDeclaration(declaration, "ExecutePersistentProfile") && uniqueDeclarationNames(declaration, info, "profile", "argv") && args == `profile.Executable, argv, profile.Environment`:
			count = "child persistent exec"
		case file.relative == "internal/process/managed_exec_linux.go" && exactBoundaryDeclaration(declaration, "Execute") && uniqueDeclarationNames(declaration, info, "authority", "argv", "environment") && args == `authority.Service.Executable, argv, environment`:
			count = "managed exec"
		default:
			return fmt.Errorf("unix.Exec is outside the fixed boundary in %s", file.relative)
		}
	default:
		return fmt.Errorf("process API %s is not allowed in %s", key, file.relative)
	}

	state.counts[count]++
	state.allowedProcessCalls[call] = true
	return nil
}

func exactGitLoop(declaration *ast.FuncDecl, info *types.Info, commandCall *ast.CallExpr) bool {
	if declaration == nil || len(commandCall.Args) != 2 {
		return false
	}
	var commands types.Object
	ast.Inspect(declaration, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || nodeString(assignment.Lhs[0]) != "commands" || nodeString(assignment.Rhs[0]) != `[][]string{{"diff", "--quiet", "HEAD", "--"}, {"diff", "--cached", "--quiet", "HEAD", "--"}}` {
			return true
		}
		identifier, ok := assignment.Lhs[0].(*ast.Ident)
		if ok {
			commands = info.Defs[identifier]
		}
		return false
	})
	appendCall, ok := commandCall.Args[1].(*ast.CallExpr)
	if !ok {
		return false
	}
	appendIdentifier, appendOK := appendCall.Fun.(*ast.Ident)
	if !appendOK || info.Uses[appendIdentifier] != types.Universe.Lookup("append") {
		return false
	}
	arguments := uniqueDefinition(declaration, info, "arguments")
	for node := ast.Node(commandCall); node != nil; node = parentWithin(declaration, node) {
		loop, ok := node.(*ast.RangeStmt)
		if !ok {
			continue
		}
		value, valueOK := loop.Value.(*ast.Ident)
		source, sourceOK := loop.X.(*ast.Ident)
		return valueOK && sourceOK && info.Defs[value] == arguments && info.Uses[source] == commands
	}
	return false
}

func parentWithin(declaration *ast.FuncDecl, target ast.Node) ast.Node {
	var parent ast.Node
	stack := []ast.Node{}
	ast.Inspect(declaration, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if node == target && len(stack) != 0 {
			parent = stack[len(stack)-1]
			return false
		}
		stack = append(stack, node)
		return parent == nil
	})
	return parent
}

func uniqueDefinition(declaration *ast.FuncDecl, info *types.Info, name string) types.Object {
	var result types.Object
	ast.Inspect(declaration, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok || identifier.Name != name || info.Defs[identifier] == nil {
			return true
		}
		if result != nil && result != info.Defs[identifier] {
			result = nil
			return false
		}
		result = info.Defs[identifier]
		return true
	})
	return result
}

func expectedCommandName(kind string) string {
	switch kind {
	case "untracked", "head":
		return kind
	default:
		return "command"
	}
}

func (state *auditState) auditCommandMethods(file fileAudit, info *types.Info) error {
	var auditErr error
	ast.Inspect(file.file, func(node ast.Node) bool {
		if auditErr != nil {
			return false
		}
		selector, ok := node.(*ast.SelectorExpr)
		selection := info.Selections[selector]
		if !ok || selection == nil || !isExecCmdType(selection.Recv()) {
			return true
		}
		method := selection.Obj().Name()
		if method == "StdinPipe" || method == "StdoutPipe" || method == "StderrPipe" {
			auditErr = fmt.Errorf("exec.Cmd pipe method %s is forbidden in %s", method, file.relative)
			return false
		}
		if !launchMethods[method] {
			return true
		}
		if selection.Kind() == types.MethodExpr {
			auditErr = fmt.Errorf("exec.Cmd method %s used as a method expression in %s", method, file.relative)
			return false
		}
		call, ok := file.parents[selector].(*ast.CallExpr)
		if !ok || call.Fun != selector || hasFunctionLiteralAncestor(call, file.parents) {
			auditErr = fmt.Errorf("exec.Cmd method %s used as a function value in %s", method, file.relative)
			return false
		}
		receiver, ok := unparenthesized(selector.X).(*ast.Ident)
		if !ok {
			auditErr = fmt.Errorf("exec.Cmd method %s has an indirect receiver in %s", method, file.relative)
			return false
		}
		kind := state.commands[info.Uses[receiver]]
		declaration := enclosingDeclaration(file.file, call.Pos())
		count := ""
		switch {
		case kind == "child" && method == "Start" && file.relative == "internal/child/executor_linux.go" && exactBoundaryDeclaration(declaration, "RunInvocation") && exactLauncherReceiver(declaration, info):
			count = "child Start"
		case kind == "git-loop" && method == "Run" && file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "requireExactCleanCommit"):
			count = "generator git loop Run"
		case kind == "untracked" && method == "Output" && file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "requireExactCleanCommit"):
			count = "generator untracked Output"
		case kind == "head" && method == "Output" && file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "requireExactCleanCommit"):
			count = "generator head Output"
		case kind == "build" && method == "CombinedOutput" && file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "buildCandidate"):
			count = "generator build output"
		default:
			auditErr = fmt.Errorf("exec.Cmd method %s is outside the fixed boundary in %s", method, file.relative)
			return false
		}
		state.counts[count]++
		return true
	})
	return auditErr
}

func (state *auditState) auditCommandAssignments(file fileAudit, info *types.Info) error {
	var auditErr error
	ast.Inspect(file.file, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || auditErr != nil {
			return auditErr == nil
		}
		seen := make(map[types.Object]bool)
		for _, left := range assignment.Lhs {
			object := rootCommandObject(left, info, state.commands)
			if object == nil || seen[object] {
				continue
			}
			seen[object] = true
			if isConstructorAssignment(assignment, state.allowedProcessCalls) {
				continue
			}
			if configuration := allowedCommandConfiguration(state.commands[object], file, info, assignment); configuration != "" {
				state.counts[configuration]++
				continue
			}
			auditErr = fmt.Errorf("fixed exec.Cmd is mutated outside its exact configuration in %s: %s", file.relative, nodeString(assignment))
			return false
		}
		return true
	})
	return auditErr
}

func allowedCommandConfiguration(kind string, file fileAudit, info *types.Info, assignment *ast.AssignStmt) string {
	if hasFunctionLiteralAncestor(assignment, file.parents) || !exactConfigurationObjects(assignment, info) {
		return ""
	}
	declaration := enclosingDeclaration(file.file, assignment.Pos())
	text := nodeString(assignment)
	if kind == "child" && file.relative == "internal/child/executor_linux.go" && exactBoundaryDeclaration(declaration, "RunInvocation") && exactLauncherReceiver(declaration, info) {
		switch text {
		case `command.Env = []string{}`:
			return "child Env"
		case `command.ExtraFiles = []*os.File{instructionRead, inputRead}`:
			return "child ExtraFiles"
		case `command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}`:
			return "child SysProcAttr"
		case `command.Stdout, command.Stderr = stdout, stderr`:
			return "child output"
		}
	}
	if kind == "build" && file.relative == "internal/qualification/generator_linux.go" && exactBoundaryDeclaration(declaration, "buildCandidate") {
		switch text {
		case `command.Dir = root`:
			return "generator build Dir"
		case `command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOENV=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off"}`:
			return "generator build Env"
		}
	}
	return ""
}

func exactConfigurationObjects(assignment *ast.AssignStmt, info *types.Info) bool {
	expected := map[string]string{
		"File": "os.File", "Getenv": "os.Getenv", "SIGKILL": "syscall.SIGKILL",
	}
	valid := true
	ast.Inspect(assignment, func(node ast.Node) bool {
		if !valid {
			return false
		}
		switch value := node.(type) {
		case *ast.SelectorExpr:
			key := objectKey(info.Uses[value.Sel])
			if want := expected[value.Sel.Name]; want != "" && key != want {
				valid = false
			}
			if value.Sel.Name == "SysProcAttr" && key != "syscall.SysProcAttr" && key != "os/exec.SysProcAttr" {
				valid = false
			}
		case *ast.Ident:
			if value.Name == "true" && info.Uses[value] != types.Universe.Lookup("true") {
				valid = false
			}
		}
		return valid
	})
	return valid
}

func (state *auditState) auditCommandValues(file fileAudit, info *types.Info) error {
	var auditErr error
	ast.Inspect(file.file, func(node ast.Node) bool {
		if auditErr != nil {
			return false
		}
		if identifier, ok := node.(*ast.Ident); ok {
			object := info.Uses[identifier]
			if object == nil {
				object = info.Defs[identifier]
			}
			if state.goBinary != nil && object == state.goBinary && !state.allowedGoBinaryUse(identifier, file.parents) {
				auditErr = fmt.Errorf("goBinary is reassigned or escapes before the fixed build in %s", file.relative)
				return false
			}
			if isExecCmdTypeName(info.Uses[identifier]) {
				auditErr = fmt.Errorf("explicit exec.Cmd type reference is forbidden in %s", file.relative)
				return false
			}
		}
		expression, ok := node.(ast.Expr)
		if !ok {
			return true
		}
		if selector, ok := expression.(*ast.SelectorExpr); ok && mutableCommandField(selector.Sel.Name) && rootCommandObject(selector, info, state.commands) != nil && !insideAssignmentLeftHandSide(selector, file.parents) {
			auditErr = fmt.Errorf("mutable exec.Cmd field %s escapes its fixed assignment in %s", selector.Sel.Name, file.relative)
			return false
		}
		if !isExecCmdType(info.TypeOf(expression)) {
			return true
		}
		switch value := expression.(type) {
		case *ast.CallExpr:
			if state.allowedProcessCalls[value] {
				return true
			}
		case *ast.Ident:
			object := info.Uses[value]
			if object == nil {
				object = info.Defs[value]
			}
			if _, allowed := state.commands[object]; allowed && allowedCommandIdentifierUse(value, file.parents) {
				return true
			}
		}
		auditErr = fmt.Errorf("exec.Cmd value escapes its fixed local boundary in %s", file.relative)
		return false
	})
	return auditErr
}

func (state *auditState) allowedGoBinaryUse(identifier *ast.Ident, parents map[ast.Node]ast.Node) bool {
	parent := parents[identifier]
	if assignment, ok := parent.(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 {
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		return ok && state.allowedProcessCalls[call]
	}
	if call, ok := parent.(*ast.CallExpr); ok && len(call.Args) != 0 && call.Args[0] == identifier {
		return state.allowedProcessCalls[call]
	}
	return false
}

func mutableCommandField(name string) bool {
	switch name {
	case "Path", "Args", "Env", "Dir", "ExtraFiles", "SysProcAttr", "Stdin", "Stdout", "Stderr", "Err", "Cancel", "WaitDelay":
		return true
	default:
		return false
	}
}

func insideAssignmentLeftHandSide(node ast.Node, parents map[ast.Node]ast.Node) bool {
	for {
		parent := parents[node]
		switch value := parent.(type) {
		case *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr, *ast.ParenExpr:
			node = parent
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if left == node {
					return true
				}
			}
			return false
		default:
			return false
		}
	}
}

func allowedCommandIdentifierUse(identifier *ast.Ident, parents map[ast.Node]ast.Node) bool {
	node := ast.Node(identifier)
	for {
		parent := parents[node]
		if parentheses, ok := parent.(*ast.ParenExpr); ok && parentheses.X == node {
			node = parentheses
			continue
		}
		switch value := parent.(type) {
		case *ast.SelectorExpr:
			return value.X == node
		case *ast.AssignStmt:
			for _, left := range value.Lhs {
				if left == node {
					return true
				}
			}
		}
		return false
	}
}

func identifierObject(info *types.Info, expression ast.Expr) types.Object {
	identifier, ok := unparenthesized(expression).(*ast.Ident)
	if !ok {
		return nil
	}
	return info.Uses[identifier]
}

func expressionObject(info *types.Info, expression ast.Expr) types.Object {
	switch value := unparenthesized(expression).(type) {
	case *ast.Ident:
		return info.Uses[value]
	case *ast.SelectorExpr:
		return info.Uses[value.Sel]
	default:
		return nil
	}
}

func assignedObject(call *ast.CallExpr, parents map[ast.Node]ast.Node, info *types.Info) types.Object {
	assignment, ok := parents[call].(*ast.AssignStmt)
	if !ok || len(assignment.Rhs) != 1 || len(assignment.Lhs) == 0 {
		return nil
	}
	identifier, ok := assignment.Lhs[0].(*ast.Ident)
	if !ok {
		return nil
	}
	object := info.Defs[identifier]
	if object == nil {
		object = info.Uses[identifier]
	}
	return object
}

func isConstructorAssignment(assignment *ast.AssignStmt, allowed map[*ast.CallExpr]bool) bool {
	if len(assignment.Rhs) != 1 {
		return false
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	return ok && allowed[call]
}

func rootCommandObject(expression ast.Expr, info *types.Info, commands map[types.Object]string) types.Object {
	switch value := unparenthesized(expression).(type) {
	case *ast.Ident:
		object := info.Uses[value]
		if object == nil {
			object = info.Defs[value]
		}
		if _, ok := commands[object]; ok {
			return object
		}
	case *ast.SelectorExpr:
		return rootCommandObject(value.X, info, commands)
	case *ast.IndexExpr:
		return rootCommandObject(value.X, info, commands)
	case *ast.StarExpr:
		return rootCommandObject(value.X, info, commands)
	}
	return nil
}

func rootIdentifierObject(info *types.Info, expression ast.Expr) types.Object {
	for {
		switch value := unparenthesized(expression).(type) {
		case *ast.Ident:
			return info.Uses[value]
		case *ast.SelectorExpr:
			expression = value.X
		default:
			return nil
		}
	}
}

func receiverObject(declaration *ast.FuncDecl, info *types.Info, name string) types.Object {
	if declaration == nil || declaration.Recv == nil || len(declaration.Recv.List) != 1 || len(declaration.Recv.List[0].Names) != 1 || declaration.Recv.List[0].Names[0].Name != name {
		return nil
	}
	return info.Defs[declaration.Recv.List[0].Names[0]]
}

func hasNamedParameters(declaration *ast.FuncDecl, info *types.Info, names ...string) bool {
	if declaration == nil || declaration.Type.Params == nil {
		return false
	}
	found := make(map[string]bool, len(names))
	for _, field := range declaration.Type.Params.List {
		for _, identifier := range field.Names {
			if info.Defs[identifier] != nil {
				found[identifier.Name] = true
			}
		}
	}
	for _, name := range names {
		if !found[name] {
			return false
		}
	}
	return true
}

func uniqueDeclarationNames(declaration *ast.FuncDecl, info *types.Info, names ...string) bool {
	if declaration == nil {
		return false
	}
	objects := make(map[string]map[types.Object]bool, len(names))
	for _, name := range names {
		objects[name] = make(map[types.Object]bool)
	}
	ast.Inspect(declaration, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if ok && info.Defs[identifier] != nil && objects[identifier.Name] != nil {
			objects[identifier.Name][info.Defs[identifier]] = true
		}
		return true
	})
	for _, name := range names {
		if len(objects[name]) != 1 {
			return false
		}
		var definition types.Object
		for object := range objects[name] {
			definition = object
		}
		valid := true
		ast.Inspect(declaration, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && identifier.Name == name && info.Uses[identifier] != nil && info.Uses[identifier] != definition {
				valid = false
				return false
			}
			return true
		})
		if !valid {
			return false
		}
	}
	return true
}

func exactLauncherReceiver(declaration *ast.FuncDecl, info *types.Info) bool {
	object := receiverObject(declaration, info, "launcher")
	if object == nil {
		return false
	}
	pointer, ok := object.Type().(*types.Pointer)
	if !ok {
		return false
	}
	if _, alias := pointer.Elem().(*types.Alias); alias {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg() == object.Pkg() && named.Obj().Name() == "Launcher"
}

func exactBoundaryDeclaration(declaration *ast.FuncDecl, name string) bool {
	if declaration == nil || declaration.Name.Name != name {
		return false
	}
	if name == "RunInvocation" {
		return declaration.Recv != nil && len(declaration.Recv.List) == 1 && nodeString(declaration.Recv.List[0].Type) == "*Launcher"
	}
	return declaration.Recv == nil
}

func isExecCmdType(value types.Type) bool {
	if value == nil {
		return false
	}
	value = types.Unalias(value)
	if pointer, ok := value.(*types.Pointer); ok {
		value = types.Unalias(pointer.Elem())
	}
	named, ok := value.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "os/exec" && named.Obj().Name() == "Cmd"
}

func isExecCmdTypeName(object types.Object) bool {
	name, ok := object.(*types.TypeName)
	return ok && isExecCmdType(name.Type())
}

func objectKey(object types.Object) string {
	if object == nil || object.Pkg() == nil {
		return ""
	}
	return object.Pkg().Path() + "." + object.Name()
}

func expressionList(expressions []ast.Expr) string {
	parts := make([]string, len(expressions))
	for index, expression := range expressions {
		parts[index] = nodeString(expression)
	}
	return strings.Join(parts, ", ")
}

func nodeString(node any) string {
	var output bytes.Buffer
	_ = format.Node(&output, token.NewFileSet(), node)
	return output.String()
}

func unparenthesized(expression ast.Expr) ast.Expr {
	for {
		parentheses, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parentheses.X
	}
}

func parentNodes(root ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	stack := []ast.Node{}
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) != 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

func hasFunctionLiteralAncestor(node ast.Node, parents map[ast.Node]ast.Node) bool {
	for node = parents[node]; node != nil; node = parents[node] {
		switch node.(type) {
		case *ast.FuncLit:
			return true
		case *ast.FuncDecl:
			return false
		}
	}
	return false
}

func enclosingDeclaration(file *ast.File, position token.Pos) *ast.FuncDecl {
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Body != nil && function.Body.Pos() <= position && position < function.Body.End() {
			return function
		}
	}
	return nil
}

func auditRequestFields(path string) error {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"SchemaVersion": true, "RequestID": true, "Operation": true, "Target": true, "IntentGeneration": true, "Deadline": true, "InputDigest": true, "Action": true, "Resource": true}
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
