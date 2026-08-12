package packages

// NoAutostartExitCode implements Debian policy-rc.d's fixed deny-start result.
// It intentionally makes no decision from package-controlled service/action
// arguments: every maintainer-script attempt is denied with status 101.
func NoAutostartExitCode(_ []string) int { return 101 }
