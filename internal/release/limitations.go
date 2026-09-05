package release

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

var requiredLimitationStatements = [][]byte{
	[]byte("Clean installation only"),
	[]byte("No supported product backup/restore"),
	[]byte("A manual host copy or VM snapshot is not automatically a supported recoverable backup."),
	[]byte("No generic Repair"),
	[]byte("No EdgeOne integration"),
	[]byte("No connector disconnect, logout, reset, rejoin, or rebind automation"),
	[]byte("Key revoke does not expire a registered device."),
	[]byte("Connector mismatches must be resolved outside LanPanel"),
	[]byte("not live tested"),
	[]byte("Temporary public HTTP is plaintext and does not expire automatically"),
	[]byte("Fail-closed Nginx stop can interrupt Headscale control ingress"),
}

func ValidateKnownLimitations(data []byte) error {
	if len(data) == 0 || len(data) > 1<<20 || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || bytes.Contains(data, []byte("\r")) || data[len(data)-1] != '\n' {
		return fmt.Errorf("known limitations encoding is invalid")
	}
	for _, statement := range requiredLimitationStatements {
		if !bytes.Contains(data, statement) {
			return fmt.Errorf("known limitations omit required statement %q", statement)
		}
	}
	return nil
}
