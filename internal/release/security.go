package release

import (
	"fmt"
	"strings"
	"time"
)

const SecurityReportSchemaVersion = "lanpanel.release.security-report.v1"

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type FindingResolution string

const (
	ResolutionUnresolved    FindingResolution = "unresolved"
	ResolutionFixedBaseline FindingResolution = "fixed_baseline"
	ResolutionMitigation    FindingResolution = "verified_mitigation"
	ResolutionFalsePositive FindingResolution = "evidenced_false_positive"
	ResolutionNotAffected   FindingResolution = "evidenced_not_affected"
)

type ScannerIdentity struct {
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	DatabaseDigest string `json:"database_digest"`
	Coverage       string `json:"coverage"`
}

type SecurityFinding struct {
	ID               string            `json:"id"`
	Component        string            `json:"component"`
	Severity         Severity          `json:"severity"`
	InShippedClosure bool              `json:"in_shipped_closure"`
	RuntimeReachable bool              `json:"runtime_reachable"`
	Resolution       FindingResolution `json:"resolution"`
	EvidenceDigest   string            `json:"evidence_digest,omitempty"`
}

type SecurityReport struct {
	SchemaVersion   string            `json:"schema_version"`
	CandidateDigest string            `json:"candidate_digest"`
	ScannedAt       time.Time         `json:"scanned_at"`
	Scanners        []ScannerIdentity `json:"scanners"`
	Findings        []SecurityFinding `json:"findings"`
}

var requiredScannerCoverage = map[string]string{
	"distro_security":  "runtime_os_packages",
	"go_vulnerability": "go_binary",
	"sbom_osv":         "sbom",
}

func DecodeSecurityReport(data []byte) (SecurityReport, error) {
	var report SecurityReport
	if err := DecodeCanonical(data, &report); err != nil {
		return SecurityReport{}, err
	}
	if err := ValidateSecurityReport(report); err != nil {
		return SecurityReport{}, err
	}
	return report, nil
}

func ValidateSecurityReport(report SecurityReport) error {
	if report.SchemaVersion != SecurityReportSchemaVersion || !ValidDigest(report.CandidateDigest) || !sameUTCSecond(report.ScannedAt) || len(report.Scanners) != len(requiredScannerCoverage) {
		return fmt.Errorf("security report identity, time, or scanner inventory is invalid")
	}
	previous := ""
	seen := map[string]bool{}
	for _, scanner := range report.Scanners {
		expectedCoverage, required := requiredScannerCoverage[scanner.Kind]
		if !required || scanner.Coverage != expectedCoverage || !refPattern.MatchString(scanner.Name) || !concreteVersionPattern.MatchString(scanner.Version) || !ValidDigest(scanner.DatabaseDigest) || previous != "" && strings.Compare(previous, scanner.Kind) >= 0 {
			return fmt.Errorf("scanner/feed identities or coverage are invalid, duplicated, or unsorted")
		}
		seen[scanner.Kind] = true
		previous = scanner.Kind
	}
	for kind := range requiredScannerCoverage {
		if !seen[kind] {
			return fmt.Errorf("security report omits mandatory scanner coverage %q", kind)
		}
	}
	previous = ""
	for _, finding := range report.Findings {
		if !refPattern.MatchString(finding.ID) || !refPattern.MatchString(finding.Component) || previous != "" && strings.Compare(previous, finding.ID) >= 0 || !validSeverity(finding.Severity) || !validResolution(finding.Resolution) {
			return fmt.Errorf("security findings are invalid, duplicated, or unsorted")
		}
		if finding.Resolution == ResolutionUnresolved {
			if finding.EvidenceDigest != "" {
				return fmt.Errorf("unresolved finding cannot carry resolution evidence")
			}
		} else if !ValidDigest(finding.EvidenceDigest) {
			return fmt.Errorf("resolved finding lacks exact evidence")
		}
		previous = finding.ID
	}
	return nil
}

func CheckSecurityGate(report SecurityReport) error {
	if err := ValidateSecurityReport(report); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		material := finding.InShippedClosure || finding.RuntimeReachable
		if material && (finding.Severity == SeverityHigh || finding.Severity == SeverityCritical) && finding.Resolution == ResolutionUnresolved {
			return fmt.Errorf("unresolved high/critical vulnerability %q blocks publication", finding.ID)
		}
	}
	return nil
}

func AuthorizePublication(verified *VerifiedRelease) error {
	if verified == nil || verified.security.CandidateDigest != verified.value.Binary.Digest || !verified.qualification.JourneySucceeded || verified.qualification.CandidateDigest != verified.value.Binary.Digest {
		return fmt.Errorf("publication requires one fully verified release.json and exact binary")
	}
	return CheckSecurityGate(verified.security)
}

func validSeverity(severity Severity) bool {
	return severity == SeverityLow || severity == SeverityMedium || severity == SeverityHigh || severity == SeverityCritical
}

func validResolution(resolution FindingResolution) bool {
	switch resolution {
	case ResolutionUnresolved, ResolutionFixedBaseline, ResolutionMitigation, ResolutionFalsePositive, ResolutionNotAffected:
		return true
	default:
		return false
	}
}
