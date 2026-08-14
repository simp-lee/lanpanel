//go:build linux

package application

import "testing"

func TestProtectedPathContainmentRejectsOnlyManagedDescendants(t *testing.T) {
	parent := "/var/lib/lanpanel"
	cases := []struct {
		candidate string
		contained bool
	}{{parent, true}, {parent + "/state/file", true}, {"/srv/auth.htpasswd", false}, {"/var/lib/lanpanel-other/auth", false}, {"/var/lib/other", false}}
	for _, test := range cases {
		if got := pathContainedBy(parent, test.candidate); got != test.contained {
			t.Fatalf("containment %q: got %t want %t", test.candidate, got, test.contained)
		}
	}
}
