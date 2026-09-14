package debianversion

import "testing"

func TestCompareDebianOrdering(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
	}{
		{"1.22", "1.9", 1},
		{"1:1.0", "2.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0-1", "1.0-2", -1},
		{"1.0", "1.0-1", -1},
		{"1.0-1", "1.0-1+b1", -1},
		{"1.0a", "1.0-1", 1},
		{"1.0a", "1.01", -1},
		{"1.0", "1.0", 0},
	}
	for _, value := range cases {
		if got := Compare(value.left, value.right); (got < 0) != (value.want < 0) || (got > 0) != (value.want > 0) {
			t.Errorf("Compare(%q, %q) = %d, want sign %d", value.left, value.right, got, value.want)
		}
	}
}

func TestSatisfies(t *testing.T) {
	if Satisfies("1.0a", "1.01", "") {
		t.Fatal("version below minimum should not satisfy")
	}
	if !Satisfies("1.26.3-3+deb13u7", "1.26", "2.0") {
		t.Fatal("version should satisfy inclusive minimum and exclusive maximum")
	}
	if Satisfies("2.0", "1.26", "2.0") {
		t.Fatal("maximum bound should be exclusive")
	}
}
