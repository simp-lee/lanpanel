package staticcontent

import "testing"

func TestRegisterRejectsNoncanonicalStaticRootIDs(t *testing.T) {
	for _, id := range []string{
		"static_0000000000000000000000000000000g",
		"static_0000000000000000000000000000000A",
		"static_0000000000000000000000000000000 ",
		"static_0000000000000000000000000000000\x00",
	} {
		if _, err := Register(id, t.TempDir(), nil); err == nil || err.Error() != "static root identity invalid" {
			t.Fatalf("Register(%q) error = %v, want static ID rejection", id, err)
		}
	}
}

func TestStaticMappingGrammarIsClosed(t *testing.T) {
	cases := []struct {
		path      string
		directory bool
		ok        bool
	}{{"/robots.txt", false, true}, {"/assets/", true, true}, {"/assets", true, false}, {"/assets/../secret", false, false}, {"//assets", false, false}}
	for _, value := range cases {
		if got := validURLPath(value.path, value.directory); got != value.ok {
			t.Fatalf("path %q directory=%v got=%v", value.path, value.directory, got)
		}
	}
	relativeCases := []struct {
		name  string
		path  string
		valid bool
	}{
		{name: "backslash", path: `assets\app.js`},
		{name: "newline", path: "assets/\napp.js"},
		{name: "nul", path: "assets/\x00app.js"},
		{name: "del", path: "assets/\x7fapp.js"},
		{name: "absolute", path: "/etc/passwd"},
		{name: "parent_escape", path: "../secret"},
		{name: "legal_nested", path: "assets/app.js", valid: true},
	}
	for _, testCase := range relativeCases {
		t.Run("relative_"+testCase.name, func(t *testing.T) {
			if got := cleanRelative(testCase.path); got != testCase.valid {
				t.Fatalf("cleanRelative(%q) = %v, want %v", testCase.path, got, testCase.valid)
			}
		})
	}
}
