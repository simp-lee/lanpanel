package staticcontent

import "testing"

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
	for _, value := range []string{"index.html", "assets/app.js"} {
		if !cleanRelative(value) {
			t.Fatalf("relative %q rejected", value)
		}
	}
	for _, value := range []string{"../secret", "/absolute", "a\\b"} {
		if cleanRelative(value) {
			t.Fatalf("relative %q accepted", value)
		}
	}
}
