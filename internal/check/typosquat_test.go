package check

import "testing"

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "a", 1},
		{"kitten", "sitting", 3},
		{"chalk", "chalks", 1},
		{"lodash", "lodahs", 2},
		{"express", "expres", 1},
		{"requests", "reqeusts", 2},
		{"react", "react", 0},
	}

	for _, tt := range tests {
		got := levenshtein(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCheckTyposquatting(t *testing.T) {
	tests := []struct {
		ecosystem string
		name      string
		maxDist   int
		wantMatch bool
		wantPkg   string
	}{
		{"npm", "chalks", 2, true, "chalk"},
		{"npm", "expres", 2, true, "express"},
		{"npm", "lodahs", 2, true, "lodash"},
		{"npm", "react", 2, false, ""},
		{"npm", "chalk", 2, false, ""},
		{"npm", "totally-different-name", 2, false, ""},
		{"pip", "reqeusts", 2, true, "requests"},
		{"pip", "djang0", 2, true, "django"},
		{"pip", "requests", 2, false, ""},
	}

	for _, tt := range tests {
		pkg, _, err := CheckTyposquatting(tt.ecosystem, tt.name, tt.maxDist)
		if err != nil {
			t.Fatalf("CheckTyposquatting(%q, %q, %d) error: %v", tt.ecosystem, tt.name, tt.maxDist, err)
		}
		gotMatch := pkg != ""
		if gotMatch != tt.wantMatch {
			t.Errorf("CheckTyposquatting(%q, %q, %d) match=%v, want %v (got pkg=%q)",
				tt.ecosystem, tt.name, tt.maxDist, gotMatch, tt.wantMatch, pkg)
		}
		if tt.wantPkg != "" && pkg != tt.wantPkg {
			t.Errorf("CheckTyposquatting(%q, %q, %d) pkg=%q, want %q",
				tt.ecosystem, tt.name, tt.maxDist, pkg, tt.wantPkg)
		}
	}
}
