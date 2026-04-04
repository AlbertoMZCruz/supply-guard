package check

import "testing"

func TestClassifyNpmRange(t *testing.T) {
	tests := []struct {
		version string
		want    VersionRisk
	}{
		// Exact
		{"1.2.3", RiskExact},
		{"0.0.1", RiskExact},
		{"=1.2.3", RiskExact},
		{"1.2.3-beta.1", RiskExact},

		// Conservative (patch-only)
		{"~1.2.3", RiskConservative},
		{"~0.5.0", RiskConservative},
		{"^0.2.3", RiskConservative},
		{"^0.0.3", RiskExact},

		// Permissive (minor+patch)
		{"^1.2.3", RiskPermissive},
		{"^2.0.0", RiskPermissive},
		{"1.x", RiskPermissive},
		{"1.2.x", RiskPermissive},
		{"1.2.X", RiskPermissive},
		{"1.0.0 - 2.0.0", RiskPermissive},

		// Dangerous
		{"*", RiskDangerous},
		{"latest", RiskDangerous},
		{"next", RiskDangerous},
		{"", RiskDangerous},
		{">=1.0.0", RiskDangerous},
		{"git+https://github.com/user/repo.git", RiskDangerous},
		{"github:user/repo", RiskDangerous},
		{"^1.0.0 || ^2.0.0", RiskDangerous},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := ClassifyNpmRange(tt.version)
			if got.Risk != tt.want {
				t.Errorf("ClassifyNpmRange(%q).Risk = %v, want %v (explanation: %s)", tt.version, got.Risk, tt.want, got.Explanation)
			}
		})
	}
}

func TestClassifyPipRange(t *testing.T) {
	tests := []struct {
		version string
		want    VersionRisk
	}{
		// Exact
		{"==1.2.3", RiskExact},
		{"==2.0.0", RiskExact},

		// Conservative
		{"~=1.2.3", RiskConservative},
		{"~=2.0", RiskConservative},

		// Permissive
		{">=1.2.3,<2.0.0", RiskPermissive},
		{"==1.*", RiskPermissive},

		// Dangerous
		{"", RiskDangerous},
		{"(no version)", RiskDangerous},
		{">=1.0.0", RiskDangerous},
		{">2.0", RiskDangerous},
		{"!=1.2.3", RiskDangerous},
		{"<=5.0", RiskDangerous},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := ClassifyPipRange(tt.version)
			if got.Risk != tt.want {
				t.Errorf("ClassifyPipRange(%q).Risk = %v, want %v (explanation: %s)", tt.version, got.Risk, tt.want, got.Explanation)
			}
		})
	}
}

func TestClassifyCargoRange(t *testing.T) {
	tests := []struct {
		version string
		want    VersionRisk
	}{
		// Exact
		{"=1.2.3", RiskExact},
		{"^0.0.3", RiskExact},

		// Conservative
		{"~1.2.3", RiskConservative},
		{"^0.2.3", RiskConservative},
		{"0.2.3", RiskConservative},

		// Permissive
		{"^1.2.3", RiskPermissive},
		{"1.2.3", RiskPermissive},
		{">=1.0.0, <2.0.0", RiskPermissive},

		// Dangerous
		{"*", RiskDangerous},
		{"", RiskDangerous},
		{">=1.0.0", RiskDangerous},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := ClassifyCargoRange(tt.version)
			if got.Risk != tt.want {
				t.Errorf("ClassifyCargoRange(%q).Risk = %v, want %v (explanation: %s)", tt.version, got.Risk, tt.want, got.Explanation)
			}
		})
	}
}

func TestClassifyNugetRange(t *testing.T) {
	tests := []struct {
		version string
		want    VersionRisk
	}{
		// Exact
		{"13.0.1", RiskExact},
		{"1.0.0.0", RiskExact},
		{"[1.0.0]", RiskExact},

		// Permissive
		{"13.*", RiskPermissive},
		{"[1.0.0, 2.0.0)", RiskPermissive},

		// Dangerous
		{"*", RiskDangerous},
		{"", RiskDangerous},
		{"[1.0.0,)", RiskDangerous},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := ClassifyNugetRange(tt.version)
			if got.Risk != tt.want {
				t.Errorf("ClassifyNugetRange(%q).Risk = %v, want %v (explanation: %s)", tt.version, got.Risk, tt.want, got.Explanation)
			}
		})
	}
}

func TestClassifyMavenRange(t *testing.T) {
	tests := []struct {
		version string
		want    VersionRisk
	}{
		// Exact
		{"1.2.3", RiskExact},
		{"[1.2.3]", RiskExact},
		{"2.0", RiskExact},

		// Permissive
		{"${project.version}", RiskPermissive},
		{"[1.0, 2.0)", RiskPermissive},

		// Dangerous
		{"LATEST", RiskDangerous},
		{"RELEASE", RiskDangerous},
		{"", RiskDangerous},
		{"[1.0,)", RiskDangerous},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := ClassifyMavenRange(tt.version)
			if got.Risk != tt.want {
				t.Errorf("ClassifyMavenRange(%q).Risk = %v, want %v (explanation: %s)", tt.version, got.Risk, tt.want, got.Explanation)
			}
		})
	}
}

func TestClassifyGradleRange(t *testing.T) {
	tests := []struct {
		version string
		want    VersionRisk
	}{
		// Exact
		{"1.2.3", RiskExact},
		{"2.0", RiskExact},

		// Permissive
		{"[1.0, 2.0)", RiskPermissive},

		// Dangerous
		{"latest.release", RiskDangerous},
		{"latest.integration", RiskDangerous},
		{"1.0.+", RiskDangerous},
		{"", RiskDangerous},
		{"[1.0,)", RiskDangerous},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := ClassifyGradleRange(tt.version)
			if got.Risk != tt.want {
				t.Errorf("ClassifyGradleRange(%q).Risk = %v, want %v (explanation: %s)", tt.version, got.Risk, tt.want, got.Explanation)
			}
		})
	}
}

func TestVersionRisk_String(t *testing.T) {
	tests := []struct {
		risk VersionRisk
		want string
	}{
		{RiskExact, "exact"},
		{RiskConservative, "conservative"},
		{RiskPermissive, "permissive"},
		{RiskDangerous, "dangerous"},
	}
	for _, tt := range tests {
		if got := tt.risk.String(); got != tt.want {
			t.Errorf("VersionRisk(%d).String() = %q, want %q", tt.risk, got, tt.want)
		}
	}
}
