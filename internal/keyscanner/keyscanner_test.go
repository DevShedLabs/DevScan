package keyscanner

import (
	"os"
	"path/filepath"
	"testing"
)

// fixturesDir holds test credential strings that cannot be committed to git.
// See testdata/.gitignore. Run `make testdata` or create manually before testing.
const fixturesDir = "testdata"

func TestScanFindsSecrets(t *testing.T) {
	// Each case is a line number in testdata/fixtures.env -> expected rule.
	// Line numbers correspond to the fixture file order.
	lineTests := []struct {
		line         int
		wantRule     string
		wantSeverity Severity
	}{
		{1, "aws-access-key-id", SeverityCritical},
		{2, "github-token", SeverityCritical},
		{3, "stripe-live-secret-key", SeverityCritical},
		{4, "stripe-live-publishable-key", SeverityCritical},
		{5, "sendgrid-api-key", SeverityCritical},
		{6, "slack-token", SeverityCritical},
		{7, "slack-webhook", SeverityCritical},
		{8, "npm-token", SeverityCritical},
		{9, "private-key-header", SeverityCritical},
		{10, "private-key-header", SeverityCritical},
		{11, "database-url-with-credentials", SeverityCritical},
		{12, "mailchimp-key", SeverityCritical},
		{13, "sentry-key", SeverityCritical},
		{14, "generic-password", SeverityMedium},
	}

	fixturePath := filepath.Join(fixturesDir, "fixtures.env")
	if _, err := os.Stat(fixturePath); os.IsNotExist(err) {
		t.Skipf("testdata/fixtures.env not present (excluded from git) — skipping fixture tests")
	}

	findings, err := Scan(fixturesDir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// Index findings by line number for easy lookup
	byLine := map[int][]Finding{}
	for _, f := range findings {
		byLine[f.Line] = append(byLine[f.Line], f)
	}

	for _, tt := range lineTests {
		t.Run(tt.wantRule, func(t *testing.T) {
			found := false
			for _, f := range byLine[tt.line] {
				if f.RuleName == tt.wantRule {
					found = true
					if f.Severity != tt.wantSeverity {
						t.Errorf("line %d rule %q: got severity %q, want %q", tt.line, tt.wantRule, f.Severity, tt.wantSeverity)
					}
				}
			}
			if !found {
				got := ruleNames(byLine[tt.line])
				t.Errorf("line %d: expected rule %q, got %v", tt.line, tt.wantRule, got)
			}
		})
	}
}

func TestNegativeCases(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"comment line", `# api_key = "your_key_here"`},
		{"short password", `password = "short"`},
		{"unknown service", `XYZZY_API_KEY=abcdefghijklmnopqrstuvwxyz12345`},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			f := filepath.Join(dir, "test.env")
			if err := os.WriteFile(f, []byte(tt.content+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			findings, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) > 0 {
				t.Errorf("expected no findings, got %d: %+v", len(findings), findings)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	cases := []struct{ input, wantPrefix string }{
		{"AKIAIOSFODNN7EXAMPLE", "AKIA"},
		{"short", "sh"},
		{"ab", ""},
	}
	for _, tt := range cases {
		got := redact(tt.input)
		if got == tt.input {
			t.Errorf("redact(%q) returned unredacted value", tt.input)
		}
	}
}

func TestSkipNodeModules(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules", "some-pkg")
	if err := os.MkdirAll(nm, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nm, "index.js"), []byte("MAILCHIMP_API_KEY=abcdefghijklmnopqrstuvwxyz12345\n"), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		t.Errorf("expected node_modules to be skipped, got %d findings", len(findings))
	}
}

func ruleNames(findings []Finding) []string {
	names := make([]string, len(findings))
	for i, f := range findings {
		names[i] = f.RuleName
	}
	return names
}
