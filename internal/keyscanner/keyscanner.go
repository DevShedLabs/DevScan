package keyscanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Finding struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	RuleName string   `json:"rule"`
	Match    string   `json:"match"`
	Severity Severity `json:"severity"`
}

type Rule struct {
	Name     string
	Severity Severity
	Pattern  *regexp.Regexp
}

var rules = []Rule{
	// AWS
	{Name: "aws-access-key-id", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(aws_access_key_id|aws_key|access_key_id)\s*[=:]\s*["']?(AKIA[0-9A-Z]{16})["']?`)},
	{Name: "aws-secret-access-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?`)},

	// GitHub
	{Name: "github-token", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\b(ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`)},

	// Stripe
	{Name: "stripe-live-secret-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`)},
	{Name: "stripe-live-publishable-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{24,}\b`)},

	// Twilio
	{Name: "twilio-account-sid", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bAC[0-9a-f]{32}\b`)},
	{Name: "twilio-auth-token", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(twilio_auth_token|auth_token)\s*[=:]\s*["']?([0-9a-f]{32})["']?`)},

	// SendGrid
	{Name: "sendgrid-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)},

	// Slack
	{Name: "slack-token", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bxox[bpoas]-[0-9A-Za-z-]{10,}\b`)},
	{Name: "slack-webhook", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`)},

	// GCP / Firebase
	{Name: "gcp-service-account", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`"type"\s*:\s*"service_account"`)},
	{Name: "firebase-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(firebase_api_key|FIREBASE_API_KEY)\s*[=:]\s*["']?([A-Za-z0-9_-]{39})["']?`)},

	// Anthropic (must come before OpenAI to avoid double-matching sk- prefix)
	{Name: "anthropic-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9\-_]{20,}\b`)},

	// OpenAI (match sk-proj- prefix; sk-ant- and sk-or- are caught by their own rules)
	{Name: "openai-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bsk-proj-[A-Za-z0-9\-_]{20,}\b`)},

	// Google AI / Gemini
	{Name: "google-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},

	// Groq
	{Name: "groq-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bgsk_[A-Za-z0-9]{52}\b`)},

	// OpenRouter
	{Name: "openrouter-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bsk-or-v1-[A-Za-z0-9]{64}\b`)},

	// npm / package registries
	{Name: "npm-token", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36,}\b`)},

	// Private keys / certs
	{Name: "private-key-header", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{Name: "pem-certificate", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)},

	// Mailgun
	{Name: "mailgun-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(mailgun_api_key|MAILGUN_API_KEY)\s*[=:]\s*["']?(key-[0-9a-zA-Z]{32})["']?`)},

	// Heroku
	{Name: "heroku-api-key", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(heroku_api_key|HEROKU_API_KEY)\s*[=:]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?`)},

	// Database URLs with embedded credentials
	{Name: "database-url-with-credentials", Severity: SeverityCritical,
		Pattern: regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s"']+`)},

	// Generic password (quoted only, to reduce bare-value false positives)
	{Name: "generic-password", Severity: SeverityMedium,
		Pattern: regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*["']([^"']{8,})["']`)},
}

// serviceNames is the dictionary of known service/provider names. When a variable
// name contains one of these words (e.g. MAILCHIMP_API_KEY, STRIPE_SECRET) and
// carries a non-trivial value, we name the finding after the service rather than
// reporting it as generic.
var serviceNames = []string{
	"stripe", "twilio", "sendgrid", "mailgun", "mailchimp", "postmark",
	"openai", "anthropic", "groq", "openrouter", "cohere", "replicate", "mistral", "perplexity", "huggingface",
	"google", "firebase", "gcp", "aws", "azure", "cloudflare", "digitalocean", "linode", "vultr",
	"github", "gitlab", "bitbucket", "jira", "linear", "asana", "notion",
	"slack", "discord", "telegram", "twitch", "twitter", "x_api", "facebook", "instagram",
	"shopify", "paypal", "braintree", "square", "adyen",
	"heroku", "vercel", "netlify", "render", "railway",
	"datadog", "newrelic", "sentry", "loggly", "splunk",
	"algolia", "elastic", "pinecone", "weaviate",
	"plaid", "finicity", "yodlee",
	"pusher", "ably", "pubnub",
	"mapbox", "googlemaps",
	"npm", "packagist", "rubygems", "pypi",
}

// serviceDictPattern matches VAR_NAMES containing a service keyword followed by
// a key/secret/token suffix with a non-trivial value.
var serviceDictPattern = regexp.MustCompile(`(?i)([A-Z][A-Z0-9_]*(?:_API)?(?:_KEY|_SECRET|_TOKEN|_ACCESS_KEY|_AUTH_TOKEN))\s*[=:]\s*["']?([A-Za-z0-9_\-\.\/+]{16,})["']?`)

// skipDirs are directories we never scan.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".terraform":   true,
	"dist":         true,
	"build":        true,
	".cache":       true,
	"__pycache__":  true,
}

// skipExts are file extensions we skip (binaries, media, docs, etc).
var skipExts = map[string]bool{
	// Binary / media
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".mp4": true, ".mp3": true, ".woff": true,
	".woff2": true, ".ttf": true, ".eot": true, ".pdf": true, ".zip": true,
	".tar": true, ".gz": true, ".tgz": true, ".bin": true, ".exe": true,
	".so": true, ".dylib": true, ".dll": true, ".lock": true, ".sum": true,
	".mod": true,
	// Documentation — full of example tokens and code snippets
	".md": true, ".mdx": true, ".rst": true, ".txt": true, ".adoc": true,
}

// Options controls scan behaviour.
type Options struct {
	// MaxDepth limits how many directory levels below Root are visited.
	// 0 means unlimited.
	MaxDepth int
	// Progress, if non-nil, is called with each file path before it is scanned.
	Progress func(path string)
}

// Scan walks root with default options (unlimited depth, no progress).
func Scan(root string) ([]Finding, error) {
	return ScanWithOptions(root, Options{})
}

// ScanWithOptions walks root respecting the supplied options.
func ScanWithOptions(root string, opts Options) ([]Finding, error) {
	var findings []Finding

	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}

		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			if opts.MaxDepth > 0 {
				depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
				if depth >= opts.MaxDepth {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if skipExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}

		// Skip example/template files — they contain placeholder values, not real secrets
		base := strings.ToLower(info.Name())
		if strings.Contains(base, ".example") || strings.Contains(base, ".sample") ||
			strings.Contains(base, ".template") || strings.HasSuffix(base, ".dist") {
			return nil
		}

		// Skip very large files (> 1 MB)
		if info.Size() > 1024*1024 {
			return nil
		}

		if opts.Progress != nil {
			opts.Progress(path)
		}

		found, err := scanFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		findings = append(findings, found...)
		return nil
	})

	return findings, err
}

func scanFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comment-only lines and regex/pattern definition lines to reduce false positives
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.Contains(line, "regexp.MustCompile") || strings.Contains(line, "regexp.Compile") {
			continue
		}

		var lineFindings []Finding
		for _, rule := range rules {
			if rule.Pattern.MatchString(line) {
				match := rule.Pattern.FindString(line)
				lineFindings = append(lineFindings, Finding{
					File:     path,
					Line:     lineNum,
					RuleName: rule.Name,
					Match:    redact(match),
					Severity: rule.Severity,
				})
			}
		}
		lineFindings = deduplicateLineFindings(lineFindings)

		// If no specific rule fired, try the service name dictionary.
		if len(lineFindings) == 0 {
			if f, ok := matchServiceDict(line, path, lineNum); ok {
				lineFindings = append(lineFindings, f)
			}
		}

		findings = append(findings, lineFindings...)
	}

	return findings, scanner.Err()
}

// matchServiceDict checks whether the line contains a known service keyword in
// the variable name, paired with a non-trivial value.
func matchServiceDict(line, filePath string, lineNum int) (Finding, bool) {
	m := serviceDictPattern.FindStringSubmatch(line)
	if m == nil {
		return Finding{}, false
	}
	varName := strings.ToLower(m[1])
	for _, svc := range serviceNames {
		if strings.Contains(varName, svc) {
			return Finding{
				File:     filePath,
				Line:     lineNum,
				RuleName: svc + "-key",
				Match:    redact(m[0]),
				Severity: SeverityCritical,
			}, true
		}
	}
	return Finding{}, false
}

// deduplicateLineFindings suppresses generic rule hits when a specific rule
// already fired on the same line, preventing double-reporting.
func deduplicateLineFindings(findings []Finding) []Finding {
	genericRules := map[string]bool{
		"generic-api-key":  true,
		"generic-password": true,
		"generic-secret":   true,
		"generic-token":    true,
	}

	hasSpecific := false
	for _, f := range findings {
		if !genericRules[f.RuleName] {
			hasSpecific = true
			break
		}
	}

	if !hasSpecific {
		return findings
	}

	out := findings[:0:0]
	for _, f := range findings {
		if !genericRules[f.RuleName] {
			out = append(out, f)
		}
	}
	return out
}

// redact masks the sensitive value portion of a match, keeping enough context
// to identify what was found without exposing the actual secret.
func redact(match string) string {
	if len(match) <= 8 {
		return strings.Repeat("*", len(match))
	}
	// Show first 4 chars and last 2, mask the middle
	visible := 4
	tail := 2
	middle := len(match) - visible - tail
	if middle <= 0 {
		return match[:4] + "***"
	}
	return match[:visible] + strings.Repeat("*", middle) + match[len(match)-tail:]
}
