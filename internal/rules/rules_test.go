package rules

import (
	"strings"
	"testing"
)

// Fixtures are built at test time from fragments and deterministic
// generators. No complete secret pattern appears as a literal in this file,
// so secret scanners never see one in the repository.

const (
	alnumSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	hexSet   = "0123456789abcdef"
	upperSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digitSet = "0123456789"
	b64Set   = alnumSet + "+/"
	urlSet   = alnumSet + "-_"
)

// gen returns a deterministic pseudo-random string over alphabet.
func gen(alphabet string, n int, seed uint32) string {
	x := seed*2654435761 + 12345
	b := make([]byte, n)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = alphabet[(x>>16)%uint32(len(alphabet))]
	}
	return string(b)
}

func alnum(n int, seed uint32) string  { return gen(alnumSet, n, seed) }
func hexs(n int, seed uint32) string   { return gen(hexSet, n, seed) }
func upper(n int, seed uint32) string  { return gen(upperSet, n, seed) }
func digits(n int, seed uint32) string { return gen(digitSet, n, seed) }
func b64(n int, seed uint32) string    { return gen(b64Set, n, seed) }
func urls(n int, seed uint32) string   { return gen(urlSet, n, seed) }

func frag(parts ...string) string { return strings.Join(parts, "") }
func env(k, v string) string      { return k + "=" + v }
func js(k, v string) string       { return `{"` + k + `": "` + v + `"}` }
func esc(k, v string) string      { return `\"` + k + `\":\"` + v + `\"` }

type fixture struct {
	rule string
	line string
	want string // expected secret for positives
	none bool   // negatives only: no rule at all may fire
}

func pos(rule, line, want string) fixture { return fixture{rule: rule, line: line, want: want} }
func neg(rule, line string) fixture       { return fixture{rule: rule, line: line} }
func clean(rule, line string) fixture     { return fixture{rule: rule, line: line, none: true} }

func positives() []fixture {
	var f []fixture
	add := func(rule, line, want string) { f = append(f, pos(rule, line, want)) }
	wrap := func(rule, secret string) { add(rule, js("value", secret), secret) }

	// Anthropic and OpenAI
	wrap("anthropic-api-key", frag("sk-ant-", "api03-", urls(93, 1)))
	wrap("anthropic-api-key", frag("sk-ant-", "oat01-", urls(80, 2)))
	wrap("openai-project-key", frag("sk-", "proj-", urls(120, 3)))
	wrap("openai-project-key", frag("sk-", "svcacct-", alnum(60, 4)))
	wrap("openai-project-key", frag("sk-", "admin-", alnum(60, 5)))
	wrap("openai-legacy-key", frag("sk-", alnum(20, 6), "T3Blbk", "FJ", alnum(20, 7)))
	wrap("openai-api-key", frag("sk-", alnum(48, 8)))
	add("openai-api-key", env("OPENAI_API_KEY", frag("sk-", alnum(44, 9))), frag("sk-", alnum(44, 9)))
	add("deepseek-api-key", env("DEEPSEEK_API_KEY", frag("sk-", hexs(32, 10))), frag("sk-", hexs(32, 10)))

	// AWS
	for i, p := range []string{"AKIA", "ASIA", "ABIA", "ACCA"} {
		s := frag(p, upper(16, uint32(20+i)))
		add("aws-access-key-id", env("AWS_ACCESS_KEY_ID", s), s)
	}
	awsSecret := b64(40, 30)
	add("aws-secret-access-key", env("AWS_SECRET_ACCESS_KEY", awsSecret), awsSecret)
	add("aws-secret-access-key", "aws-secret-access-key: "+awsSecret, awsSecret)
	add("aws-secret-access-key", js("awsSecretAccessKey", awsSecret), awsSecret)
	add("aws-secret-access-key", esc("aws_secret_key", awsSecret), awsSecret)

	// GitHub
	wrap("github-pat", frag("ghp_", alnum(36, 40)))
	add("github-pat", "git clone https://x:"+frag("ghp_", alnum(36, 41))+"@github.com/o/r.git", frag("ghp_", alnum(36, 41)))
	wrap("github-fine-grained-pat", frag("github_pat_", alnum(22, 42), "_", alnum(59, 43)))
	wrap("github-oauth-token", frag("gho_", alnum(36, 44)))
	wrap("github-app-token", frag("ghu_", alnum(36, 45)))
	wrap("github-app-token", frag("ghs_", alnum(36, 46)))
	wrap("github-refresh-token", frag("ghr_", alnum(76, 47)))

	// GitLab
	wrap("gitlab-pat", frag("glpat-", alnum(20, 50)))
	wrap("gitlab-runner-token", frag("glrt-", alnum(20, 51)))
	wrap("gitlab-deploy-token", frag("gldt-", alnum(20, 52)))

	// Stripe
	for i, p := range []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"} {
		wrap("stripe-secret-key", frag(p, alnum(24, uint32(60+i))))
	}
	wrap("stripe-webhook-secret", frag("whsec_", alnum(32, 65)))

	// Slack
	for i, p := range []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"} {
		wrap("slack-token", frag(p, digits(11, uint32(70+i)), "-", digits(13, uint32(80+i)), "-", alnum(24, uint32(90+i))))
	}
	wrap("slack-app-token", frag("xapp-1-A", upper(10, 100), "-", digits(12, 101), "-", hexs(64, 102)))
	wrap("slack-webhook-url", frag("https://hooks.slack.com/services/T", upper(8, 103), "/B", upper(10, 104), "/", alnum(24, 105)))

	// Google
	wrap("google-api-key", frag("AIza", urls(35, 110)))
	add("google-api-key", env("GEMINI_API_KEY", frag("AIza", urls(35, 111))), frag("AIza", urls(35, 111)))
	wrap("google-oauth-client-secret", frag("GOCSPX-", urls(28, 112)))
	wrap("google-oauth-access-token", frag("ya29.", urls(100, 113)))
	add("google-service-account", `{"type": "service_account", "project_id": "p", "private_key_id": "`+hexs(40, 114)+`"}`, hexs(40, 114))
	add("google-service-account", esc("private_key_id", hexs(40, 115)), hexs(40, 115))

	// Model providers
	wrap("huggingface-token", frag("hf_", alnum(34, 120)))
	wrap("groq-api-key", frag("gsk_", alnum(52, 121)))
	add("mistral-api-key", env("MISTRAL_API_KEY", alnum(32, 122)), alnum(32, 122))
	add("mistral-api-key", esc("mistralApiKey", alnum(32, 123)), alnum(32, 123))
	wrap("openrouter-api-key", frag("sk-or-v1-", hexs(64, 124)))
	add("together-api-key", env("TOGETHER_API_KEY", hexs(64, 125)), hexs(64, 125))
	wrap("replicate-api-token", frag("r8_", alnum(37, 126)))
	add("vercel-token", env("VERCEL_TOKEN", alnum(24, 127)), alnum(24, 127))
	wrap("supabase-access-token", frag("sbp_", hexs(40, 128)))
	wrap("supabase-secret-key", frag("sb_secret_", urls(30, 129)))
	add("cohere-api-key", env("COHERE_API_KEY", alnum(40, 130)), alnum(40, 130))
	wrap("xai-api-key", frag("xai-", alnum(80, 131)))
	wrap("perplexity-api-key", frag("pplx-", alnum(48, 132)))
	wrap("fireworks-api-key", frag("fw_", alnum(24, 133)))
	wrap("langfuse-secret-key", frag("sk-lf-", hexs(8, 134), "-", hexs(4, 135), "-", hexs(4, 136), "-", hexs(4, 137), "-", hexs(12, 138)))

	// Twilio, SendGrid, npm, PyPI
	add("twilio-api-key", "TWILIO_API_KEY_SID="+frag("SK", hexs(32, 140)), frag("SK", hexs(32, 140)))
	add("twilio-auth-token", env("TWILIO_AUTH_TOKEN", hexs(32, 141)), hexs(32, 141))
	wrap("sendgrid-api-key", frag("SG.", urls(22, 142), ".", urls(43, 143)))
	wrap("npm-token", frag("npm_", alnum(36, 144)))
	add("npm-authtoken-line", "//registry.npmjs.org/:_authToken="+alnum(40, 145), alnum(40, 145))
	wrap("pypi-token", frag("pypi-", "AgEIcHlwaS5vcmc", urls(80, 146)))

	// Cryptographic material
	add("private-key", frag("-----BEGIN ", "RSA ", "PRIVATE KEY", "-----"), frag("-----BEGIN ", "RSA ", "PRIVATE KEY", "-----"))
	add("private-key", js("private_key", frag("-----BEGIN ", "PRIVATE KEY", "-----\\n", b64(64, 150), "\\n-----END ", "PRIVATE KEY", "-----\\n")), frag("-----BEGIN ", "PRIVATE KEY", "-----"))
	add("private-key", frag("-----BEGIN ", "OPENSSH ", "PRIVATE KEY", "-----"), frag("-----BEGIN ", "OPENSSH ", "PRIVATE KEY", "-----"))
	add("private-key", frag("-----BEGIN ", "PGP ", "PRIVATE KEY", " BLOCK-----"), frag("-----BEGIN ", "PGP ", "PRIVATE KEY", " BLOCK-----"))
	wrap("age-secret-key", frag("AGE-SECRET-KEY-1", upper(58, 151)))
	jwt := frag("eyJ", urls(30, 152), ".", "eyJ", urls(60, 153), ".", urls(43, 154))
	add("jwt", "Authorization: Bearer "+jwt, jwt)
	add("jwt", js("access_token", jwt), jwt)

	// Other providers
	for i, p := range []string{"dop_v1_", "doo_v1_", "dor_v1_"} {
		wrap("digitalocean-token", frag(p, hexs(64, uint32(160+i))))
	}
	wrap("tailscale-key", frag("tskey-auth-k", alnum(10, 165), "CNTRL-", alnum(30, 166)))
	tailscaleKey := frag("tskey-api-", alnum(7, 167), "CNTRL-", alnum(18, 168))
	add("tailscale-key", js("value", tailscaleKey), tailscaleKey)
	for i, p := range []string{"shpat_", "shpca_", "shppa_", "shpss_"} {
		wrap("shopify-access-token", frag(p, hexs(32, uint32(170+i))))
	}
	tg := frag(digits(10, 175), ":AA", urls(33, 176))
	add("telegram-bot-token", "bot token: "+tg, tg)
	add("cloudflare-api-token", env("CLOUDFLARE_API_TOKEN", urls(40, 177)), urls(40, 177))
	add("cloudflare-api-token", js("cloudflare_api_key", hexs(37, 178)), hexs(37, 178))
	wrap("notion-integration-token", frag("ntn_", alnum(46, 179)))
	wrap("linear-api-key", frag("lin_api_", alnum(40, 180)))
	wrap("postman-api-key", frag("PMAK-", hexs(24, 181), "-", hexs(34, 182)))
	// Organization auth tokens contain a Base64 payload and a 43-character
	// Base64 secret. Include characters outside the URL-safe alphabet so the
	// fixture catches partial matches as well as missed tokens.
	sentryOrgToken := frag("sntrys_", strings.Repeat("A", 40), "+/==", "_", strings.Repeat("B", 41), "+/")
	add("sentry-auth-token", js("value", sentryOrgToken), sentryOrgToken)
	sentryUserToken := frag("sntryu_", hexs(64, 184))
	add("sentry-auth-token", js("value", sentryUserToken), sentryUserToken)
	for i, p := range []string{"dp.ct.", "dp.pt.", "dp.sa.", "dp.said.", "dp.scim.", "dp.audit."} {
		wrap("doppler-token", frag(p, alnum(40+i%5, uint32(190+i))))
	}
	wrap("doppler-token", frag("dp.st.", alnum(40, 196)))
	wrap("doppler-token", frag("dp.st.", strings.Repeat("a", 35), ".", alnum(44, 197)))
	add("mailgun-api-key", env("MAILGUN_API_KEY", frag("key-", hexs(32, 195))), frag("key-", hexs(32, 195)))
	add("datadog-api-key", env("DD_API_KEY", hexs(32, 196)), hexs(32, 196))
	add("datadog-api-key", env("DD_APP_KEY", hexs(40, 197)), hexs(40, 197))
	add("datadog-api-key", env("DATADOG_API_KEY", hexs(32, 198)), hexs(32, 198))
	add("datadog-api-key", "dd-api-key: "+hexs(32, 199), hexs(32, 199))
	add("datadog-api-key", "dd-app-key: "+hexs(40, 200), hexs(40, 200))
	uuid := frag(hexs(8, 201), "-", hexs(4, 202), "-", hexs(4, 203), "-", hexs(4, 204), "-", hexs(12, 205))
	add("heroku-api-key", env("HEROKU_API_KEY", uuid), uuid)

	// Connection strings and URLs
	schemes := []string{"postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "redis", "rediss", "amqp", "amqps", "mssql"}
	for i, s := range schemes {
		pw := alnum(20, uint32(210+i))
		add("db-connection-string", env("DATABASE_URL", frag(s, "://app:", pw, "@db.internal:5432/app")), pw)
	}
	pw := alnum(20, 230)
	add("url-with-credentials", "curl https://deploy:"+pw+"@git.internal.dev/repo.git", pw)
	add("url-with-credentials", "curl http://deploy:"+pw+"@git.internal.dev/repo.git", pw)

	// Generic
	add("generic-bearer-token", "Authorization: Bearer "+alnum(40, 240), alnum(40, 240))
	add("generic-api-key", js("api_key", alnum(32, 241)), alnum(32, 241))
	add("generic-api-key", env("SOME_SERVICE_API-KEY", alnum(32, 242)), alnum(32, 242))
	add("generic-api-key", "apikey: "+alnum(32, 243), alnum(32, 243))
	add("generic-api-key", js("access_token", alnum(32, 244)), alnum(32, 244))
	add("generic-api-key", js("client_secret", alnum(32, 245)), alnum(32, 245))
	add("generic-api-key", env("DB_PASSWORD", alnum(20, 246)), alnum(20, 246))
	add("generic-api-key", env("PASSWD", alnum(20, 247)), alnum(20, 247))
	add("generic-api-key", esc("api_key", alnum(32, 248)), alnum(32, 248))
	add("generic-api-key", env("SESSION_SECRET", alnum(32, 249)), alnum(32, 249))
	return f
}

func negatives() []fixture {
	return []fixture{
		neg("anthropic-api-key", js("value", frag("sk-ant-", "api03-", alnum(10, 1)))),
		neg("openai-project-key", js("value", frag("sk-", "proj-", alnum(10, 2)))),
		neg("openai-legacy-key", js("value", frag("sk-", alnum(20, 3), "T3Blbk", "FJ", alnum(5, 4)))),
		neg("openai-api-key", js("value", frag("sk-", strings.Repeat("a", 48)))),
		neg("openai-api-key", js("value", frag("sk-ant-", "api03-", urls(93, 5)))),
		neg("openai-api-key", js("value", frag("sk-or-v1-", hexs(64, 6)))),
		neg("openai-api-key", js("value", frag("sk_live_", alnum(24, 7)))),
		neg("deepseek-api-key", env("DEEPSEEK_API_KEY", frag("sk-", hexs(10, 8)))),
		neg("aws-access-key-id", env("AWS_ACCESS_KEY_ID", frag("AKIA", upper(12, 9)))),
		neg("aws-access-key-id", env("AWS_ACCESS_KEY_ID", frag("AKIA", "IOSFODNN7", "EXAMPLE"))),
		neg("aws-secret-access-key", env("AWS_SECRET_ACCESS_KEY", strings.Repeat("x", 40))),
		neg("aws-secret-access-key", env("AWS_SECRET_ACCESS_KEY", "${AWS_SECRET_ACCESS_KEY}")),
		neg("github-pat", js("value", frag("ghp_", alnum(20, 10)))),
		neg("github-fine-grained-pat", js("value", frag("github_pat_", alnum(22, 11)))),
		neg("github-oauth-token", js("value", frag("gho_", alnum(20, 12)))),
		neg("github-app-token", js("value", frag("ghu_", alnum(20, 13)))),
		neg("github-refresh-token", js("value", frag("ghr_", alnum(10, 14)))),
		neg("gitlab-pat", js("value", frag("glpat-", alnum(5, 15)))),
		neg("gitlab-runner-token", js("value", frag("glrt-", alnum(5, 16)))),
		neg("gitlab-deploy-token", js("value", frag("gldt-", alnum(5, 17)))),
		neg("stripe-secret-key", js("value", frag("sk_live_", alnum(10, 18)))),
		neg("stripe-secret-key", js("value", frag("pk_live_", alnum(24, 19)))),
		neg("stripe-webhook-secret", js("value", frag("whsec_", alnum(10, 20)))),
		neg("slack-token", js("value", frag("xoxb-", alnum(5, 21)))),
		neg("slack-token", js("value", frag("xoxz-", alnum(40, 22)))),
		neg("slack-app-token", js("value", frag("xapp-", alnum(10, 23)))),
		neg("slack-webhook-url", "https://hooks.slack.com/services/short"),
		neg("google-api-key", js("value", frag("AIza", urls(20, 24)))),
		neg("google-oauth-client-secret", js("value", frag("GOCSPX-", urls(10, 25)))),
		neg("google-oauth-access-token", js("value", frag("ya29.", alnum(5, 26)))),
		neg("google-service-account", `{"private_key_id": "`+hexs(10, 27)+`"}`),
		neg("huggingface-token", js("value", frag("hf_", alnum(10, 28)))),
		neg("groq-api-key", js("value", frag("gsk_", alnum(10, 29)))),
		neg("mistral-api-key", env("MISTRAL_API_KEY", "your-key-here")),
		neg("openrouter-api-key", js("value", frag("sk-or-v1-", hexs(10, 30)))),
		neg("together-api-key", env("TOGETHER_API_KEY", hexs(20, 31))),
		neg("replicate-api-token", js("value", frag("r8_", alnum(5, 32)))),
		neg("vercel-token", env("VERCEL_TOKEN", alnum(10, 33))),
		neg("supabase-access-token", js("value", frag("sbp_", hexs(10, 34)))),
		neg("supabase-secret-key", js("value", frag("sb_secret_", alnum(5, 35)))),
		neg("cohere-api-key", env("COHERE_API_KEY", alnum(10, 36))),
		neg("xai-api-key", js("value", frag("xai-", alnum(10, 37)))),
		neg("perplexity-api-key", js("value", frag("pplx-", alnum(10, 38)))),
		neg("fireworks-api-key", "fw_version = 3"),
		neg("fireworks-api-key", js("value", frag("fw_", strings.Repeat("a", 30)))),
		neg("langfuse-secret-key", js("value", frag("sk-lf-", hexs(8, 39)))),
		neg("twilio-api-key", js("value", frag("SK", hexs(32, 40)))),
		neg("twilio-auth-token", env("TWILIO_AUTH_TOKEN", "changeme")),
		neg("sendgrid-api-key", js("value", frag("SG.", urls(10, 41)))),
		neg("npm-token", js("value", frag("npm_", alnum(10, 42)))),
		neg("npm-authtoken-line", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}"),
		neg("pypi-token", js("value", frag("pypi-", alnum(10, 43)))),
		neg("private-key", "-----BEGIN CERTIFICATE-----"),
		neg("private-key", "the private key is stored in the keychain"),
		neg("age-secret-key", js("value", frag("AGE-SECRET-KEY-1", upper(10, 44)))),
		neg("jwt", js("value", frag("eyJ", urls(30, 45)))),
		neg("jwt", js("value", frag("eyJ", strings.Repeat("a", 20), ".eyJ", strings.Repeat("b", 20), ".", strings.Repeat("c", 20)))),
		neg("digitalocean-token", js("value", frag("dop_v1_", hexs(10, 46)))),
		neg("tailscale-key", js("value", "tskey-auth-short")),
		neg("tailscale-key", js("value", frag("tskey-api-", alnum(7, 169), "CNTRL-", alnum(17, 170)))),
		neg("shopify-access-token", js("value", frag("shpat_", hexs(10, 47)))),
		neg("telegram-bot-token", frag(digits(5, 48), ":AA", urls(10, 49))),
		neg("cloudflare-api-token", env("CLOUDFLARE_API_TOKEN", "xxxxxxxxx")),
		neg("notion-integration-token", js("value", frag("ntn_", alnum(10, 50)))),
		neg("linear-api-key", js("value", frag("lin_api_", alnum(10, 51)))),
		neg("postman-api-key", js("value", frag("PMAK-", hexs(10, 52)))),
		neg("sentry-auth-token", js("value", frag("sntrys_", alnum(10, 53)))),
		neg("sentry-auth-token", js("value", frag("sntryu_", hexs(32, 185)))),
		neg("doppler-token", js("value", "dp.st.short")),
		neg("doppler-token", js("value", frag("dp.pt.prd.", alnum(40, 198)))),
		neg("doppler-token", js("value", frag("dp.st.a.", alnum(40, 199)))),
		neg("doppler-token", js("value", frag("dp.st.", alnum(45, 200)))),
		neg("mailgun-api-key", env("MAILGUN_API_KEY", frag("key-", hexs(10, 54)))),
		neg("datadog-api-key", env("DD_API_KEY", hexs(10, 55))),
		neg("heroku-api-key", env("HEROKU_API_KEY", "not-a-uuid-at-all")),
		neg("db-connection-string", env("DATABASE_URL", "postgres://app:password@db/app")),
		neg("db-connection-string", env("DATABASE_URL", "postgres://localhost:5432/app")),
		neg("db-connection-string", env("DATABASE_URL", "postgres://app:${DB_PASSWORD}@db/app")),
		neg("url-with-credentials", "https://example.com:8080/path"),
		neg("url-with-credentials", "https://user:pass@example.com"),
		neg("generic-bearer-token", "Authorization: Bearer $TOKEN"),
		neg("generic-bearer-token", "Authorization: Bearer YOUR_TOKEN_HERE"),
		neg("generic-bearer-token", "Authorization: Bearer "+strings.Repeat("x", 40)),
		clean("generic-api-key", `"input_tokens": 2`),
		clean("generic-api-key", `"cache_read_input_tokens":24762`),
		clean("generic-api-key", `"max_tokens": 64000`),
		clean("generic-api-key", env("TOKEN", "[REDACTED:generic-api-key]")),
		clean("generic-api-key", js("access_token", "[REDACTED:generic-api-key]")),
		clean("generic-api-key", `api_key = os.environ["OPENAI_API_KEY"]`),
		clean("generic-api-key", "api_key: process.env.OPENAI_API_KEY"),
		clean("generic-api-key", `password = "correct horse battery staple"`),
		clean("generic-api-key", js("token", strings.Repeat("ab", 16))),
		clean("generic-api-key", js("secret", "/run/secrets/db_password")),
		clean("generic-api-key", js("api_key", "your-api-key-here-1234")),
		clean("generic-api-key", js("password", "example-password-123")),
		clean("generic-api-key", js("password_hash", "$2b$12$"+alnum(40, 56))),
	}
}

func TestEveryRuleHasPositiveAndNegative(t *testing.T) {
	set := MustLoad()
	havePos := map[string]bool{}
	haveNeg := map[string]bool{}
	for _, f := range positives() {
		if set.Get(f.rule) == nil {
			t.Errorf("positive fixture names unknown rule %q", f.rule)
		}
		havePos[f.rule] = true
	}
	for _, f := range negatives() {
		if set.Get(f.rule) == nil {
			t.Errorf("negative fixture names unknown rule %q", f.rule)
		}
		haveNeg[f.rule] = true
	}
	for _, r := range set.Rules {
		if !havePos[r.ID] {
			t.Errorf("rule %s has no positive fixture", r.ID)
		}
		if !haveNeg[r.ID] {
			t.Errorf("rule %s has no negative fixture", r.ID)
		}
	}
}

func TestPositives(t *testing.T) {
	set := MustLoad()
	for _, f := range positives() {
		ms := set.Scan([]byte(f.line))
		var hit *Match
		for i := range ms {
			if ms[i].Rule.ID == f.rule {
				hit = &ms[i]
				break
			}
		}
		if hit == nil {
			var ids []string
			for _, m := range ms {
				ids = append(ids, m.Rule.ID)
			}
			t.Errorf("%s: no match on %q (got %v)", f.rule, f.line, ids)
			continue
		}
		if hit.Secret != f.want {
			t.Errorf("%s: secret = %q, want %q", f.rule, hit.Secret, f.want)
		}
		if hit.Rule.Provider == "" || hit.Rule.Provider != set.Get(f.rule).Provider {
			t.Errorf("%s: provider = %q", f.rule, hit.Rule.Provider)
		}
		if f.line[hit.Start:hit.End] != hit.Secret {
			t.Errorf("%s: offsets do not point at the secret", f.rule)
		}
	}
}

func TestNegatives(t *testing.T) {
	set := MustLoad()
	for _, f := range negatives() {
		ms := set.Scan([]byte(f.line))
		for _, m := range ms {
			if m.Rule.ID == f.rule {
				t.Errorf("%s: fired on %q with %q", f.rule, f.line, m.Secret)
			}
			if f.none {
				t.Errorf("%s: %q should be clean but %s fired with %q", f.rule, f.line, m.Rule.ID, m.Secret)
			}
		}
	}
}

func TestKeywordCoverage(t *testing.T) {
	set := MustLoad()
	matched := map[string][]string{}
	for _, f := range positives() {
		for _, m := range set.Scan([]byte(f.line)) {
			if m.Rule.ID == f.rule {
				matched[f.rule] = append(matched[f.rule], strings.ToLower(f.line))
			}
		}
	}
	for _, r := range set.Rules {
		if len(r.Keywords) == 0 {
			t.Errorf("rule %s has no keywords", r.ID)
			continue
		}
		for _, kw := range r.Keywords {
			kw = strings.ToLower(kw)
			found := false
			for _, line := range matched[r.ID] {
				if strings.Contains(line, kw) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("rule %s: keyword %q has no matching positive fixture", r.ID, kw)
			}
		}
	}
}

func TestOverlapPrecedence(t *testing.T) {
	set := MustLoad()
	cases := []struct {
		line string
		want string
	}{
		{js("key", frag("sk-ant-", "api03-", urls(93, 300))), "anthropic-api-key"},
		{js("key", frag("sk-or-v1-", hexs(64, 301))), "openrouter-api-key"},
		{js("key", frag("sk-", "proj-", urls(80, 302))), "openai-project-key"},
		{js("key", frag("sk-", alnum(20, 303), "T3Blbk", "FJ", alnum(20, 304))), "openai-legacy-key"},
		{js("access_token", frag("ghp_", alnum(36, 305))), "github-pat"},
		{env("OPENAI_API_KEY", frag("sk-", alnum(48, 306))), "openai-api-key"},
	}
	for _, c := range cases {
		ms := set.Scan([]byte(c.line))
		if len(ms) != 1 {
			t.Errorf("%q: got %d matches, want 1", c.line, len(ms))
			continue
		}
		if ms[0].Rule.ID != c.want {
			t.Errorf("%q: rule = %s, want %s", c.line, ms[0].Rule.ID, c.want)
		}
	}
}

func TestTranscriptLineIsClean(t *testing.T) {
	set := MustLoad()
	line := `{"parentUuid":"` + hexs(8, 400) + `-` + hexs(4, 401) + `","isSidechain":false,` +
		`"message":{"model":"claude-opus-5-5","id":"msg_01` + alnum(24, 402) + `","type":"message","role":"assistant",` +
		`"content":[{"type":"thinking","thinking":"","signature":"` + b64(400, 403) + `"},` +
		`{"type":"tool_use","id":"toolu_01` + alnum(22, 404) + `","name":"Bash","input":{"command":"go test ./...","description":"Run tests"}}],` +
		`"stop_reason":"tool_use","usage":{"input_tokens":2,"cache_creation_input_tokens":10301,"cache_read_input_tokens":24762,` +
		`"output_tokens":421,"output_tokens_details":{"thinking_tokens":21},"service_tier":"standard"}},` +
		`"requestId":"req_011` + alnum(20, 405) + `","uuid":"` + hexs(8, 406) + `","timestamp":"2026-09-29T13:46:45.273Z",` +
		`"cwd":"/Users/arthur/Desktop/project","sessionId":"` + hexs(8, 407) + `","version":"2.1.282","gitBranch":"main"}`
	if ms := set.Scan([]byte(line)); len(ms) != 0 {
		for _, m := range ms {
			t.Errorf("transcript line matched %s: %q", m.Rule.ID, Mask(m.Secret))
		}
	}
	// A tool result quoting a df listing and a git log, also clean.
	result := `{"type":"user","message":{"role":"user","content":[{"tool_use_id":"toolu_01` + alnum(22, 408) + `","type":"tool_result",` +
		`"content":"Filesystem Size Used Avail Capacity\n/dev/disk3s1s1 460Gi 10Gi 300Gi 4% /\ncommit ` + hexs(40, 409) + ` (HEAD -> main)","is_error":false}]}}`
	if ms := set.Scan([]byte(result)); len(ms) != 0 {
		for _, m := range ms {
			t.Errorf("tool result matched %s: %q", m.Rule.ID, Mask(m.Secret))
		}
	}
}

func TestTwoSecretsInOffsetOrder(t *testing.T) {
	set := MustLoad()
	first := frag("hf_", alnum(34, 500))
	second := frag("ghp_", alnum(36, 501))
	line := "HF_TOKEN=" + first + " GITHUB_TOKEN=" + second
	ms := set.Scan([]byte(line))
	if len(ms) != 2 {
		t.Fatalf("got %d matches, want 2", len(ms))
	}
	if ms[0].Rule.ID != "huggingface-token" || ms[1].Rule.ID != "github-pat" {
		t.Errorf("rules = %s, %s", ms[0].Rule.ID, ms[1].Rule.ID)
	}
	if ms[0].Start >= ms[1].Start {
		t.Errorf("matches not in offset order: %d then %d", ms[0].Start, ms[1].Start)
	}
	if ms[0].Secret != first || ms[1].Secret != second {
		t.Errorf("secrets = %q, %q", Mask(ms[0].Secret), Mask(ms[1].Secret))
	}
}

func TestMaskAndFingerprint(t *testing.T) {
	secret := frag("ghp_", alnum(36, 600))
	m := Mask(secret)
	if len(m) != 11 {
		t.Errorf("Mask length = %d, want 11 (6 + 3 + 2)", len(m))
	}
	if !strings.HasPrefix(m, secret[:6]) || !strings.HasSuffix(m, secret[len(secret)-2:]) {
		t.Errorf("Mask = %q does not keep 6 leading and 2 trailing characters", m)
	}
	if strings.Contains(m, secret[6:len(secret)-2]) {
		t.Errorf("Mask leaks the middle of the secret")
	}
	if got := Mask("abc"); got != "***" {
		t.Errorf("Mask short = %q", got)
	}
	if got := Mask("abcdefghij"); got != "abc...j" {
		t.Errorf("Mask medium = %q", got)
	}
	fp := Fingerprint(secret)
	if len(fp) != 12 {
		t.Errorf("Fingerprint length = %d, want 12", len(fp))
	}
	if fp != Fingerprint(secret) {
		t.Errorf("Fingerprint is not stable")
	}
	if fp == Fingerprint(secret+"x") {
		t.Errorf("Fingerprint collides on different input")
	}
	if strings.Contains(fp, secret[4:12]) {
		t.Errorf("Fingerprint contains secret bytes")
	}
}

func TestRedactionMarker(t *testing.T) {
	set := MustLoad()
	r := Redaction("github-pat")
	if !RedactionPattern.MatchString(r) {
		t.Errorf("RedactionPattern does not match %q", r)
	}
	line := env("GITHUB_TOKEN", r)
	if ms := set.Scan([]byte(line)); len(ms) != 0 {
		t.Errorf("redaction marker was detected as a secret: %v", ms[0].Rule.ID)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"no rules":     "version = 1\n",
		"missing id":   "[[rules]]\nregex = 'x'\nkeywords = ['x']\n",
		"missing re":   "[[rules]]\nid = 'a'\nkeywords = ['x']\n",
		"bad regex":    "[[rules]]\nid = 'a'\nregex = '('\nkeywords = ['x']\n",
		"bad group":    "[[rules]]\nid = 'a'\nregex = 'x'\ngroup = 2\nkeywords = ['x']\n",
		"bad severity": "[[rules]]\nid = 'a'\nregex = 'x'\nseverity = 'urgent'\nkeywords = ['x']\n",
		"dup id":       "[[rules]]\nid = 'a'\nregex = 'x'\nkeywords = ['x']\n[[rules]]\nid = 'a'\nregex = 'y'\nkeywords = ['y']\n",
		"bad allow":    "[[rules]]\nid = 'a'\nregex = 'x'\nallowlist = ['(']\nkeywords = ['x']\n",
		"bad block":    "[[rules]]\nid = 'a'\nregex = 'x'\nblock_end = '('\nkeywords = ['x']\n",
		"not toml":     "this is not toml = = =",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	ok := "[[rules]]\nid = 'a'\nprovider = 'p'\nregex = 'x([0-9]+)'\ngroup = 1\nkeywords = ['x']\n"
	set, err := Parse([]byte(ok))
	if err != nil {
		t.Fatalf("valid rule set rejected: %v", err)
	}
	if set.Get("a").Severity != SeverityHigh {
		t.Errorf("default severity = %q", set.Get("a").Severity)
	}
	ms := set.Scan([]byte("see x12345 here"))
	if len(ms) != 1 || ms[0].Secret != "12345" {
		t.Errorf("group capture: %+v", ms)
	}
}

func TestDefaultSetShape(t *testing.T) {
	set := MustLoad()
	if len(set.Rules) < 60 {
		t.Errorf("expected at least 60 rules, got %d", len(set.Rules))
	}
	pk := set.Get("private-key")
	if pk == nil || !pk.IsBlock() {
		t.Fatalf("private-key must be a block rule")
	}
	if !pk.BlockEnd.MatchString(frag("-----END ", "RSA ", "PRIVATE KEY", "-----")) {
		t.Errorf("private-key block_end does not match the footer")
	}
	last := set.Rules[len(set.Rules)-1]
	if last.ID != "generic-api-key" {
		t.Errorf("generic-api-key must be the last rule, got %s", last.ID)
	}
	for _, r := range set.Rules {
		if r.Description == "" || r.Provider == "" {
			t.Errorf("rule %s lacks provider or description", r.ID)
		}
	}
}
