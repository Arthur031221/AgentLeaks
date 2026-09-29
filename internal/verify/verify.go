// Package verify checks whether a found secret is still accepted by its
// provider. It is off by default. Every prober uses a read-only endpoint
// that returns account or catalogue metadata and changes nothing.
//
// A probe sends the secret to the provider that issued it, and nowhere else.
// Callers must print Notice and get consent before calling Probe.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Status is the outcome of one probe.
type Status string

const (
	// StatusLive means the provider accepted the secret.
	StatusLive Status = "live"
	// StatusDead means the provider answered 401 or 403.
	StatusDead Status = "dead"
	// StatusUnknown covers network errors, timeouts, unexpected status
	// codes and unsupported providers.
	StatusUnknown Status = "unknown"
)

// Result is what a probe reports. It never contains the secret.
type Result struct {
	Provider string
	Status   Status
	Detail   string
}

// Notice is the consent text printed before any probe runs.
const Notice = "Verification sends each key to the provider that issued it, using a read-only endpoint. " +
	"Nothing is sent anywhere else. The provider will see the request in its logs. " +
	"A live key is still a live key after this check. Revoke it at the provider."

// authKind selects how the secret is attached to the request.
type authKind int

const (
	authBearer authKind = iota
	authBasicUser
	authAnthropic
)

type verifier struct {
	method  string
	url     string
	auth    authKind
	headers map[string]string
	// detailKey names a top-level JSON string field to echo on success.
	detailKey string
	// slackStyle means the endpoint always answers 200 and the JSON "ok"
	// field carries the real outcome.
	slackStyle bool
}

var verifiers = map[string]verifier{
	"github": {
		method:    http.MethodGet,
		url:       "https://api.github.com/user",
		auth:      authBearer,
		headers:   map[string]string{"Accept": "application/vnd.github+json"},
		detailKey: "login",
	},
	"openai": {
		method: http.MethodGet,
		url:    "https://api.openai.com/v1/models",
		auth:   authBearer,
	},
	"anthropic": {
		method:  http.MethodGet,
		url:     "https://api.anthropic.com/v1/models",
		auth:    authAnthropic,
		headers: map[string]string{"anthropic-version": "2023-06-01"},
	},
	"huggingface": {
		method:    http.MethodGet,
		url:       "https://huggingface.co/api/whoami-v2",
		auth:      authBearer,
		detailKey: "name",
	},
	"stripe": {
		method: http.MethodGet,
		url:    "https://api.stripe.com/v1/balance",
		auth:   authBasicUser,
	},
	"slack": {
		method:     http.MethodPost,
		url:        "https://slack.com/api/auth.test",
		auth:       authBearer,
		headers:    map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		slackStyle: true,
	},
	"groq": {
		method: http.MethodGet,
		url:    "https://api.groq.com/openai/v1/models",
		auth:   authBearer,
	},
	"mistral": {
		method: http.MethodGet,
		url:    "https://api.mistral.ai/v1/models",
		auth:   authBearer,
	},
	"openrouter": {
		method: http.MethodGet,
		url:    "https://openrouter.ai/api/v1/auth/key",
		auth:   authBearer,
	},
	"together": {
		method: http.MethodGet,
		url:    "https://api.together.xyz/v1/models",
		auth:   authBearer,
	},
	"replicate": {
		method: http.MethodGet,
		url:    "https://api.replicate.com/v1/account",
		auth:   authBearer,
	},
	"vercel": {
		method: http.MethodGet,
		url:    "https://api.vercel.com/v2/user",
		auth:   authBearer,
	},
	"sendgrid": {
		method: http.MethodGet,
		url:    "https://api.sendgrid.com/v3/scopes",
		auth:   authBearer,
	},
	"npm": {
		method: http.MethodGet,
		url:    "https://registry.npmjs.org/-/whoami",
		auth:   authBearer,
	},
}

// Providers returns the supported verifier names, sorted.
func Providers() []string {
	names := make([]string, 0, len(verifiers))
	for name := range verifiers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Supported reports whether a verifier name has a prober.
func Supported(name string) bool {
	_, ok := verifiers[name]
	return ok
}

// Describe returns the endpoint a verifier calls, for documentation.
func Describe(name string) string {
	v, ok := verifiers[name]
	if !ok {
		return ""
	}
	return v.method + " " + v.url
}

// Prober runs probes. Zero values are filled in by New.
type Prober struct {
	Client  *http.Client
	BaseURL map[string]string
}

// New returns a Prober with a 10 second timeout that never follows redirects.
func New() *Prober {
	return &Prober{
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Probe sends one request to the named provider and classifies the answer.
func (p *Prober) Probe(ctx context.Context, name, secret string) Result {
	v, ok := verifiers[name]
	if !ok {
		return Result{Provider: name, Status: StatusUnknown, Detail: "no prober for this provider"}
	}
	if secret == "" {
		return Result{Provider: name, Status: StatusUnknown, Detail: "empty secret"}
	}
	url := v.url
	if p.BaseURL != nil {
		if override, ok := p.BaseURL[name]; ok && override != "" {
			url = override
		}
	}
	var body io.Reader
	if v.method == http.MethodPost {
		body = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, v.method, url, body)
	if err != nil {
		return Result{Provider: name, Status: StatusUnknown, Detail: "bad request"}
	}
	req.Header.Set("User-Agent", "agentleaks")
	for k, val := range v.headers {
		req.Header.Set(k, val)
	}
	switch v.auth {
	case authBearer:
		req.Header.Set("Authorization", "Bearer "+secret)
	case authBasicUser:
		req.SetBasicAuth(secret, "")
	case authAnthropic:
		req.Header.Set("x-api-key", secret)
	}

	client := p.Client
	if client == nil {
		client = New().Client
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Provider: name, Status: StatusUnknown, Detail: describeErr(err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if v.slackStyle {
		return slackResult(name, resp.StatusCode, raw)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		detail := "HTTP 200"
		if v.detailKey != "" {
			if val := jsonString(raw, v.detailKey); val != "" {
				detail += " " + v.detailKey + "=" + val
			}
		}
		return Result{Provider: name, Status: StatusLive, Detail: detail}
	case http.StatusUnauthorized, http.StatusForbidden:
		return Result{Provider: name, Status: StatusDead, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	case http.StatusTooManyRequests:
		return Result{Provider: name, Status: StatusUnknown, Detail: "rate limited"}
	default:
		return Result{Provider: name, Status: StatusUnknown, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
}

func slackResult(name string, code int, raw []byte) Result {
	if code == http.StatusTooManyRequests {
		return Result{Provider: name, Status: StatusUnknown, Detail: "rate limited"}
	}
	if code != http.StatusOK {
		return Result{Provider: name, Status: StatusUnknown, Detail: fmt.Sprintf("HTTP %d", code)}
	}
	var payload struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		User  string `json:"user"`
		Team  string `json:"team"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return Result{Provider: name, Status: StatusUnknown, Detail: "HTTP 200 unparseable body"}
	}
	if payload.OK {
		detail := "HTTP 200 ok=true"
		if payload.User != "" {
			detail += " user=" + payload.User
		}
		if payload.Team != "" {
			detail += " team=" + payload.Team
		}
		return Result{Provider: name, Status: StatusLive, Detail: detail}
	}
	switch payload.Error {
	case "invalid_auth", "token_revoked", "account_inactive":
		return Result{Provider: name, Status: StatusDead, Detail: "HTTP 200 error=" + payload.Error}
	}
	if payload.Error == "" {
		payload.Error = "unspecified"
	}
	return Result{Provider: name, Status: StatusUnknown, Detail: "HTTP 200 error=" + payload.Error}
}

func jsonString(raw []byte, key string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil {
		return ""
	}
	return s
}

// describeErr turns a transport error into a short label without echoing
// the request, which would carry the secret in its headers.
func describeErr(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return "timeout"
	}
	return "network error"
}
