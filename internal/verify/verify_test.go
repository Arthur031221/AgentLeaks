package verify

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeToken() string { return "tok" + strings.Repeat("x", 20) }

func proberFor(t *testing.T, name string, srv *httptest.Server) *Prober {
	t.Helper()
	p := New()
	p.BaseURL = map[string]string{name: srv.URL}
	return p
}

func TestGitHubLive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fakeToken() {
			t.Errorf("unexpected Authorization header %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("unexpected Accept header %q", r.Header.Get("Accept"))
		}
		if r.Header.Get("User-Agent") != "agentleaks" {
			t.Errorf("unexpected User-Agent %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer srv.Close()

	res := proberFor(t, "github", srv).Probe(context.Background(), "github", fakeToken())
	if res.Status != StatusLive {
		t.Fatalf("status = %q, want live (detail %q)", res.Status, res.Detail)
	}
	if res.Detail != "HTTP 200 login=octocat" {
		t.Errorf("detail = %q", res.Detail)
	}
	if strings.Contains(res.Detail, fakeToken()) {
		t.Errorf("detail leaks the secret")
	}
}

func TestGitHubDead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	res := proberFor(t, "github", srv).Probe(context.Background(), "github", fakeToken())
	if res.Status != StatusDead {
		t.Fatalf("status = %q, want dead", res.Status)
	}
	if res.Detail != "HTTP 401" {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestGitHubUnknownOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	res := proberFor(t, "github", srv).Probe(context.Background(), "github", fakeToken())
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown", res.Status)
	}
	if res.Detail != "HTTP 500" {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	res := proberFor(t, "openai", srv).Probe(context.Background(), "openai", fakeToken())
	if res.Status != StatusUnknown || res.Detail != "rate limited" {
		t.Fatalf("got %+v", res)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)

	p := proberFor(t, "github", srv)
	p.Client = &http.Client{Timeout: 200 * time.Millisecond}
	res := p.Probe(context.Background(), "github", fakeToken())
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown", res.Status)
	}
	if res.Detail != "timeout" {
		t.Errorf("detail = %q, want timeout", res.Detail)
	}
}

func TestContextCancelled(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	res := proberFor(t, "github", srv).Probe(ctx, "github", fakeToken())
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown", res.Status)
	}
}

func TestSlackOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer "+fakeToken() {
			t.Errorf("unexpected Authorization header")
		}
		_, _ = w.Write([]byte(`{"ok":true,"user":"bob","team":"acme"}`))
	}))
	defer srv.Close()

	res := proberFor(t, "slack", srv).Probe(context.Background(), "slack", fakeToken())
	if res.Status != StatusLive {
		t.Fatalf("status = %q, want live (detail %q)", res.Status, res.Detail)
	}
	if res.Detail != "HTTP 200 ok=true user=bob team=acme" {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestSlackInvalidAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer srv.Close()

	res := proberFor(t, "slack", srv).Probe(context.Background(), "slack", fakeToken())
	if res.Status != StatusDead {
		t.Fatalf("status = %q, want dead", res.Status)
	}
	if res.Detail != "HTTP 200 error=invalid_auth" {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestSlackOtherError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"ratelimited"}`))
	}))
	defer srv.Close()

	res := proberFor(t, "slack", srv).Probe(context.Background(), "slack", fakeToken())
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown", res.Status)
	}
}

func TestStripeBasicAuth(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(fakeToken()+":"))
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"object":"balance"}`))
	}))
	defer srv.Close()

	res := proberFor(t, "stripe", srv).Probe(context.Background(), "stripe", fakeToken())
	if res.Status != StatusLive {
		t.Fatalf("status = %q, want live", res.Status)
	}
	if g, _ := got.Load().(string); g != want {
		t.Errorf("Authorization = %q, want %q", g, want)
	}
}

func TestAnthropicHeaders(t *testing.T) {
	var key, version atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key.Store(r.Header.Get("x-api-key"))
		version.Store(r.Header.Get("anthropic-version"))
		if r.Header.Get("Authorization") != "" {
			t.Errorf("anthropic probe must not send Authorization")
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	res := proberFor(t, "anthropic", srv).Probe(context.Background(), "anthropic", fakeToken())
	if res.Status != StatusLive {
		t.Fatalf("status = %q, want live", res.Status)
	}
	if k, _ := key.Load().(string); k != fakeToken() {
		t.Errorf("x-api-key = %q", k)
	}
	if v, _ := version.Load().(string); v != "2023-06-01" {
		t.Errorf("anthropic-version = %q", v)
	}
}

func TestAnthropicForbiddenIsDead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	res := proberFor(t, "anthropic", srv).Probe(context.Background(), "anthropic", fakeToken())
	if res.Status != StatusDead {
		t.Fatalf("status = %q, want dead", res.Status)
	}
}

func TestHuggingFaceName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"user","name":"alice"}`))
	}))
	defer srv.Close()

	res := proberFor(t, "huggingface", srv).Probe(context.Background(), "huggingface", fakeToken())
	if res.Status != StatusLive || res.Detail != "HTTP 200 name=alice" {
		t.Fatalf("got %+v", res)
	}
}

func TestUnsupportedNoCall(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()

	p := New()
	p.BaseURL = map[string]string{"nope": srv.URL}
	res := p.Probe(context.Background(), "nope", fakeToken())
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown", res.Status)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("unsupported provider made %d HTTP calls", calls)
	}
	if Supported("nope") {
		t.Errorf("Supported(nope) = true")
	}
	if Describe("nope") != "" {
		t.Errorf("Describe(nope) = %q", Describe("nope"))
	}
}

func TestEmptySecretNoCall(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()

	res := proberFor(t, "github", srv).Probe(context.Background(), "github", "")
	if res.Status != StatusUnknown {
		t.Fatalf("status = %q, want unknown", res.Status)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("empty secret made %d HTTP calls", calls)
	}
}

func TestProvidersMatchDescribe(t *testing.T) {
	names := Providers()
	if len(names) == 0 {
		t.Fatal("no providers")
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Errorf("Providers() not sorted at %d: %q >= %q", i, names[i-1], names[i])
		}
	}
	for _, n := range names {
		if !Supported(n) {
			t.Errorf("Supported(%q) = false", n)
		}
		d := Describe(n)
		if d == "" {
			t.Errorf("Describe(%q) is empty", n)
		}
		if !strings.HasPrefix(d, "GET https://") && !strings.HasPrefix(d, "POST https://") {
			t.Errorf("Describe(%q) = %q, want a method and https URL", n, d)
		}
	}
	want := []string{
		"anthropic", "github", "groq", "huggingface", "mistral", "npm", "openai",
		"openrouter", "replicate", "sendgrid", "slack", "stripe", "together", "vercel",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("Providers() = %v, want %v", names, want)
	}
}

func TestNoRedirectFollow(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	res := proberFor(t, "github", srv).Probe(context.Background(), "github", fakeToken())
	if res.Status != StatusUnknown || res.Detail != "HTTP 302" {
		t.Fatalf("got %+v", res)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("redirect followed, %d hits", hits)
	}
}
