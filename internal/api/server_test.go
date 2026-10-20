package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/huihui-top/banner-fingerprint/internal/config"
	"github.com/huihui-top/banner-fingerprint/internal/fingerprint"
	"github.com/huihui-top/banner-fingerprint/internal/model"
)

func testServer(t *testing.T, cfg config.Config, output io.Writer) *Server {
	t.Helper()
	engine, err := fingerprint.Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, engine, slog.New(slog.NewJSONHandler(output, nil)))
	s.SetReady(true)
	return s
}

func request(s *Server, method, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestMixedBatchContractAndInternalLogs(t *testing.T) {
	var logs bytes.Buffer
	s := testServer(t, config.Defaults(), &logs)
	data, err := os.ReadFile("../../testdata/mixed.json")
	if err != nil {
		t.Fatal(err)
	}
	resp := request(s, "POST", "/fingerprint", "application/json; charset=utf-8", string(data))
	if resp.Code != 200 {
		t.Fatalf("status %d: %s", resp.Code, resp.Body)
	}
	var results []model.Result
	if err := json.Unmarshal(resp.Body.Bytes(), &results); err != nil || len(results) != 6 {
		t.Fatalf("results: %v %s", err, resp.Body)
	}
	wantProtocols := []string{"SSH", "unknown", "unknown", "unknown", "unknown", "HTTP"}
	for i, want := range wantProtocols {
		if results[i].Protocol != want {
			t.Errorf("item %d = %+v", i, results[i])
		}
	}
	if results[1].IP != "127.0.0.2" || results[1].Port != 0 ||
		results[3].IP != "127.0.0.3" || results[3].Port != 80 ||
		results[5].Product != "Jetty" || results[5].Version != "12.0.8" {
		t.Fatalf("bad recovery: %+v", results)
	}
	var objects []map[string]json.RawMessage
	_ = json.Unmarshal(resp.Body.Bytes(), &objects)
	for _, obj := range objects {
		if len(obj) != 7 {
			t.Fatalf("extra/missing fields: %v", obj)
		}
		for _, field := range []string{"ip", "port", "protocol", "product", "version", "os_hint", "confidence"} {
			if _, ok := obj[field]; !ok {
				t.Fatalf("missing %s", field)
			}
		}
	}
	id := resp.Header().Get("X-Request-ID")
	if id == "" || !strings.Contains(logs.String(), id) ||
		!strings.Contains(logs.String(), `"item_index":1`) || !strings.Contains(logs.String(), `"invalid":3`) {
		t.Fatalf("missing internal diagnostics: %s", logs.String())
	}
	if strings.Contains(logs.String(), "OpenSSH_9.9p2") {
		t.Fatal("raw banner leaked into logs")
	}
}

func TestRequestBoundaries(t *testing.T) {
	tests := []struct {
		name, method, path, contentType, body string
		status                                int
		configure                             func(*config.Config)
	}{
		{"empty", "POST", "/fingerprint", "application/json", "[]", 200, nil},
		{"null envelope", "POST", "/fingerprint", "application/json", "null", 400, nil},
		{"broken json", "POST", "/fingerprint", "application/json", "[", 400, nil},
		{"trailing data", "POST", "/fingerprint", "application/json", "[] {}", 400, nil},
		{"method", "GET", "/fingerprint", "application/json", "", 405, nil},
		{"media type", "POST", "/fingerprint", "text/plain", "[]", 415, nil},
		{"path", "POST", "/other", "application/json", "[]", 404, nil},
		{"body limit", "POST", "/fingerprint", "application/json", "[null]", 413, func(c *config.Config) { c.MaxRequestBytes = 3 }},
		{"batch limit", "POST", "/fingerprint", "application/json", "[null,null]", 413, func(c *config.Config) { c.MaxBatchSize = 1 }},
		{"item limit", "POST", "/fingerprint", "application/json", `[{"ip":"::1","port":80,"banner":"abcd"}]`, 200, func(c *config.Config) { c.MaxBannerBytes = 3 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			if tt.configure != nil {
				tt.configure(&cfg)
			}
			resp := request(testServer(t, cfg, io.Discard), tt.method, tt.path, tt.contentType, tt.body)
			if resp.Code != tt.status {
				t.Fatalf("status %d; want %d: %s", resp.Code, tt.status, resp.Body)
			}
			if resp.Header().Get("Content-Type") != "application/json" {
				t.Fatal("non-JSON response")
			}
			if tt.status != 200 && strings.TrimSpace(resp.Body.String()) != "[]" {
				t.Fatal("request errors must use []")
			}
			if tt.name == "empty" && strings.TrimSpace(resp.Body.String()) != "[]" {
				t.Fatal("empty array became null")
			}
		})
	}
}

type identifierFunc func(context.Context, model.Input) (model.Result, error)

func (f identifierFunc) Identify(ctx context.Context, in model.Input) (model.Result, error) {
	return f(ctx, in)
}

func TestPanicIsolation(t *testing.T) {
	s := New(config.Defaults(), identifierFunc(func(_ context.Context, in model.Input) (model.Result, error) {
		if string(in.Banner) == "panic" {
			panic("simulated parser defect")
		}
		return model.Result{IP: in.IP, Port: in.Port, Protocol: "HTTP", Confidence: 0.6}, nil
	}), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	s.SetReady(true)
	resp := request(s, "POST", "/fingerprint", "application/json",
		`[{"ip":"::1","port":80,"banner":"panic"},{"ip":"::2","port":80,"banner":"ok"}]`)
	var results []model.Result
	_ = json.Unmarshal(resp.Body.Bytes(), &results)
	if resp.Code != 200 || len(results) != 2 || results[0].Protocol != "unknown" ||
		results[0].IP != "::1" || results[1].Protocol != "HTTP" {
		t.Fatalf("panic corrupted batch: %d %s", resp.Code, resp.Body)
	}
}

func TestConcurrencyHealthAndTimeout(t *testing.T) {
	cfg := config.Defaults()
	cfg.MaxInflightRequests = 1
	cfg.RequestTimeout = 100 * time.Millisecond
	started := make(chan struct{})
	s := New(cfg, identifierFunc(func(ctx context.Context, in model.Input) (model.Result, error) {
		close(started)
		<-ctx.Done()
		return model.Unknown(in.IP, in.Port), ctx.Err()
	}), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	s.SetReady(true)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- request(s, "POST", "/fingerprint", "application/json", `[{"ip":"::1","port":80,"banner":"x"}]`)
	}()
	<-started
	if resp := request(s, "GET", "/health", "", ""); resp.Code != 200 || resp.Body.Len() != 0 {
		t.Fatal("health blocked by busy identifier")
	}
	if resp := request(s, "POST", "/fingerprint", "application/json", "[]"); resp.Code != 429 {
		t.Fatalf("expected 429, got %d", resp.Code)
	}
	if resp := <-done; resp.Code != 503 || strings.TrimSpace(resp.Body.String()) != "[]" {
		t.Fatalf("timeout contract: %d %s", resp.Code, resp.Body)
	}
	if resp := request(s, "POST", "/fingerprint", "application/json", "[]"); resp.Code != 200 {
		t.Fatal("slot not released after timeout")
	}
	s.SetReady(false)
	if resp := request(s, "GET", "/health", "", ""); resp.Code != http.StatusServiceUnavailable {
		t.Fatal("unready server reported healthy")
	}
}
