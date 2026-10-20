package client

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/huihui-top/banner-fingerprint/internal/api"
	"github.com/huihui-top/banner-fingerprint/internal/config"
	"github.com/huihui-top/banner-fingerprint/internal/fingerprint"
)

func TestClientSendsMixedBatchAndExitsSuccessfully(t *testing.T) {
	engine, err := fingerprint.Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	handler := api.New(config.Defaults(), engine, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	handler.SetReady(true)
	server := httptest.NewServer(handler)
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--input", "../../testdata/mixed.json", "--server", server.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("client rejected individually invalid records: %d %s", code, stderr.String())
	}
	results, err := decodeResults(stdout.Bytes(), 6)
	if err != nil || results[0].Protocol != "SSH" || results[5].Protocol != "HTTP" {
		t.Fatalf("output corrupted: %s %v", stdout.String(), err)
	}
}

func TestClientFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte("[null]"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		code int
		body string
	}{
		{"http failure", 500, "[]"},
		{"missing results", 200, "[]"},
		{"bad result", 200, `[{"protocol":"unknown"}]`},
		{"null numeric fields", 200, `[{"ip":"","port":null,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":null}]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.code)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer s.Close()
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"--input", path, "--server", s.URL}, &stdout, &stderr); code != 1 {
				t.Fatalf("exit %d, wanted 1", code)
			}
			if stdout.Len() != 0 {
				t.Fatal("failure wrote success output")
			}
		})
	}
}
