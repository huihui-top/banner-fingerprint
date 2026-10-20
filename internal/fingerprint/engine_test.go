package fingerprint

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/huihui-top/banner-fingerprint/internal/model"
	"github.com/huihui-top/banner-fingerprint/internal/validation"
)

func loadEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestAcceptanceSamples(t *testing.T) {
	engine := loadEngine(t)
	raw, err := os.ReadFile("../../samples/input.json")
	if err != nil {
		t.Fatal(err)
	}
	items, err := validation.Batch(raw)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("../../samples/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []model.Result
	if err := json.Unmarshal(expected, &want); err != nil {
		t.Fatal(err)
	}
	var got []model.Result
	for _, raw := range items {
		in, issues := validation.Item(raw, 65536)
		if len(issues) != 0 {
			t.Fatal(issues)
		}
		result, err := engine.Identify(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, result)
	}
	if !reflect.DeepEqual(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("sample %d: got %+v; want %+v", i, got[i], want[i])
			}
		}
	}
}

func TestUnseenVariantsAndFalsePositives(t *testing.T) {
	engine := loadEngine(t)
	tests := []struct{ name, banner, protocol, product, version, os string }{
		{"new ssh", "SSH-2.0-OpenSSH_10.2p3 Debian-5", "SSH", "OpenSSH", "10.2p3", "Debian"},
		{"ssh preamble", "Access restricted\r\nSSH-2.0-OpenSSH_9.9p2\r\n", "SSH", "OpenSSH", "9.9p2", ""},
		{"generic ssh", "SSH-2.0-custom_server", "SSH", "", "", ""},
		{"lowercase header", "HTTP/1.1 503 Busy\nsErVeR: nginx/1.29.2 (Ubuntu)", "HTTP", "nginx", "1.29.2", "Ubuntu"},
		{"versionless http", "HTTP/1.1 200 OK\r\nServer: nginx", "HTTP", "nginx", "", ""},
		{"jetty parenthesis", "HTTP/1.1 404 Not Found\r\nServer: Jetty(9.4.51.v20230217)", "HTTP", "Jetty", "9.4.51.v20230217", ""},
		{"http body ignored", "HTTP/1.1 200 OK\r\n\r\nServer: nginx/1.24.0\nSSH-2.0-OpenSSH_9.9", "HTTP", "", "", ""},
		{"generic http", "HTTP/1.0 200 OK", "HTTP", "", "", ""},
		{"smtp not ftp", "220 mail.example.org ESMTP ready", "unknown", "", "", ""},
		{"unknown error", "-ERR random error", "unknown", "", "", ""},
		{"redis crlf", "+PONG\r\n", "Redis", "Redis", "", ""},
		{"ftp version", "220 Welcome to Pure-FTPd 1.0.51", "FTP", "Pure-FTPd", "1.0.51", ""},
		{"empty known port", "", "unknown", "", "", ""},
		{"mysql missing terminator", "J\x00\x00\x00\n8.0.32", "unknown", "", "", ""},
		{"mysql short length", "\x01\x00\x00\x00\n8.0.32\x00", "unknown", "", "", ""},
		{"mysql random version", "8.0.32", "unknown", "", "", ""},
		{"tls binary", "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1", "unknown", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Every variant intentionally uses a non-default port.
			got, err := engine.Identify(context.Background(), model.Input{IP: "::1", Port: 54321, Banner: []byte(tt.banner)})
			if err != nil || got.Protocol != tt.protocol || got.Product != tt.product ||
				got.Version != tt.version || got.OSHint != tt.os {
				t.Fatalf("got %+v (%v), want %s/%s/%s/%s", got, err, tt.protocol, tt.product, tt.version, tt.os)
			}
		})
	}
}

func TestRuleValidationAndOrdering(t *testing.T) {
	a := Rule{ID: "a", Protocol: "HTTP", Kind: "product", Source: "http.server",
		Match: Match{Type: "exact", Pattern: "Custom"}, Product: "First", Priority: 10, Confidence: 0.8}
	b := a
	b.ID, b.Product = "b", "Second"
	for _, rules := range [][]Rule{{b, a}, {a, b}} {
		data, _ := json.Marshal(ruleFile{SchemaVersion: 1, Rules: rules})
		engine, err := Compile(data)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := engine.Identify(context.Background(), model.Input{Banner: []byte("HTTP/1.1 200 OK\r\nServer: Custom")})
		if got.Product != "First" {
			t.Fatal("rule file order changed tie-breaking")
		}
	}
	tests := []struct {
		name string
		edit func(*Rule)
	}{
		{"bad regex", func(r *Rule) { r.Match = Match{Type: "regex", Pattern: "("} }},
		{"missing capture", func(r *Rule) { r.Match.Type = "regex"; r.VersionGroup = "missing" }},
		{"source mismatch", func(r *Rule) { r.Source = "ssh.identification" }},
		{"bad confidence", func(r *Rule) { r.Confidence = 1.1 }},
		{"bad priority", func(r *Rule) { r.Priority = -1 }},
		{"bad OS regex", func(r *Rule) { r.OSHints = []OSHint{{Pattern: "(", Value: "x"}} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := a
			tt.edit(&r)
			data, _ := json.Marshal(ruleFile{SchemaVersion: 1, Rules: []Rule{r}})
			if _, err := Compile(data); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
	data, _ := json.Marshal(ruleFile{SchemaVersion: 1, Rules: []Rule{a, a}})
	if _, err := Compile(data); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatal("duplicate IDs accepted")
	}
}
