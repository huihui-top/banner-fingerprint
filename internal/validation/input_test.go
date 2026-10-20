package validation

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestItemValidation(t *testing.T) {
	tests := []struct {
		name, raw, code, ip string
		port                int
	}{
		{"valid ipv6", `{"ip":"::1","port":65535,"banner":""}`, "", "::1", 65535},
		{"missing banner", `{"ip":"1.2.3.4","port":80}`, "missing_field", "1.2.3.4", 80},
		{"null banner", `{"ip":"1.2.3.4","port":80,"banner":null}`, "invalid_banner", "1.2.3.4", 80},
		{"string port", `{"ip":"1.2.3.4","port":"80","banner":""}`, "invalid_port", "1.2.3.4", 0},
		{"float port", `{"ip":"1.2.3.4","port":80.0,"banner":""}`, "invalid_port", "1.2.3.4", 0},
		{"exponent port", `{"ip":"1.2.3.4","port":8e1,"banner":""}`, "invalid_port", "1.2.3.4", 0},
		{"null port", `{"ip":"1.2.3.4","port":null,"banner":""}`, "invalid_port", "1.2.3.4", 0},
		{"zero port", `{"ip":"1.2.3.4","port":0,"banner":""}`, "invalid_port", "1.2.3.4", 0},
		{"large port", `{"ip":"1.2.3.4","port":65536,"banner":""}`, "invalid_port", "1.2.3.4", 0},
		{"bad ip", `{"ip":"localhost","port":80,"banner":""}`, "invalid_ip", "", 80},
		{"ip whitespace", `{"ip":" ::1","port":80,"banner":""}`, "invalid_ip", "", 80},
		{"ip zone", `{"ip":"fe80::1%eth0","port":80,"banner":""}`, "invalid_ip", "", 80},
		{"null item", `null`, "invalid_item", "", 0},
		{"nonobject", `[]`, "invalid_item", "", 0},
		{"duplicate ip", `{"ip":"::1","ip":"::2","port":80,"banner":""}`, "duplicate_field", "", 80},
		{"duplicate extra", `{"ip":"::1","port":80,"banner":"","x":1,"x":2}`, "duplicate_field", "::1", 80},
		{"extra ignored", `{"ip":"::1","port":80,"banner":"","x":{"a":1}}`, "", "::1", 80},
		{"bad encoding", `{"ip":"::1","port":80,"banner":"","banner_encoding":"hex"}`, "unsupported_encoding", "::1", 80},
		{"null encoding", `{"ip":"::1","port":80,"banner":"","banner_encoding":null}`, "invalid_banner_encoding", "::1", 80},
		{"bad base64", `{"ip":"::1","port":80,"banner":"%%","banner_encoding":"base64"}`, "invalid_base64", "::1", 80},
		{"base64 newline", `{"ip":"::1","port":80,"banner":"YQ==\n","banner_encoding":"base64"}`, "invalid_base64", "::1", 80},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, issues := Item(json.RawMessage(tt.raw), 65536)
			if in.IP != tt.ip || in.Port != tt.port {
				t.Fatalf("identity = %q:%d; want %q:%d", in.IP, in.Port, tt.ip, tt.port)
			}
			if tt.code == "" {
				if len(issues) != 0 {
					t.Fatalf("unexpected issues: %+v", issues)
				}
			} else if len(issues) == 0 || issues[0].Code != tt.code {
				t.Fatalf("issues = %+v; want %s", issues, tt.code)
			}
		})
	}
}

func TestBinaryEncodingAndLimits(t *testing.T) {
	text, a := Item(json.RawMessage(`{"ip":"::1","port":3306,"banner":"J\u0000\u0000\u0000\n8.0.32\u0000"}`), 12)
	binary, b := Item(json.RawMessage(`{"ip":"::1","port":3306,"banner":"SgAAAAo4LjAuMzIA","banner_encoding":"base64"}`), 12)
	if len(a)+len(b) != 0 || !bytes.Equal(text.Banner, binary.Banner) || len(binary.Banner) != 12 {
		t.Fatalf("text/base64 differ: %x %x %+v %+v", text.Banner, binary.Banner, a, b)
	}
	for _, raw := range []string{
		`{"ip":"::1","port":80,"banner":"abcd"}`,
		`{"ip":"::1","port":80,"banner":"YWJjZA==","banner_encoding":"base64"}`,
	} {
		_, issues := Item(json.RawMessage(raw), 3)
		if len(issues) != 1 || issues[0].Code != "banner_too_large" {
			t.Fatalf("expected size rejection: %+v", issues)
		}
	}
}

func TestBatchEnvelope(t *testing.T) {
	for _, raw := range []string{"null", "{}", `"hello"`, "[] []", "[", ""} {
		if _, err := Batch([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid envelope %q", raw)
		}
	}
	items, err := Batch([]byte(`[null,{"port":"bad"}]`))
	if err != nil || len(items) != 2 {
		t.Fatal("batch decoder must preserve individually invalid elements")
	}
	if items, err := BatchBounded([]byte(`[null,null,null]`), 2); !errors.Is(err, ErrBatchLimit) || items != nil {
		t.Fatal("oversized batch must stop allocating at the record limit")
	}
}
