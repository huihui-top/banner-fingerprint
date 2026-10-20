package validation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/huihui-top/banner-fingerprint/internal/model"
)

var ErrBatchLimit = errors.New("batch contains too many items")

// Batch validates the envelope without strongly decoding individual records.
func Batch(data []byte) ([]json.RawMessage, error) {
	return BatchBounded(data, 0)
}

// BatchBounded stops allocating records at the configured limit. Validating the
// envelope first still distinguishes damaged JSON from a valid oversized batch.
func BatchBounded(data []byte, limit int) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '[' || !json.Valid(trimmed) {
		return nil, errors.New("expected a single JSON array")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	items := make([]json.RawMessage, 0)
	for dec.More() {
		if limit > 0 && len(items) >= limit {
			return nil, ErrBatchLimit
		}
		var item json.RawMessage
		if err := dec.Decode(&item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// Item keeps valid identity fields even when another field is invalid.
func Item(raw json.RawMessage, maxBannerBytes int) (model.Input, []model.Issue) {
	var in model.Input
	issues := make([]model.Issue, 0)
	add := func(code, field, message string) {
		issues = append(issues, model.Issue{Code: code, Field: field, Message: message})
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' || !utf8.Valid(raw) {
		add("invalid_item", "", "item must be a UTF-8 JSON object")
		return in, issues
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		add("invalid_item", "", "invalid object")
		return in, issues
	}
	fields := make(map[string]json.RawMessage)
	duplicates := make(map[string]bool)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			add("invalid_item", "", "invalid object key")
			return in, issues
		}
		key, ok := token.(string)
		if !ok {
			add("invalid_item", "", "object key must be a string")
			return in, issues
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			add("invalid_item", key, "invalid field value")
			return in, issues
		}
		if _, exists := fields[key]; exists {
			if !duplicates[key] {
				add("duplicate_field", key, "duplicate object key")
			}
			duplicates[key] = true
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		add("invalid_item", "", "unterminated object")
		return in, issues
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		add("invalid_item", "", "unexpected data after object")
		return in, issues
	}
	readString := func(key string, required bool) (string, bool) {
		value, exists := fields[key]
		if !exists {
			if required {
				add("missing_field", key, "required field is missing")
			}
			return "", false
		}
		if duplicates[key] {
			return "", false
		}
		var s string
		if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &s) != nil {
			add("invalid_"+key, key, "field must be a string")
			return "", false
		}
		return s, true
	}
	if ip, ok := readString("ip", true); ok {
		addr, err := netip.ParseAddr(ip)
		if err != nil || addr.Zone() != "" {
			add("invalid_ip", "ip", "expected an IPv4 or IPv6 address without a zone")
		} else {
			in.IP = ip
		}
	}
	if value, exists := fields["port"]; !exists {
		add("missing_field", "port", "required field is missing")
	} else if !duplicates["port"] {
		text := string(value)
		port, err := strconv.Atoi(text)
		if err != nil || port < 1 || port > 65535 || strings.ContainsAny(text, ".eE\"") {
			add("invalid_port", "port", "port must be an integer between 1 and 65535")
		} else {
			in.Port = port
		}
	}
	banner, bannerOK := readString("banner", true)
	encoding := "text"
	if _, exists := fields["banner_encoding"]; exists {
		var ok bool
		encoding, ok = readString("banner_encoding", false)
		if ok && encoding != "text" && encoding != "base64" {
			add("unsupported_encoding", "banner_encoding", "supported encodings: text, base64")
		}
	}
	if !bannerOK || len(issues) != 0 {
		return in, issues
	}
	if encoding == "base64" {
		// Bound allocation first; the exact decoded size is checked afterwards.
		if len(banner) > base64.StdEncoding.EncodedLen(maxBannerBytes) {
			add("banner_too_large", "banner", "decoded banner exceeds size limit")
			return in, issues
		}
		if strings.ContainsAny(banner, " \t\r\n") {
			add("invalid_base64", "banner", "base64 must not contain whitespace")
			return in, issues
		}
		data, err := base64.StdEncoding.Strict().DecodeString(banner)
		if err != nil {
			add("invalid_base64", "banner", "expected padded standard base64")
			return in, issues
		}
		in.Banner = data
	} else {
		in.Banner = []byte(banner)
	}
	if len(in.Banner) > maxBannerBytes {
		in.Banner = nil
		add("banner_too_large", "banner", "decoded banner exceeds size limit")
	}
	return in, issues
}
