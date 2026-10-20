package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/huihui-top/banner-fingerprint/internal/model"
	"github.com/huihui-top/banner-fingerprint/internal/validation"
)

const maxFileBytes = 16 << 20

func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", "", "local JSON array file (required)")
	address := fs.String("server", "http://127.0.0.1:8080", "server base URL")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *input == "" || *timeout <= 0 || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "client requires --input and a positive --timeout")
		return 2
	}
	base, err := url.Parse(*address)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" ||
		base.RawQuery != "" || base.Fragment != "" || base.User != nil {
		fmt.Fprintln(stderr, "invalid --server URL")
		return 2
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/fingerprint"
	fail := func(err error) int {
		fmt.Fprintln(stderr, "client:", err)
		return 1
	}
	f, err := os.Open(*input)
	if err != nil {
		return fail(err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	closeErr := f.Close()
	if err != nil {
		return fail(err)
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	if len(data) > maxFileBytes {
		return fail(errors.New("input exceeds 16 MiB"))
	}
	items, err := validation.Batch(data)
	if err != nil {
		return fail(errors.New("input must be a valid JSON array"))
	}
	req, err := http.NewRequest(http.MethodPost, base.String(), bytes.NewReader(data))
	if err != nil {
		return fail(err)
	}
	req.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	fmt.Fprintf(stderr, "HTTP %d request_id=%s\n", resp.StatusCode, resp.Header.Get("X-Request-ID"))
	if resp.StatusCode != http.StatusOK {
		return fail(errors.New("request failed; inspect server logs using request_id"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil {
		return fail(err)
	}
	if len(body) > 16<<20 {
		return fail(errors.New("response exceeds 16 MiB"))
	}
	results, err := decodeResults(body, len(items))
	if err != nil {
		return fail(err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fail(fmt.Errorf("write results: %w", err))
	}
	return 0
}

func decodeResults(data []byte, expected int) ([]model.Result, error) {
	items, err := validation.Batch(data)
	if err != nil || len(items) != expected {
		return nil, errors.New("response must be an array with one result per input")
	}
	results := make([]model.Result, len(items))
	for i, item := range items {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil || len(fields) != 7 {
			return nil, fmt.Errorf("response item %d must contain seven fields", i)
		}
		for _, name := range []string{"ip", "protocol", "product", "version", "os_hint"} {
			value, ok := fields[name]
			var s string
			if !ok || len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &s) != nil {
				return nil, fmt.Errorf("response item %d: %s must be a string", i, name)
			}
		}
		port, portOK := fields["port"]
		confidence, confidenceOK := fields["confidence"]
		if !portOK || !confidenceOK || bytes.Equal(port, []byte("null")) || bytes.Equal(confidence, []byte("null")) {
			return nil, fmt.Errorf("response item %d has missing numeric fields", i)
		}
		if err := json.Unmarshal(item, &results[i]); err != nil {
			return nil, fmt.Errorf("response item %d: %w", i, err)
		}
		r := results[i]
		if r.Port < 0 || r.Port > 65535 || math.IsNaN(r.Confidence) || math.IsInf(r.Confidence, 0) ||
			r.Confidence < 0 || r.Confidence > 1 || r.Protocol == "" {
			return nil, fmt.Errorf("response item %d contains invalid result values", i)
		}
		if r.Protocol == "unknown" && (r.Product != "" || r.Version != "" || r.OSHint != "" || r.Confidence != 0) {
			return nil, fmt.Errorf("response item %d has inconsistent unknown fields", i)
		}
	}
	return results, nil
}
