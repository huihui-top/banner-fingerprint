package fingerprint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
)

type Match struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

type OSHint struct {
	Pattern string `json:"pattern"`
	Value   string `json:"value"`
}

type Rule struct {
	ID           string   `json:"id"`
	Protocol     string   `json:"protocol"`
	Kind         string   `json:"kind"`
	Source       string   `json:"source"`
	Match        Match    `json:"match"`
	Product      string   `json:"product"`
	VersionGroup string   `json:"version_group,omitempty"`
	OSHints      []OSHint `json:"os_hints,omitempty"`
	Priority     int      `json:"priority"`
	Confidence   float64  `json:"confidence"`
}

type ruleFile struct {
	SchemaVersion int    `json:"schema_version"`
	Rules         []Rule `json:"rules"`
}

type compiledRule struct {
	Rule
	expression *regexp.Regexp
	versionIdx int
	osPatterns []*regexp.Regexp
}

var sourceProtocol = map[string]string{
	"http.server": "HTTP", "http.protocol": "HTTP",
	"ssh.identification": "SSH", "ssh.protocol": "SSH",
	"mysql.server_version": "MySQL", "redis.response": "Redis", "ftp.greeting": "FTP",
}

func Load(path string) (*Engine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rules: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	if len(data) > 4<<20 {
		return nil, errors.New("rules file exceeds 4 MiB")
	}
	return Compile(data)
}

func Compile(data []byte) (*Engine, error) {
	var file ruleFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("unexpected data after rule file")
	}
	if file.SchemaVersion != 1 || len(file.Rules) == 0 || len(file.Rules) > 4096 {
		return nil, errors.New("rules require schema_version 1 and 1..4096 entries")
	}
	engine := &Engine{}
	seen := make(map[string]bool)
	for _, r := range file.Rules {
		if r.ID == "" || len(r.ID) > 128 || seen[r.ID] {
			return nil, fmt.Errorf("empty, oversized or duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		fail := func(message string) (*Engine, error) {
			return nil, fmt.Errorf("rule %q: %s", r.ID, message)
		}
		if protocol, exists := sourceProtocol[r.Source]; !exists || protocol != r.Protocol {
			return fail("unsupported source or protocol/source mismatch")
		}
		if r.Kind != "product" && r.Kind != "protocol" {
			return fail("kind must be product or protocol")
		}
		if (r.Kind == "product" && r.Product == "") || len(r.Product) > 128 {
			return fail("product name is required and must fit 128 bytes")
		}
		if r.Kind == "protocol" && (r.Product != "" || r.VersionGroup != "") {
			return fail("protocol rules must not specify product or software version")
		}
		if r.Priority < 0 || r.Priority > 1000000 {
			return fail("priority must be between 0 and 1000000")
		}
		if math.IsNaN(r.Confidence) || math.IsInf(r.Confidence, 0) || r.Confidence <= 0 || r.Confidence > 1 {
			return fail("known-result confidence must be greater than 0 and at most 1")
		}
		if r.Match.Pattern == "" || len(r.Match.Pattern) > 16384 {
			return fail("match pattern must be nonempty and fit 16384 bytes")
		}
		c := compiledRule{Rule: r, versionIdx: -1}
		switch r.Match.Type {
		case "regex":
			re, err := regexp.Compile(r.Match.Pattern)
			if err != nil {
				return fail("invalid match regular expression: " + err.Error())
			}
			c.expression = re
			if r.VersionGroup != "" {
				c.versionIdx = re.SubexpIndex(r.VersionGroup)
				if c.versionIdx < 1 {
					return fail("version_group must refer to a named capture")
				}
			}
		case "exact":
			if r.VersionGroup != "" {
				return fail("exact matches cannot extract a version group")
			}
		default:
			return fail("match type must be regex or exact")
		}
		if len(r.OSHints) > 32 {
			return fail("too many OS hint patterns")
		}
		for _, hint := range r.OSHints {
			if hint.Pattern == "" || len(hint.Pattern) > 4096 || hint.Value == "" || len(hint.Value) > 128 {
				return fail("OS hint must have a bounded pattern and value")
			}
			re, err := regexp.Compile(hint.Pattern)
			if err != nil {
				return fail("invalid OS regular expression: " + err.Error())
			}
			c.osPatterns = append(c.osPatterns, re)
		}
		engine.rules = append(engine.rules, c)
	}
	// Compile ordering once. The engine is immutable and safe across requests.
	sort.Slice(engine.rules, func(i, j int) bool {
		a, b := engine.rules[i], engine.rules[j]
		if a.Kind != b.Kind {
			return a.Kind == "product"
		}
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.ID < b.ID
	})
	return engine, nil
}
