// Package parsers extracts protocol-scoped evidence, never contacts the target.
package parsers

import (
	"bytes"
	"regexp"
	"strings"
)

var (
	httpStatus = regexp.MustCompile(`^HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) [1-5][0-9]{2}(?:[ \t]|$)`)
	sshID      = regexp.MustCompile(`^SSH-(?:2\.0|1\.99)-[^\s]+(?:[ \t].*)?$`)
	mysqlVer   = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?[A-Za-z0-9._+~:-]*$`)
)

// Evidence exposes only structurally appropriate sources to product rules.
func Evidence(banner []byte) map[string][]string {
	sources := make(map[string][]string)
	if len(banner) == 0 {
		return sources
	}
	if version, ok := mysqlVersion(banner); ok {
		sources["mysql.server_version"] = []string{version}
		return sources
	}
	lines := strings.Split(string(banner), "\n")
	first := strings.TrimSuffix(lines[0], "\r")
	if httpStatus.MatchString(first) {
		sources["http.protocol"] = []string{"HTTP"}
		for _, raw := range lines[1:] {
			line := strings.TrimSuffix(raw, "\r")
			if line == "" {
				break // Never look for product strings in the response body.
			}
			name, value, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(name, "Server") {
				sources["http.server"] = append(sources["http.server"], strings.TrimSpace(value))
			}
		}
		return sources
	}
	// SSH servers may send textual preamble lines before their identification.
	for i, raw := range lines {
		if i >= 50 {
			break
		}
		line := strings.TrimSuffix(raw, "\r")
		if sshID.MatchString(line) {
			sources["ssh.protocol"] = []string{"SSH"}
			sources["ssh.identification"] = []string{line}
			return sources
		}
	}
	if strings.HasPrefix(first, "+") || strings.HasPrefix(first, "-") {
		sources["redis.response"] = []string{first}
	}
	// 220 also occurs in SMTP. Only explicit FTP product rules can turn this
	// evidence into a result; there is deliberately no generic 220 rule.
	if strings.HasPrefix(first, "220 ") || strings.HasPrefix(first, "220-") {
		sources["ftp.greeting"] = []string{first}
		for _, raw := range lines[1:] {
			line := strings.TrimSuffix(raw, "\r")
			if strings.HasPrefix(line, "220 ") || strings.HasPrefix(line, "220-") {
				sources["ftp.greeting"] = append(sources["ftp.greeting"], line)
			}
		}
	}
	return sources
}

func mysqlVersion(b []byte) (string, bool) {
	if len(b) < 7 || b[3] != 0 || b[4] != 0x0a {
		return "", false
	}
	declared := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	end := bytes.IndexByte(b[5:], 0)
	if end < 0 || end == 0 || end > 128 || declared < end+2 {
		return "", false
	}
	version := string(b[5 : 5+end])
	// Captures can be shorter than the announced packet length. A complete
	// protocol byte + NUL-terminated version suffices for banner recognition.
	return version, mysqlVer.MatchString(version)
}
