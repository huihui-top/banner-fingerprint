// Package model separates the public seven-field contract from internal diagnostics.
package model

type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

type Input struct {
	IP     string
	Port   int
	Banner []byte
}

// Issue is internal only. Never marshal it into a fingerprint response.
type Issue struct {
	Code    string
	Field   string
	Message string
}

func Unknown(ip string, port int) Result {
	return Result{IP: ip, Port: port, Protocol: "unknown"}
}
