package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr          string
	RulesFile           string
	MaxRequestBytes     int64
	MaxBatchSize        int
	MaxBannerBytes      int
	MaxInflightRequests int
	RequestTimeout      time.Duration
	ShutdownTimeout     time.Duration
	LogLevel            slog.Level
}

func Defaults() Config {
	return Config{ListenAddr: ":8080", RulesFile: "rules/fingerprints.json",
		MaxRequestBytes: 16 << 20, MaxBatchSize: 1000, MaxBannerBytes: 64 << 10,
		MaxInflightRequests: 4, RequestTimeout: 20 * time.Second,
		ShutdownTimeout: 30 * time.Second, LogLevel: slog.LevelInfo}
}

func Parse(args []string, stderr io.Writer) (Config, error) {
	c := Defaults()
	// Set environment values as flag defaults, then let explicit flags override.
	fs := flag.NewFlagSet("server serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.ListenAddr, "listen", c.ListenAddr, "HTTP listen address")
	fs.StringVar(&c.RulesFile, "rules", c.RulesFile, "fingerprint rules JSON")
	fs.Int64Var(&c.MaxRequestBytes, "max-request-bytes", c.MaxRequestBytes, "request body limit")
	fs.IntVar(&c.MaxBatchSize, "max-batch-size", c.MaxBatchSize, "batch record limit")
	fs.IntVar(&c.MaxBannerBytes, "max-banner-bytes", c.MaxBannerBytes, "decoded banner limit")
	fs.IntVar(&c.MaxInflightRequests, "max-inflight-requests", c.MaxInflightRequests, "concurrent batch limit")
	fs.DurationVar(&c.RequestTimeout, "request-timeout", c.RequestTimeout, "handler budget")
	fs.DurationVar(&c.ShutdownTimeout, "shutdown-timeout", c.ShutdownTimeout, "graceful shutdown budget")
	level := c.LogLevel.String()
	fs.StringVar(&level, "log-level", level, "debug, info, warn, error")
	env := map[string]string{
		"LISTEN_ADDR": "listen", "RULES_FILE": "rules", "MAX_REQUEST_BYTES": "max-request-bytes",
		"MAX_BATCH_SIZE": "max-batch-size", "MAX_BANNER_BYTES": "max-banner-bytes",
		"MAX_INFLIGHT_REQUESTS": "max-inflight-requests", "REQUEST_TIMEOUT": "request-timeout",
		"SHUTDOWN_TIMEOUT": "shutdown-timeout", "LOG_LEVEL": "log-level",
	}
	for name, option := range env {
		if value, ok := os.LookupEnv(name); ok {
			if err := fs.Set(option, value); err != nil {
				return c, fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
	}
	if err := c.LogLevel.UnmarshalText([]byte(level)); err != nil {
		return c, fmt.Errorf("log level: %w", err)
	}
	_, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return c, fmt.Errorf("listen address: %w", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return c, errors.New("listen port must be between 1 and 65535")
	}
	if c.RulesFile == "" || c.MaxRequestBytes <= 0 || c.MaxBatchSize <= 0 ||
		c.MaxBannerBytes <= 0 || c.MaxInflightRequests <= 0 ||
		c.RequestTimeout <= 0 || c.ShutdownTimeout <= 0 {
		return c, errors.New("paths must be nonempty and resource limits must be positive")
	}
	// Protect integer calculations in Base64 sizing and limit-plus-one reads.
	if c.MaxRequestBytes > 1<<30 || c.MaxBannerBytes > 1<<28 ||
		c.MaxBatchSize > 1000000 || c.MaxInflightRequests > 1024 {
		return c, errors.New("configured resource limits exceed supported bounds")
	}
	return c, nil
}
