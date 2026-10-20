package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/huihui-top/banner-fingerprint/internal/api"
	"github.com/huihui-top/banner-fingerprint/internal/config"
	"github.com/huihui-top/banner-fingerprint/internal/fingerprint"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 && args[0] == "healthcheck" {
		return healthcheck(args[1:])
	}
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	cfg, err := config.Parse(args, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Time(slog.TimeKey, a.Value.Time().UTC())
			}
			return a
		},
	}))
	engine, err := fingerprint.Load(cfg.RulesFile)
	if err != nil {
		logger.Error("startup failed", "event", "rules_load_failed", "error", err.Error())
		return 1
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		logger.Error("listen failed", "event", "listen_failed", "error", err.Error())
		return 1
	}
	handler := api.New(cfg, engine, logger)
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: cfg.RequestTimeout + 5*time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	handler.SetReady(true)
	go func() { done <- server.Serve(listener) }()
	logger.Info("server ready", "event", "server_ready", "listen", listener.Addr().String(),
		"rules", engine.RuleCount(), "rules_file", cfg.RulesFile)
	select {
	case err := <-done:
		handler.SetReady(false)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err.Error())
			return 1
		}
	case <-signals.Done():
		handler.SetReady(false)
		logger.Info("server stopping", "event", "shutdown_started")
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown timed out", "error", err.Error())
			_ = server.Close()
			<-done
			return 1
		}
		<-done
	}
	logger.Info("server stopped", "event", "shutdown_completed")
	return 0
}

func healthcheck(args []string) int {
	fs := flag.NewFlagSet("server healthcheck", flag.ContinueOnError)
	address := fs.String("url", "http://127.0.0.1:8080/health", "health endpoint")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Get(*address)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: HTTP", response.StatusCode)
		return 1
	}
	return 0
}
