package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/huihui-top/banner-fingerprint/internal/config"
	"github.com/huihui-top/banner-fingerprint/internal/model"
	"github.com/huihui-top/banner-fingerprint/internal/validation"
)

type Identifier interface {
	Identify(context.Context, model.Input) (model.Result, error)
}

type Server struct {
	cfg    config.Config
	engine Identifier
	log    *slog.Logger
	slots  chan struct{}
	ready  atomic.Bool
	seq    atomic.Uint64
}

type counts struct {
	Total      int `json:"total"`
	Identified int `json:"identified"`
	Unknown    int `json:"unknown"`
	Invalid    int `json:"invalid"`
	Failed     int `json:"failed"`
}

func New(cfg config.Config, engine Identifier, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, engine: engine, log: logger, slots: make(chan struct{}, cfg.MaxInflightRequests)}
}

func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }

func (s *Server) requestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), s.seq.Add(1))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := s.requestID()
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Path == "/health" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !s.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	start := time.Now()
	log := s.log.With("request_id", id)
	status, payload, summary := s.process(w, r, log)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(payload); err != nil {
		log.Warn("response write failed", "event", "response_write_failed", "error", err.Error())
	}
	log.Info("request completed", "event", "request_completed", "http_status", status,
		"total", summary.Total, "identified", summary.Identified, "unknown", summary.Unknown,
		"invalid", summary.Invalid, "failed", summary.Failed,
		"duration_ms", time.Since(start).Milliseconds())
}

func (s *Server) process(w http.ResponseWriter, r *http.Request, log *slog.Logger) (status int, payload []byte, summary counts) {
	status, payload = http.StatusInternalServerError, []byte("[]\n")
	defer func() {
		if value := recover(); value != nil {
			status, payload = http.StatusInternalServerError, []byte("[]\n")
			log.Error("request panic recovered", "event", "internal_request_error",
				"panic_type", fmt.Sprintf("%T", value), "stack", string(debug.Stack()))
		}
	}()
	reject := func(code int, reason string) (int, []byte, counts) {
		log.Warn("request rejected", "event", "request_rejected", "code", reason)
		return code, []byte("[]\n"), summary
	}
	if r.URL.Path != "/fingerprint" {
		return reject(http.StatusNotFound, "not_found")
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return reject(http.StatusMethodNotAllowed, "method_not_allowed")
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return reject(http.StatusUnsupportedMediaType, "unsupported_media_type")
	}
	if !s.ready.Load() {
		return reject(http.StatusServiceUnavailable, "not_ready")
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return reject(http.StatusTooManyRequests, "concurrency_limit")
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	// Context cancellation alone does not interrupt a blocked body Read.
	readBudget := min(s.cfg.RequestTimeout, 10*time.Second)
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(readBudget))
	defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			return reject(http.StatusRequestEntityTooLarge, "request_too_large")
		case ctx.Err() != nil:
			return reject(http.StatusServiceUnavailable, "request_timeout")
		default:
			return reject(http.StatusBadRequest, "body_read_failed")
		}
	}
	if ctx.Err() != nil {
		return reject(http.StatusServiceUnavailable, "request_timeout")
	}
	items, err := validation.BatchBounded(data, s.cfg.MaxBatchSize)
	if errors.Is(err, validation.ErrBatchLimit) {
		return reject(http.StatusRequestEntityTooLarge, "batch_too_large")
	}
	if err != nil {
		return reject(http.StatusBadRequest, "invalid_json_array")
	}
	summary.Total = len(items)
	results := make([]model.Result, len(items))
	for i, raw := range items {
		if ctx.Err() != nil {
			return reject(http.StatusServiceUnavailable, "request_timeout")
		}
		result, category := s.item(ctx, raw, log, i)
		results[i] = result
		switch category {
		case "invalid":
			summary.Invalid++
		case "failed":
			summary.Failed++
		case "unknown":
			summary.Unknown++
		default:
			summary.Identified++
		}
	}
	if ctx.Err() != nil {
		return reject(http.StatusServiceUnavailable, "request_timeout")
	}
	payload, err = json.Marshal(results)
	if err != nil {
		log.Error("result encoding failed", "event", "result_encoding_failed", "error", err.Error())
		return http.StatusInternalServerError, []byte("[]\n"), summary
	}
	return http.StatusOK, append(payload, '\n'), summary
}

func (s *Server) item(ctx context.Context, raw json.RawMessage, log *slog.Logger, index int) (result model.Result, category string) {
	result, category = model.Unknown("", 0), "failed"
	defer func() {
		if value := recover(); value != nil {
			result = model.Unknown(result.IP, result.Port)
			category = "failed"
			log.Error("item panic recovered", "event", "internal_item_error", "item_index", index,
				"code", "internal_item_error", "panic_type", fmt.Sprintf("%T", value), "stack", string(debug.Stack()))
		}
	}()
	in, issues := validation.Item(raw, s.cfg.MaxBannerBytes)
	result = model.Unknown(in.IP, in.Port)
	if len(issues) > 0 {
		for _, issue := range issues {
			log.Warn("item rejected", "event", "item_rejected", "item_index", index,
				"code", issue.Code, "field", issue.Field, "reason", issue.Message)
		}
		return result, "invalid"
	}
	found, err := s.engine.Identify(ctx, in)
	if err != nil {
		log.Error("item processing failed", "event", "internal_item_error",
			"item_index", index, "code", "internal_item_error", "reason", err.Error())
		return result, "failed"
	}
	if found.Protocol == "unknown" {
		return found, "unknown"
	}
	return found, "identified"
}
