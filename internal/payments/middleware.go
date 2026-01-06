package payments

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	x402 "github.com/coinbase/x402/go"
	"github.com/coinbase/x402/go/extensions/bazaar"
	x402http "github.com/coinbase/x402/go/http"
)

type MiddlewareConfig struct {
	Routes             x402http.RoutesConfig
	FacilitatorClients []x402.FacilitatorClient
	Schemes            []SchemeRegistration
	PaywallConfig      *x402http.PaywallConfig
	ErrorHandler       func(http.ResponseWriter, *http.Request, error)
	SettlementHandler  func(http.ResponseWriter, *http.Request, *x402.SettleResponse)
	Logger             *slog.Logger
}

type SchemeRegistration struct {
	Network x402.Network
	Server  x402.SchemeNetworkServer
}

func PaymentMiddlewareFromConfig(routes x402http.RoutesConfig, cfg MiddlewareConfig) func(http.Handler) http.HandlerFunc {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	serverOpts := []x402.ResourceServerOption{}
	for _, client := range cfg.FacilitatorClients {
		serverOpts = append(serverOpts, x402.WithFacilitatorClient(client))
	}

	httpServer := x402http.Newx402HTTPResourceServer(routes, serverOpts...)
	httpServer.RegisterExtension(bazaar.BazaarResourceServerExtension)

	for _, scheme := range cfg.Schemes {
		httpServer.Register(scheme.Network, scheme.Server)
	}

	// Sync with facilitator
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Initialize(ctx); err != nil {
		cfg.Logger.Warn("failed to initialize x402 server", "error", err)
	}

	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			adapter := NewStdAdapter(r)
			reqCtx := x402http.HTTPRequestContext{
				Adapter: adapter,
				Path:    r.URL.Path,
				Method:  r.Method,
			}

			if !httpServer.RequiresPayment(reqCtx) {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			result := httpServer.ProcessHTTPRequest(ctx, reqCtx, cfg.PaywallConfig)

			switch result.Type {
			case x402http.ResultNoPaymentRequired:
				next.ServeHTTP(w, r)
			case x402http.ResultPaymentError:
				handlePaymentError(w, result.Response)
			case x402http.ResultPaymentVerified:
				handlePaymentVerified(w, r, next, httpServer, result, cfg)
			}
		}
	}
}

func handlePaymentError(w http.ResponseWriter, response *x402http.HTTPResponseInstructions) {
	for key, value := range response.Headers {
		w.Header().Set(key, value)
	}
	w.WriteHeader(response.Status)
	if response.IsHTML {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(response.Body.(string)))
	} else {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response.Body)
	}
}

func handlePaymentVerified(w http.ResponseWriter, r *http.Request, next http.Handler, server *x402http.HTTPServer, result x402http.HTTPProcessResult, config MiddlewareConfig) {
	rec := newResponseCapture(w)
	next.ServeHTTP(rec, r)

	if rec.statusCode >= 400 {
		rec.flush()
		return
	}

	settleResult := server.ProcessSettlement(r.Context(), *result.PaymentPayload, *result.PaymentRequirements)
	if !settleResult.Success {
		http.Error(w, "Settlement failed: "+settleResult.ErrorReason, http.StatusPaymentRequired)
		return
	}

	for key, value := range settleResult.Headers {
		rec.Header().Set(key, value)
	}

	if config.SettlementHandler != nil {
		config.SettlementHandler(rec, r, &x402.SettleResponse{
			Success:     true,
			Transaction: settleResult.Transaction,
			Network:     settleResult.Network,
			Payer:       settleResult.Payer,
		})
	}
	rec.flush()
}

type StdAdapter struct{ req *http.Request }

func NewStdAdapter(req *http.Request) *StdAdapter  { return &StdAdapter{req: req} }
func (a *StdAdapter) GetHeader(name string) string { return a.req.Header.Get(name) }
func (a *StdAdapter) GetMethod() string            { return a.req.Method }
func (a *StdAdapter) GetPath() string              { return a.req.URL.Path }
func (a *StdAdapter) GetURL() string {
	scheme := "http"
	if a.req.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, a.req.Host, a.req.URL.Path)
}
func (a *StdAdapter) GetAcceptHeader() string { return a.req.Header.Get("Accept") }
func (a *StdAdapter) GetUserAgent() string    { return a.req.Header.Get("User-Agent") }

type responseCapture struct {
	original   http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	header     http.Header
	written    bool
	mu         sync.Mutex
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{original: w, body: &bytes.Buffer{}, header: make(http.Header), statusCode: 200}
}
func (w *responseCapture) Header() http.Header { return w.header }
func (w *responseCapture) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.written {
		w.statusCode = code
		w.written = true
	}
}
func (w *responseCapture) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.written {
		w.written = true
		w.statusCode = 200
	}
	return w.body.Write(data)
}
func (w *responseCapture) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, vv := range w.header {
		for _, v := range vv {
			w.original.Header().Add(k, v)
		}
	}
	w.original.WriteHeader(w.statusCode)
	if w.body.Len() > 0 {
		w.original.Write(w.body.Bytes())
	}
}
