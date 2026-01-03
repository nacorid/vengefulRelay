package main

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

// ============================================================================
// Standard HTTP Adapter Implementation
// ============================================================================

// StdAdapter implements HTTPAdapter for the standard net/http library
type StdAdapter struct {
	req *http.Request
}

// NewStdAdapter creates a new standard HTTP adapter
func NewStdAdapter(req *http.Request) *StdAdapter {
	return &StdAdapter{req: req}
}

// GetHeader gets a request header
func (a *StdAdapter) GetHeader(name string) string {
	return a.req.Header.Get(name)
}

// GetMethod gets the HTTP method
func (a *StdAdapter) GetMethod() string {
	return a.req.Method
}

// GetPath gets the request path
func (a *StdAdapter) GetPath() string {
	return a.req.URL.Path
}

// GetURL gets the full request URL
func (a *StdAdapter) GetURL() string {
	scheme := "http"
	if a.req.TLS != nil {
		scheme = "https"
	}
	// Handle X-Forwarded-Proto if behind a proxy
	if proto := a.req.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}

	host := a.req.Host
	if host == "" {
		host = a.req.Header.Get("Host")
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, a.req.URL.Path)
}

// GetAcceptHeader gets the Accept header
func (a *StdAdapter) GetAcceptHeader() string {
	return a.req.Header.Get("Accept")
}

// GetUserAgent gets the User-Agent header
func (a *StdAdapter) GetUserAgent() string {
	return a.req.Header.Get("User-Agent")
}

// ============================================================================
// Middleware Configuration
// ============================================================================

// MiddlewareConfig configures the payment middleware
type MiddlewareConfig struct {
	// Routes configuration
	Routes x402http.RoutesConfig

	// Facilitator client(s)
	FacilitatorClients []x402.FacilitatorClient

	// Scheme registrations
	Schemes []SchemeRegistration

	// Paywall configuration
	PaywallConfig *x402http.PaywallConfig

	// Sync with facilitator on start
	SyncFacilitatorOnStart bool

	// Custom error handler (updated signature for net/http)
	ErrorHandler func(http.ResponseWriter, *http.Request, error)

	// Custom settlement handler (updated signature for net/http)
	SettlementHandler func(http.ResponseWriter, *http.Request, *x402.SettleResponse)

	// Context timeout for payment operations
	Timeout time.Duration

	Logger *slog.Logger
}

// SchemeRegistration registers a scheme with the server
type SchemeRegistration struct {
	Network x402.Network
	Server  x402.SchemeNetworkServer
}

// MiddlewareOption configures the middleware
type MiddlewareOption func(*MiddlewareConfig)

// WithFacilitatorClient adds a facilitator client
func WithFacilitatorClient(client x402.FacilitatorClient) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.FacilitatorClients = append(c.FacilitatorClients, client)
	}
}

// WithScheme registers a scheme server
func WithScheme(network x402.Network, schemeServer x402.SchemeNetworkServer) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.Schemes = append(c.Schemes, SchemeRegistration{
			Network: network,
			Server:  schemeServer,
		})
	}
}

// WithPaywallConfig sets the paywall configuration
func WithPaywallConfig(config *x402http.PaywallConfig) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.PaywallConfig = config
	}
}

// WithSyncFacilitatorOnStart sets whether to sync with facilitator on startup
func WithSyncFacilitatorOnStart(sync bool) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.SyncFacilitatorOnStart = sync
	}
}

// WithErrorHandler sets a custom error handler
func WithErrorHandler(handler func(http.ResponseWriter, *http.Request, error)) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.ErrorHandler = handler
	}
}

// WithSettlementHandler sets a custom settlement handler
func WithSettlementHandler(handler func(http.ResponseWriter, *http.Request, *x402.SettleResponse)) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.SettlementHandler = handler
	}
}

// WithTimeout sets the context timeout for payment operations
func WithTimeout(timeout time.Duration) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.Timeout = timeout
	}
}

// WithLogger sets the logger for the middleware
func WithLogger(logger *slog.Logger) MiddlewareOption {
	return func(c *MiddlewareConfig) {
		c.Logger = logger
	}
}

// ============================================================================
// Payment Middleware
// ============================================================================

// PaymentMiddleware creates standard HTTP middleware for x402 payment handling using a pre-configured server.
// Returns a function that wraps an http.Handler.
func PaymentMiddleware(routes x402http.RoutesConfig, server *x402.X402ResourceServer, opts ...MiddlewareOption) func(http.Handler) http.HandlerFunc {
	config := &MiddlewareConfig{
		Routes:                 routes,
		SyncFacilitatorOnStart: true,
		Timeout:                30 * time.Second,
	}

	// Apply options
	for _, opt := range opts {
		opt(config)
	}

	var logger *slog.Logger
	if config.Logger != nil {
		logger = config.Logger
	} else {
		logger = slog.Default()
	}
	// Wrap the resource server with HTTP functionality
	httpServer := x402http.Wrappedx402HTTPResourceServer(routes, server)

	httpServer.RegisterExtension(bazaar.BazaarResourceServerExtension)

	// Initialize if requested
	if config.SyncFacilitatorOnStart {
		ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
		defer cancel()
		if err := httpServer.Initialize(ctx); err != nil {
			logger.Warn("failed to initialize x402 server", "error", err)
		}
	}

	// Create middleware handler
	return createMiddlewareHandler(httpServer, config)
}

// PaymentMiddlewareFromConfig creates standard HTTP middleware for x402 payment handling.
func PaymentMiddlewareFromConfig(routes x402http.RoutesConfig, opts ...MiddlewareOption) func(http.Handler) http.HandlerFunc {
	config := &MiddlewareConfig{
		Routes:                 routes,
		FacilitatorClients:     []x402.FacilitatorClient{},
		Schemes:                []SchemeRegistration{},
		SyncFacilitatorOnStart: true,
		Timeout:                30 * time.Second,
	}

	// Apply options
	for _, opt := range opts {
		opt(config)
	}

	var logger *slog.Logger
	if config.Logger != nil {
		logger = config.Logger
	} else {
		logger = slog.Default()
	}

	serverOpts := []x402.ResourceServerOption{}
	for _, client := range config.FacilitatorClients {
		serverOpts = append(serverOpts, x402.WithFacilitatorClient(client))
	}

	httpServer := x402http.Newx402HTTPResourceServer(config.Routes, serverOpts...)

	httpServer.RegisterExtension(bazaar.BazaarResourceServerExtension)

	// Register schemes
	for _, scheme := range config.Schemes {
		httpServer.Register(scheme.Network, scheme.Server)
	}

	// Initialize if requested
	if config.SyncFacilitatorOnStart {
		ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
		defer cancel()
		if err := httpServer.Initialize(ctx); err != nil {
			logger.Warn("failed to initialize x402 server", "error", err)
		}
	}

	// Create middleware handler
	return createMiddlewareHandler(httpServer, config)
}

// createMiddlewareHandler creates the actual middleware function.
func createMiddlewareHandler(server *x402http.HTTPServer, config *MiddlewareConfig) func(http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create adapter and request context
			adapter := NewStdAdapter(r)
			reqCtx := x402http.HTTPRequestContext{
				Adapter: adapter,
				Path:    r.URL.Path,
				Method:  r.Method,
			}

			logger := config.Logger
			if logger == nil {
				logger = slog.Default()
			}

			// Check if route requires payment before waiting for initialization
			if !server.RequiresPayment(reqCtx) {
				next.ServeHTTP(w, r)
				return
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), config.Timeout)
			defer cancel()

			// Update request with timeout context
			r = r.WithContext(ctx)

			result := server.ProcessHTTPRequest(ctx, reqCtx, config.PaywallConfig)

			// Debug logging for request processing
			logger.DebugContext(ctx, "🔍 Processed HTTP request", "resultType", result.Type, "path", reqCtx.Path, "method", reqCtx.Method)

			// Handle result
			switch result.Type {
			case x402http.ResultNoPaymentRequired:
				// No payment required, continue to next handler
				next.ServeHTTP(w, r)

			case x402http.ResultPaymentError:
				// Payment required but not provided or invalid
				handlePaymentError(w, r, result.Response, config)

			case x402http.ResultPaymentVerified:
				// Payment verified, continue with settlement handling
				handlePaymentVerified(w, r, next, server, ctx, result, config)
			}
		})
	}
}

// handlePaymentError handles payment error responses
func handlePaymentError(w http.ResponseWriter, r *http.Request, response *x402http.HTTPResponseInstructions, _ *MiddlewareConfig) {
	// Set headers
	for key, value := range response.Headers {
		w.Header().Set(key, value)
	}

	w.WriteHeader(response.Status)

	// Send response body
	if response.IsHTML {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(response.Body.(string)))
	} else {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response.Body)
	}
}

// handlePaymentVerified handles verified payments with settlement
func handlePaymentVerified(w http.ResponseWriter, r *http.Request, next http.Handler, server *x402http.HTTPServer, ctx context.Context, result x402http.HTTPProcessResult, config *MiddlewareConfig) {
	// Capture response for settlement
	rec := newResponseCapture(w)

	// Continue to protected handler using the recorder
	next.ServeHTTP(rec, r)

	// Don't settle if response failed (>= 400)
	if rec.statusCode >= 400 {
		rec.flush() // Flush captured response immediately
		return
	}

	var logger *slog.Logger
	if config.Logger != nil {
		logger = config.Logger
	} else {
		logger = slog.Default()
	}

	// Debug logging for settlement
	logger.DebugContext(ctx, "🔍 Starting settlement process", "statusCode", rec.statusCode, "contextError", ctx.Err(),
		"paymentPayload", result.PaymentPayload, "paymentRequirements", result.PaymentRequirements)

	// Process settlement
	settleResult := server.ProcessSettlement(
		ctx,
		*result.PaymentPayload,
		*result.PaymentRequirements,
	)

	logger.DebugContext(ctx, "🔍 Settlement completed", "success", settleResult.Success, "errorReason", settleResult.ErrorReason)

	// Check settlement success
	if !settleResult.Success {
		// Discard the captured success response and send 402/Error
		errorReason := settleResult.ErrorReason
		if errorReason == "" {
			errorReason = "Settlement failed"
		}
		if config.ErrorHandler != nil {
			config.ErrorHandler(w, r, fmt.Errorf("settlement failed: %s", errorReason))
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "Settlement failed",
				"details": errorReason,
			})
		}
		return
	}

	// Add settlement headers to the REAL ResponseWriter (w), not the recorder
	// (Though typically we might want to merge them into the recorder if they modify existing ones,
	// but settlement headers are usually additive X-headers).
	for key, value := range settleResult.Headers {
		rec.Header().Set(key, value)
	}

	// Call settlement handler if configured
	if config.SettlementHandler != nil {
		settleResponse := &x402.SettleResponse{
			Success:     true,
			Transaction: settleResult.Transaction,
			Network:     settleResult.Network,
			Payer:       settleResult.Payer,
		}
		// Pass the underlying writer if the handler needs to do something specific,
		// OR pass the recorder. passing the recorder maintains the buffer.
		// However, handlers usually just log or side-effect.
		config.SettlementHandler(rec, r, settleResponse)
	}

	// Finally, write captured response
	rec.flush()
}

// ============================================================================
// Response Capture
// ============================================================================

// responseCapture captures the response for settlement processing
type responseCapture struct {
	original   http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	header     http.Header
	written    bool
	mu         sync.Mutex
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{
		original:   w,
		body:       &bytes.Buffer{},
		header:     make(http.Header),
		statusCode: http.StatusOK, // Default to 200 if WriteHeader never called
	}
}

// Header returns the header map that will be sent once flushed
func (w *responseCapture) Header() http.Header {
	return w.header
}

// WriteHeader captures the status code
func (w *responseCapture) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.written {
		w.statusCode = code
		w.written = true
	}
}

// Write captures the response body
func (w *responseCapture) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// If Write is called before WriteHeader, standard lib implies 200 OK
	if !w.written {
		w.written = true
		w.statusCode = http.StatusOK
	}
	return w.body.Write(data)
}

// flush writes the captured data to the original response writer
func (w *responseCapture) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Copy headers
	originalHeaders := w.original.Header()
	for k, vv := range w.header {
		for _, v := range vv {
			originalHeaders.Add(k, v)
		}
	}

	// Write status code
	w.original.WriteHeader(w.statusCode)

	// Write body
	if w.body.Len() > 0 {
		_, _ = w.original.Write(w.body.Bytes())
	}
}
