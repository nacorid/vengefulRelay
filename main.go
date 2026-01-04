package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"

	x402 "github.com/coinbase/x402/go"
	x402http "github.com/coinbase/x402/go/http"
	evm "github.com/coinbase/x402/go/mechanisms/evm/exact/server"
	svm "github.com/coinbase/x402/go/mechanisms/svm/exact/server"
	"github.com/fiatjaf/eventstore/postgresql"
	"github.com/fiatjaf/relayer/v2"
	"github.com/kelseyhightower/envconfig"
	_ "github.com/lib/pq"
	"github.com/mark3labs/x402-go/signers/coinbase"
)

const CdPFacilitatorURL = "https://api.cdp.coinbase.com/platform/v2/x402"

var _ x402http.AuthProvider = (*auth)(nil)

type auth struct {
	coinbaseSigner *coinbase.CDPAuth
}

func NewAuthProvider(apiKeyName, apiKeySecret string) *auth {
	cdp, err := coinbase.NewCDPAuth(apiKeyName, apiKeySecret, "")
	if err != nil {
		slog.Error("failed to create CDP auth", "error", err)
		os.Exit(1)
	}
	return &auth{
		coinbaseSigner: cdp,
	}
}

func (a *auth) GetAuthHeaders(ctx context.Context) (x402http.AuthHeaders, error) {
	verify, err := a.coinbaseSigner.GenerateBearerToken("POST", "/verify")
	if err != nil {
		slog.Default().WarnContext(ctx, "failed to generate verify auth header", "error", err)
	}
	settle, err := a.coinbaseSigner.GenerateBearerToken("POST", "/settle")
	if err != nil {
		slog.Default().WarnContext(ctx, "failed to generate settle auth header", "error", err)
	}
	supported, err := a.coinbaseSigner.GenerateBearerToken("GET", "/supported")
	if err != nil {
		slog.Default().WarnContext(ctx, "failed to generate supported auth header", "error", err)
	}
	return x402http.AuthHeaders{
		Verify:    map[string]string{"Authorization": "Bearer " + verify},
		Settle:    map[string]string{"Authorization": "Bearer " + settle},
		Supported: map[string]string{"Authorization": "Bearer " + supported},
	}, nil
}

func main() {
	logger := slog.Default()
	r := Relay{}
	if err := envconfig.Process("", &r); err != nil {
		logger.Error("failed to read from env", "error", err)
		os.Exit(1)
	}
	if r.DeleteEventsOlderThan < 0 && r.DeleteOldEvents {
		logger.Error("cannot delete events from the future")
		os.Exit(1)
	}
	if r.MaxEventLength <= 0 {
		logger.Error("cannot accept events with length <= 0")
		os.Exit(1)
	}

	r.storage = &postgresql.PostgresBackend{DatabaseURL: r.PostgresDatabase}
	server, err := relayer.NewServer(&r)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	evmNetwork := x402.Network("eip155:8453")
	svmNetwork := x402.Network("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
	auth := NewAuthProvider(r.CDPAPIKeyName, r.CDPAPIKeySecret)
	x402Facilitator := x402http.NewHTTPFacilitatorClient(&x402http.FacilitatorConfig{URL: CdPFacilitatorURL, AuthProvider: auth})

	routes := x402http.RoutesConfig{
		"GET /admission": {
			Accepts: x402http.PaymentOptions{
				{
					Scheme:  "exact",
					Price:   getUSDCPrice(),
					Network: evmNetwork,
					PayTo:   r.EVMWallet,
				},
				{
					Scheme:  "exact",
					Price:   getUSDCPrice(),
					Network: svmNetwork,
					PayTo:   r.SVMWallet,
				},
			},
			Description: "Pay to register your nostr key with this relay",
		},
	}

	x402pw := &x402http.PaywallConfig{
		CDPClientKey:         r.CDPClientKey,
		AppName:              "Vengeful Relay",
		AppLogo:              "",
		SessionTokenEndpoint: "",
		CurrentURL:           "https://relay.vengeful.eu/admission",
		Testnet:              false,
	}

	x402mw := PaymentMiddlewareFromConfig(routes, WithFacilitatorClient(x402Facilitator),
		WithScheme(evmNetwork, evm.NewExactEvmScheme()), WithScheme(svmNetwork, svm.NewExactSvmScheme()),
		WithPaywallConfig(x402pw), WithSettlementHandler(func(w http.ResponseWriter, rq *http.Request, s *x402.SettleResponse) { saveSettlement(w, rq, s, &r) }))

	x402Handler := X402Handler{Relay: &r}
	// special handlers
	server.Router().HandleFunc("/", handleWebpage)
	server.Router().HandleFunc("/invoice", func(w http.ResponseWriter, rq *http.Request) {
		handleInvoice(w, rq, &r)
	})
	server.Router().HandleFunc("admission", x402mw(&x402Handler))
	if err := server.Start(r.ListeningAddress, r.Port); err != nil {
		logger.Error("server terminated", "error", err)
	}
}

func getUSDCPrice() string {
	return "$0.50"
}

func saveSettlement(w http.ResponseWriter, rq *http.Request, s *x402.SettleResponse, r *Relay) {
	logger := slog.Default()
	signature := rq.Header.Get("PAYMENT-SIGNATURE")
	if signature == "" {
		logger.Error("unexpected state", "error", "successfull settlement response without payment signature")
	}
	pubkey := rq.URL.Query().Get("pubkey")
	requirement := parsePaymentPayload(signature)
	_, _ = r.storage.Exec(
		"INSERT INTO invoices_paid (pubkey, transaction_id, asset, amount, network, payer) VALUES ($1, $2, $3, $4, $5, $6)",
		pubkey,
		s.Transaction,
		requirement.Asset,
		requirement.Amount,
		s.Network,
		s.Payer,
	)
}

func parsePaymentPayload(header string) x402.PaymentRequirements {
	logger := slog.Default()
	bytes, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		logger.Error("failed to decode payment header", "error", err)
	}
	var payload *x402.PaymentPayload
	err = json.Unmarshal(bytes, &payload)
	if err != nil {
		logger.Error("failed to parse payment payload", "error", err)
	}
	return payload.Accepted
}
