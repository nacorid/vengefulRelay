package payments

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"git.vengeful.eu/nacorid/vengefulRelay/internal/config"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"

	x402 "github.com/coinbase/x402/go"
	x402http "github.com/coinbase/x402/go/http"
	evm "github.com/coinbase/x402/go/mechanisms/evm/exact/server"
	svm "github.com/coinbase/x402/go/mechanisms/svm/exact/server"
	"github.com/mark3labs/x402-go/signers/coinbase"
)

// ... (Auth struct remains the same as previous) ...
type auth struct {
	coinbaseSigner *coinbase.CDPAuth
}

func (a *auth) GetAuthHeaders(ctx context.Context) (x402http.AuthHeaders, error) {
	verify, _ := a.coinbaseSigner.GenerateBearerToken("POST", "/platform/v2/x402/verify")
	settle, _ := a.coinbaseSigner.GenerateBearerToken("POST", "/platform/v2/x402/settle")
	supported, _ := a.coinbaseSigner.GenerateBearerToken("GET", "/platform/v2/x402/supported")
	return x402http.AuthHeaders{
		Verify:    map[string]string{"Authorization": "Bearer " + verify},
		Settle:    map[string]string{"Authorization": "Bearer " + settle},
		Supported: map[string]string{"Authorization": "Bearer " + supported},
	}, nil
}

func SetupMiddleware(cfg config.Config, st *store.Storage) func(http.Handler) http.HandlerFunc {
	// ... (Network definitions remain the same) ...
	evmNetwork := x402.Network("eip155:8453")
	svmNetwork := x402.Network("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")

	cdpAuth, err := coinbase.NewCDPAuth(cfg.CDPAPIKeyName, cfg.CDPAPIKeySecret, "")
	if err != nil {
		slog.Error("failed to create CDP auth", "error", err)
		os.Exit(1)
	}

	client := x402http.NewHTTPFacilitatorClient(&x402http.FacilitatorConfig{
		URL:          "https://api.cdp.coinbase.com/platform/v2/x402",
		AuthProvider: &auth{coinbaseSigner: cdpAuth},
	})

	// Define Configuration Object for our custom middleware
	mwConfig := MiddlewareConfig{
		Routes: x402http.RoutesConfig{
			"GET /admission": {
				Accepts: x402http.PaymentOptions{
					{Scheme: "exact", Price: "$0.50", Network: evmNetwork, PayTo: cfg.EVMWallet},
					{Scheme: "exact", Price: "$0.50", Network: svmNetwork, PayTo: cfg.SVMWallet},
				},
				Resource:    fmt.Sprintf("%s Admission", cfg.RelayName),
				Description: "Pay to register your nostr key",
				//CustomPaywallHTML: customPaywallHTML,
			},
		},
		FacilitatorClients: []x402.FacilitatorClient{client},
		Schemes: []SchemeRegistration{
			{Network: evmNetwork, Server: evm.NewExactEvmScheme()},
			{Network: svmNetwork, Server: svm.NewExactSvmScheme()},
		},
		PaywallConfig: &x402http.PaywallConfig{
			//CDPClientKey: cfg.CDPClientKey,
			AppName:    cfg.RelayName,
			AppLogo:    cfg.RelayIcon,
			CurrentURL: cfg.RelayURL + "/admission",
			Testnet:    false,
		},
		SettlementHandler: func(w http.ResponseWriter, r *http.Request, s *x402.SettleResponse) {
			handleSettlement(w, r, s, st)
		},
	}

	return PaymentMiddlewareFromConfig(mwConfig.Routes, mwConfig)
}

func handleSettlement(w http.ResponseWriter, r *http.Request, s *x402.SettleResponse, st *store.Storage) {
	pubkey := r.URL.Query().Get("pubkey")
	if pubkey == "" {
		return
	}
	signature := r.Header.Get("PAYMENT-SIGNATURE")
	bytes, _ := base64.StdEncoding.DecodeString(signature)
	var payload struct{ Accepted x402.PaymentRequirements }
	_ = json.Unmarshal(bytes, &payload)
	st.RegisterPayment(pubkey, s.Transaction, payload.Accepted.Asset, payload.Accepted.Amount, string(s.Network), s.Payer, "0")
}
