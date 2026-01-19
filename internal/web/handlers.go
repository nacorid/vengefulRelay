package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"git.vengeful.eu/nacorid/vengefulRelay/internal/config"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/lightning"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/utils"
)

type Server struct {
	Config     config.Config
	Store      *store.Storage
	LNProvider *lightning.Provider
	Logger     *slog.Logger
}

type payload struct {
	ID           string `json:"id"`
	CallbackURL  string `json:"callback_url"`
	SuccessURL   string `json:"success_url"`
	Status       string `json:"status"`
	OrderID      string `json:"order_id"`
	Description  string `json:"description"`
	Price        string `json:"price"`
	Fee          string `json:"fee"`
	AutoSettle   string `json:"auto_settle,omitempty"`
	HashedOrder  string `json:"hashed_order"`
	Transactions []struct {
		Address   string `json:"address"`
		CreatedAt string `json:"created_at"`
		SettledAt string `json:"settled_at"`
		TX        string `json:"tx"`
		Status    string `json:"status"`
		Amount    string `json:"amount"`
	} `json:"transactions,omitempty"`
	MissingAmount string `json:"missing_amt,omitempty"`
	OverpaidBy    string `json:"overpaid_by,omitempty"`
}

func (s *Server) HandleWebpage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
<meta charset=utf-8>
<title>%s</title>
<h1>%s</h1>
<p>%s</p>
<p>Ticket Price: %d sats</p>
<form>
  <label>nostr public key: <input name=pubkey /></label>
  <button>Get Invoice</button>
</form>
<p id=message></p>
<a id=link><canvas id=qr /></a>
<code id=invoice></code>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js"></script>
<script>
document.querySelector('form').addEventListener('submit', async ev => {
  ev.preventDefault()
  let res = await (await fetch('/invoice?pubkey=' + ev.target.pubkey.value)).json()
  if (res.bolt11) {
    document.getElementById('invoice').innerHTML = res.bolt11
    document.getElementById('link').href = 'lightning:' + res.bolt11
    new QRious({ element: document.getElementById('qr'), value: res.bolt11.toUpperCase(), size: 300 });
    
    // Poll for payment
    const checkPayment = setInterval(async () => {
        let check = await (await fetch('/check?hash=' + res.hash + '&pubkey=' + ev.target.pubkey.value)).json()
        if (check.paid) {
            clearInterval(checkPayment)
            document.getElementById('message').innerText = "PAID! You can now write to the relay."
            document.getElementById('invoice').style.display = 'none';
        }
    }, 2000);
  } else {
    document.getElementById('message').innerHTML = res.error
  }
})
</script>
<style>body { margin: 10px auto; width: 800px; max-width: 90%%; font-family: sans-serif; }</style>
    `, s.Config.RelayName, s.Config.RelayName, s.Config.RelayDescription, s.Config.AdmissionFee)
}

func (s *Server) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("ok"))
}

func (s *Server) HandleZaps(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if err := r.ParseForm(); err != nil {
		s.Logger.Error("failed to parse form", "error", err)
		return
	}

	var payload payload
	payload.ID = r.FormValue("id")
	payload.Status = r.FormValue("status")
	payload.OrderID = r.FormValue("order_id")
	payload.Description = r.FormValue("description")
	payload.Price = r.FormValue("price")
	payload.Fee = r.FormValue("fee")
	payload.HashedOrder = r.FormValue("hashed_order")

	s.Logger.Info("received zap payload", "id", payload.ID, "status", payload.Status, "order_id", payload.OrderID,
		"description", payload.Description, "price", payload.Price, "fee", payload.Fee, "hashed_order", payload.HashedOrder)

	w.Write([]byte("OK"))
}

func (s *Server) HandleInvoice(w http.ResponseWriter, r *http.Request) {
	pubkey := r.URL.Query().Get("pubkey")
	pubkey = strings.Trim(pubkey, " ")
	var err error
	if strings.HasPrefix(pubkey, "npub") {
		pubkey, err = utils.DecodeNpub(pubkey)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), 400)
			return
		}
	}
	if pubkey == "" {
		http.Error(w, `{"error": "pubkey required"}`, 400)
		return
	}

	if s.Store.IsPubkeyRegistered(pubkey) {
		http.Error(w, `{"error": "already registered"}`, 400)
		return
	}

	bolt11, hash, err := s.LNProvider.GenerateInvoice(s.Config.AdmissionFee, "Admission for "+pubkey)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"bolt11": bolt11,
		"hash":   hash,
	})
}

func (s *Server) HandleCheck(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")

	if s.LNProvider.CheckPayment(hash) {
		json.NewEncoder(w).Encode(map[string]bool{"paid": true})
	} else {
		json.NewEncoder(w).Encode(map[string]bool{"paid": false})
	}
}

func (s *Server) HandleOpenNodeCallback(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if err := r.ParseForm(); err != nil {
		s.Logger.Error("failed to parse form", "error", err)
		return
	}

	var payload payload
	payload.ID = r.FormValue("id")
	payload.Status = r.FormValue("status")
	payload.OrderID = r.FormValue("order_id")
	payload.Description = r.FormValue("description")
	payload.Price = r.FormValue("price")
	payload.Fee = r.FormValue("fee")
	payload.HashedOrder = r.FormValue("hashed_order")

	if payload.Status == "paid" {
		var pubkey string
		fmt.Sscanf(payload.Description, "Admission for %s", &pubkey)
		s.Logger.Info("payment received", "payload", payload)
		s.Store.RegisterPayment(pubkey, payload.HashedOrder, "BTC", payload.Price, "lightning", "opennode", payload.Fee)
	}
}

func (s *Server) HandleAdmission(w http.ResponseWriter, r *http.Request) {
	pubkey := r.URL.Query().Get("pubkey")
	pubkey = strings.Trim(pubkey, " ")
	var err error
	if strings.HasPrefix(pubkey, "npub") {
		pubkey, err = utils.DecodeNpub(pubkey)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), 400)
			return
		}
	}
	if s.Store.IsPubkeyRegistered(pubkey) {
		w.WriteHeader(400)
		w.Write([]byte("already paid"))
	} else if pubkey == "" {
		w.WriteHeader(400)
		w.Write([]byte("pubkey must not be empty"))
	} else {
		w.Write([]byte("OK"))
	}
}
