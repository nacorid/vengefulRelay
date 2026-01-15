package lightning

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func NewProvider(url, key string) *Provider {
	client := &http.Client{Timeout: 10 * time.Second}
	return &Provider{URL: url, Key: key, client: client}
}

func (p *Provider) GenerateInvoice(amountSats int64, memo string) (string, string, error) {
	body := map[string]any{
		"amount":       amountSats,
		"description":  memo,
		"order_id":     fmt.Sprintf("%s-%d", memo, time.Now().Unix()),
		"callback_url": "",
		"expiry":       3600,
	}
	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", p.URL+"/v1/charges", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", p.Key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", "", fmt.Errorf("opennode returned status %d", resp.StatusCode)
	}

	var res InvoiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", "", err
	}

	return res.PaymentRequest, res.PaymentHash, nil
}

func (p *Provider) CheckPayment(paymentHash string) bool {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/payments/%s", p.URL, paymentHash), nil)
	req.Header.Set("Authorization", p.Key)

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return false
	}

	var res CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false
	}

	return res.Paid
}
