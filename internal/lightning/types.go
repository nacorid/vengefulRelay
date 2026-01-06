package lightning

import "net/http"

type Provider struct {
	URL    string
	Key    string
	client *http.Client
}

type InvoiceResponse struct {
	PaymentHash    string `json:"payment_hash"`
	PaymentRequest string `json:"payment_request"`
	CheckingID     string `json:"checking_id"`
}

type CheckResponse struct {
	Paid bool `json:"paid"`
}
