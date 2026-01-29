package lightning

import "net/http"

var _ Provider = (*Opennode)(nil)

type Provider interface {
	GenerateInvoice(amount int64, memo string) (string, string, error)
	CheckPayment(paymentHash string) bool
}

type Opennode struct {
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
