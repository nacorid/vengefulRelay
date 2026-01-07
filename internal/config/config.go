package config

import (
	"log"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	PostgresDatabase string   `required:"true" envconfig:"POSTGRESQL_DATABASE"`
	RelayName        string   `default:"Vengeful Relay" envconfig:"RELAY_NAME"`
	RelayPubkey      string   `envconfig:"RELAY_PUBKEY"`
	RelayDescription string   `default:"A simple nostr relay written in go" envconfig:"RELAY_DESCRIPTION"`
	RelayURL         string   `default:"https://relay.vengeful.eu" envconfig:"RELAY_URL"`
	RelayIcon        string   `default:"https://vengeful.eu/favicon.ico" envconfig:"RELAY_ICON"`
	ContactEmail     string   `envconfig:"CONTACT_EMAIL"`
	ListeningAddress string   `default:"0.0.0.0" envconfig:"LISTENING_ADDRESS"`
	Port             string   `default:"7447" envconfig:"PORT"`
	MaxEventLength   int      `default:"100000" envconfig:"MAX_EVENT_LENGTH"`
	Whitelist        []string `envconfig:"WHITELIST"`
	FreeRelay        bool     `default:"false" envconfig:"FREE_RELAY"`

	// Lightning (LNBits/Alby compatible)
	LNBitsURL    string `envconfig:"LNBITS_URL"` // e.g. https://legend.lnbits.com
	LNBitsKey    string `envconfig:"LNBITS_KEY"` // Invoice/Read key
	AdmissionFee int64  `default:"100" envconfig:"ADMISSION_FEE"`

	// x402 / CDP
	CDPAPIKeyName   string `envconfig:"CDP_API_KEY_NAME"`
	CDPAPIKeySecret string `envconfig:"CDP_API_KEY_SECRET"`
	CDPClientKey    string `envconfig:"CDP_CLIENT_KEY"`
	EVMWallet       string `envconfig:"EVM_WALLET"`
	SVMWallet       string `envconfig:"SVM_WALLET"`
}

func Load() Config {
	var c Config
	if err := envconfig.Process("", &c); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	return c
}
