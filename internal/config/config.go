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
	MinPowDifficulty int      `default:"0" envconfig:"PROOF_OF_WORK_DIFFICULTY"`
	ContactEmail     string   `envconfig:"CONTACT_EMAIL"`
	ListeningAddress string   `default:"0.0.0.0" envconfig:"LISTENING_ADDRESS"`
	Port             string   `default:"7447" envconfig:"PORT"`
	MaxEventLength   int      `default:"100000" envconfig:"MAX_EVENT_LENGTH"`
	Whitelist        []string `envconfig:"WHITELIST"`
	FreeRelay        bool     `default:"false" envconfig:"FREE_RELAY"`
	Debug            bool     `default:"false" envconfig:"DEBUG"`
	LogFilePath      string   `default:"output.log" envconfig:"LOG_FILE_PATH"`
	ConsoleLogLvl    string   `default:"info" envconfig:"CONSOLE_LOG_LEVEL"`
	FileLogLvl       string   `default:"trace" envconfig:"FILE_LOG_LEVEL"`

	// Lightning
	OpennodeApiKey string `envconfig:"OPENNODE_API_KEY"`
	AdmissionFee   int64  `default:"100" envconfig:"ADMISSION_FEE"`

	// x402 / CDP
	CDPAPIKeyName   string `envconfig:"CDP_API_KEY_NAME"`
	CDPAPIKeySecret string `envconfig:"CDP_API_KEY_SECRET"`
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
