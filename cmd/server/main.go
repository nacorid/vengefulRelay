package main

import (
	"log"
	"log/slog"
	"net/http"

	"git.vengeful.eu/nacorid/vengefulRelay/internal/config"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/lightning"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/payments"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/relay"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/store"
	"git.vengeful.eu/nacorid/vengefulRelay/internal/web"

	"github.com/joho/godotenv"
	logn "github.com/nacorid/logger"
)

func main() {
	godotenv.Load()

	cfg := config.Load()
	cfg.Whitelist = append(cfg.Whitelist, cfg.RelayPubkey)

	db, err := store.Init(cfg.PostgresDatabase)
	if err != nil {
		log.Fatalf("db init error: %v", err)
	}

	consoleLvl, err := logn.ParseLevel(cfg.ConsoleLogLvl)
	fileLvl, err := logn.ParseLevel(cfg.FileLogLvl)
	err = logn.Init(logn.Config{LogFilePath: cfg.LogFilePath, ConsoleLevel: consoleLvl, FileLevel: fileLvl})
	if err != nil {
		log.Printf("logger init error: %v", err)
	}
	logger := slog.Default().With("component", "relay")

	lnProvider := lightning.NewProvider("", cfg.OpennodeApiKey)

	khatruRelay := relay.New(cfg, db, lnProvider, logger)

	webHandler := &web.Server{
		Config:     cfg,
		Store:      db,
		LNProvider: lnProvider,
		Logger:     logger,
	}

	mux := khatruRelay.Router()

	mux.HandleFunc("/", webHandler.HandleWebpage)
	mux.HandleFunc("/healthz", webHandler.HandleHealthz)
	mux.HandleFunc("/invoice", webHandler.HandleInvoice)
	mux.HandleFunc("/check", webHandler.HandleCheck)
	mux.HandleFunc("/opennode/callback", webHandler.HandleOpennodeCallback)
	mux.HandleFunc("/opennode/zaps", webHandler.HandleOpennodeZaps)

	if cfg.CDPAPIKeyName != "" && cfg.CDPAPIKeySecret != "" {
		x402Middleware := payments.SetupMiddleware(cfg, db)

		finalHandler := http.HandlerFunc(webHandler.HandleAdmission)
		mux.Handle("/admission", x402Middleware(finalHandler))
	} else {
		mux.HandleFunc("/admission", webHandler.HandleAdmission)
	}

	slog.Info("relay running", "port", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, khatruRelay); err != nil {
		log.Fatal(err)
	}
}
