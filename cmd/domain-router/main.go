package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	domainrouter "github.com/pablu23/domain-router"
	"github.com/pablu23/domain-router/acme"
	"github.com/pablu23/domain-router/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

var (
	configFileFlag = flag.String("config", "config.yaml", "Path to config file")
)

func main() {
	flag.Parse()

	config, err := loadConfig(*configFileFlag)
	if err != nil {
		log.Fatal().Err(err).Str("path", *configFileFlag).Msg("Could not load Config")
	}

	setupLogging(config)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	router := domainrouter.New(config, client)
	mux := http.NewServeMux()
	mux.HandleFunc("/", router.ServeHTTP)

	pipeline := configureMiddleware(config)

	pipeline.Manage()
	server := http.Server{
		Addr: fmt.Sprintf(":%d", config.Server.Port),
		// this is rather bad looking
		Handler: pipeline.Use()(mux),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-sigs
		log.Info().Msg("Stopping server")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		server.Shutdown(ctx)
		log.Info().Msg("Http Server stopped")
		log.Info().Msg("Stopping pipeline")
		pipeline.Stop(ctx)
		log.Info().Msg("Pipeline stopped")
	}()

	if config.Server.Ssl.Enabled {
		server.TLSConfig = &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair(config.Server.Ssl.CertFile, config.Server.Ssl.KeyFile)
				if err != nil {
					return nil, err
				}
				return &cert, err
			},
		}

		if config.Server.Ssl.Acme.Enabled {
			acmeRenewer, err := acme.SetupAcme(config)
			if err != nil {
				log.Fatal().Err(err).Msg("unable to setup acme")
			}

			go func() {
				acmeRenewer.RegisterTicker()
			}()
		}
		log.Info().Int("port", config.Server.Port).Str("cert", config.Server.Ssl.CertFile).Str("key", config.Server.Ssl.KeyFile).Msg("Starting server")
		err := server.ListenAndServeTLS("", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Str("cert", config.Server.Ssl.CertFile).Str("key", config.Server.Ssl.KeyFile).Int("port", config.Server.Port).Msg("Could not start server")
		}
	} else {
		log.Info().Int("port", config.Server.Port).Msg("Starting server")
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Int("port", config.Server.Port).Msg("Could not start server")
		}
	}

	wg.Wait()
	log.Info().Msg("Server shutdown completly, have a nice day")
}

func configureMiddleware(config *domainrouter.Config) *middleware.Pipeline {
	pipeline := middleware.NewPipeline()

	if config.RateLimit.Enabled {
		refillTicker, err := time.ParseDuration(config.RateLimit.RefillTicker)
		if err != nil {
			log.Fatal().Err(err).Str("refill", config.RateLimit.RefillTicker).Msg("Could not parse refill Ticker")
		}

		cleanupTicker, err := time.ParseDuration(config.RateLimit.CleanupTicker)
		if err != nil {
			log.Fatal().Err(err).Str("cleanup", config.RateLimit.CleanupTicker).Msg("Could not parse cleanup Ticker")
		}
		limiter := middleware.NewLimiter(config.RateLimit.BucketSize, config.RateLimit.BucketRefill, refillTicker, cleanupTicker)
		pipeline.AddMiddleware(limiter)
	}

	if config.Logging.Requests {
		pipeline.AddMiddleware(&middleware.RequestLogger{})
	}

	if config.Metrics.Enabled {
		flushInterval, err := time.ParseDuration(config.Metrics.FlushInterval)
		if err != nil {
			log.Fatal().Err(err).Str("flush_interval", config.Metrics.FlushInterval).Msg("Could not parse FlushInterval")
		}
		metrics := middleware.NewMetrics(config.Metrics.BufferSize, flushInterval, config.Metrics.File)
		pipeline.AddMiddleware(metrics)
	}

	return pipeline
}

func setupLogging(config *domainrouter.Config) {
	logLevel, err := zerolog.ParseLevel(config.Logging.Level)
	if err != nil {
		log.Fatal().Err(err).Str("level", config.Logging.Level).Msg("Could not parse string to level")
	}

	zerolog.SetGlobalLevel(logLevel)
	log.Info().Str("level", config.Logging.Level).Msg("Set logging level")
	if config.Logging.Pretty {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	if config.Logging.File.Enabled {
		var console io.Writer = os.Stderr
		if config.Logging.Pretty {
			console = zerolog.ConsoleWriter{Out: os.Stderr}
		}

		log.Logger = log.Output(zerolog.MultiLevelWriter(console, &lumberjack.Logger{
			Filename:   config.Logging.File.Path,
			MaxAge:     config.Logging.File.MaxAge,
			MaxBackups: config.Logging.File.MaxBackups,
		}))
	}
}

func loadConfig(path string) (*domainrouter.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg domainrouter.Config
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, err
}
