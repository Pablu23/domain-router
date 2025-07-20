package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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

	router := domainrouter.New(config, client)
	mux := http.NewServeMux()
	mux.HandleFunc("/", router.Route)

	if config.General.AnnouncePublic {
		h, err := url.JoinPath("/", config.General.HealthEndpoint)
		if err != nil {
			log.Error().Err(err).Str("endpoint", config.General.HealthEndpoint).Msg("Could not create endpoint path")
			h = "/healthz"
		}
		mux.HandleFunc(h, router.Healthz)
	}

	pipeline := configureMiddleware(config)

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", config.Server.Port),
		Handler: pipeline(mux),
	}

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
			err := acme.SetupAcme(config)
			if err != nil {
				log.Fatal().Err(err).Msg("unable to setup acme")
			}
		}

		log.Info().Int("port", config.Server.Port).Str("cert", config.Server.Ssl.CertFile).Str("key", config.Server.Ssl.KeyFile).Msg("Starting server")
		err := server.ListenAndServeTLS("", "")
		log.Fatal().Err(err).Str("cert", config.Server.Ssl.CertFile).Str("key", config.Server.Ssl.KeyFile).Int("port", config.Server.Port).Msg("Could not start server")
	} else {
		log.Info().Int("port", config.Server.Port).Msg("Starting server")
		err := server.ListenAndServe()
		log.Fatal().Err(err).Int("port", config.Server.Port).Msg("Could not start server")
	}
}

func configureMiddleware(config *domainrouter.Config) middleware.Middleware {
	middlewares := make([]middleware.Middleware, 0)

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
		limiter.Start()
		middlewares = append(middlewares, limiter.RateLimiter)
	}

	if config.Logging.Requests {
		middlewares = append(middlewares, middleware.RequestLogger)
	}

	pipeline := middleware.Pipeline(middlewares...)
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
