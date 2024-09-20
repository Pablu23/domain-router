package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	domainrouter "github.com/pablu23/domain-router"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	configFileFlag = flag.String("config", "domains.conf", "Path to Domain config file")
	certFlag       = flag.String("cert", "", "Path to cert file")
	keyFlag        = flag.String("key", "", "Path to key file")
	portFlag       = flag.Int("port", 80, "Port")
	prettyLogsFlag = flag.Bool("pretty", false, "Pretty print? Default is json")
	logPathFlag    = flag.String("log", "", "Path to logfile, default is stderr")
	logLevelFlag   = flag.String("log-level", "info", "Log Level")
)

func main() {
	flag.Parse()

	setupLogging()

	domains, err := loadConfig(*configFileFlag)
	if err != nil {
		log.Fatal().Err(err).Str("path", *configFileFlag).Msg("Could not load Config")
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	router := domainrouter.New(domains, client)
	mux := http.NewServeMux()
	mux.HandleFunc("/", router.Route)

	limiter := domainrouter.NewLimiter(3, 250, 1*time.Minute)
	limiter.Start()

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", *portFlag),
		Handler: limiter.RateLimiter(domainrouter.RequestLogger(mux)),
	}

	if *certFlag != "" && *keyFlag != "" {
		server.TLSConfig = &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair(*certFlag, *keyFlag)
				if err != nil {
					return nil, err
				}
				return &cert, err
			},
		}

		log.Info().Int("port", *portFlag).Str("cert", *certFlag).Str("key", *keyFlag).Msg("Starting server")
		err := server.ListenAndServeTLS("", "")
		log.Fatal().Err(err).Str("cert", *certFlag).Str("key", *keyFlag).Int("port", *portFlag).Msg("Could not start server")
	} else {
		log.Info().Int("port", *portFlag).Msg("Starting server")
		err := server.ListenAndServe()
		log.Fatal().Err(err).Int("port", *portFlag).Msg("Could not start server")
	}
}

func setupLogging() {
	logLevel, err := zerolog.ParseLevel(*logLevelFlag)
	if err != nil {
		log.Fatal().Err(err).Str("level", *logLevelFlag).Msg("Could not parse string to level")
	}

	zerolog.SetGlobalLevel(logLevel)
	if *prettyLogsFlag {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	if *logPathFlag != "" {
		var console io.Writer = os.Stderr
		if *prettyLogsFlag {
			console = zerolog.ConsoleWriter{Out: os.Stderr}
		}
		log.Logger = log.Output(zerolog.MultiLevelWriter(console, &lumberjack.Logger{
			Filename:   *logPathFlag,
			MaxAge:     14,
			MaxBackups: 10,
		}))
	}
}

func loadConfig(path string) (map[string]int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	m := make(map[string]int)
	for scanner.Scan() {
		line := scanner.Text()
		params := strings.Split(line, ";")
		if len(params) <= 1 {
			return nil, errors.New("Line does not contain enough Parameters")
		}
		port, err := strconv.Atoi(params[1])
		if err != nil {
			return nil, err
		}
		m[params[0]] = port
	}

	return m, nil
}
