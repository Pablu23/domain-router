package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"

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

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		port, ok := domains[r.Host]
		if !ok {
			w.WriteHeader(http.StatusOK)
			return
		}

		if !dumpRequest(w, r) {
			return
		}

		subUrlPath := r.URL.RequestURI()
		req, err := http.NewRequest(r.Method, fmt.Sprintf("http://localhost:%d%s", port, subUrlPath), r.Body)
		if err != nil {
			log.Error().Err(err).Str("path", subUrlPath).Int("port", port).Msg("Could not create request")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		for name, values := range r.Header {
			for _, value := range values {
				req.Header.Set(name, value)
			}
		}

		for _, cookie := range r.Cookies() {
			req.AddCookie(cookie)
		}

		if !dumpRequest(w, req) {
			return
		}

		res, err := client.Do(req)
		if err != nil {
			log.Error().Err(err).Str("path", subUrlPath).Int("port", port).Msg("Could not complete request")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		cookies := res.Cookies()
		for _, cookie := range cookies {
			// fmt.Printf("Setting cookie, Name: %s, Value: %s\n", cookie.Name, cookie.Value)
			http.SetCookie(w, cookie)
		}

		if !dumpResponse(w, res) {
			return
		}

		if loc, err := res.Location(); !errors.Is(err, http.ErrNoLocation) {
			http.Redirect(w, r, loc.RequestURI(), http.StatusFound)
		} else {
			for name, values := range res.Header {
				for _, value := range values {
					w.Header().Set(name, value)
				}
			}
			w.WriteHeader(res.StatusCode)

			body, err := io.ReadAll(res.Body)
			defer res.Body.Close()
			if err != nil {
				log.Error().Err(err).Msg("Could not read body")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			_, err = w.Write(body)
			if err != nil {
				log.Error().Err(err).Msg("Could not write body")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
	})

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", *portFlag),
		Handler: RequestLogger(mux),
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

func dumpRequest(w http.ResponseWriter, r *http.Request) bool {
	if e := log.Debug(); e.Enabled() && r.Method == "POST" {
		rDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Error().Err(err).Msg("Could not dump request")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		log.Debug().Str("dump", string(rDump)).Send()
	}
	return true
}

func dumpResponse(w http.ResponseWriter, r *http.Response) bool {
	if e := log.Debug(); e.Enabled() {
		dump, err := httputil.DumpResponse(r, true)
		if err != nil {
			log.Error().Err(err).Msg("Could not dump response")
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		log.Debug().Str("dump", string(dump)).Send()
	}
	return true
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
