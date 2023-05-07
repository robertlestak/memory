package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/robertlestak/memory/pkg/memory"
	log "github.com/sirupsen/logrus"
)

func init() {
	ll, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
}

func httpGetHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"cmd": "http-get-handler",
	})
	l.Info("Handling HTTP GET request")
	vars := mux.Vars(r)
	var resp []byte
	err := memory.Get(vars["key"], &resp)
	if err != nil {
		l.WithError(err).Error("Failed to get key")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func httpPutHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"cmd": "http-put-handler",
	})
	l.Info("Handling HTTP PUT request")
	defer r.Body.Close()
	jd, err := io.ReadAll(r.Body)
	if err != nil {
		l.WithError(err).Error("Failed to read request body")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	if err := memory.Set(vars["key"], jd); err != nil {
		l.WithError(err).Error("Failed to set key")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func httpDelHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"cmd": "http-del-handler",
	})
	l.Info("Handling HTTP DEL request")
	vars := mux.Vars(r)
	if err := memory.Delete(vars["key"]); err != nil {
		l.WithError(err).Error("Failed to delete key")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func httpServer(port int, tlsCa, tlsCert, tlsKey string, tlsClientAuth bool) error {
	l := log.WithFields(log.Fields{
		"cmd": "http-server",
	})
	l.Info("Starting HTTP server")
	r := mux.NewRouter()
	r.HandleFunc("/{key}", httpGetHandler).Methods("GET")
	r.HandleFunc("/{key}", httpPutHandler).Methods("PUT")
	r.HandleFunc("/{key}", httpDelHandler).Methods("DELETE")
	tlsConfig := &tls.Config{}
	if tlsClientAuth {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if tlsCa != "" {
		caCert, err := os.ReadFile(tlsCa)
		if err != nil {
			l.WithError(err).Fatal("Failed to read TLS CA certificate")
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
	}
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: tlsConfig,
		Handler:   r,
	}
	if err := server.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
		l.WithError(err).Fatal("Failed to start HTTP server")
		return err
	}
	return nil
}

func server() {
	l := log.WithFields(log.Fields{
		"cmd": "server",
	})
	l.Info("Starting server")
	serverFlags := flag.NewFlagSet("server", flag.ExitOnError)
	httpPort := serverFlags.Int("http-port", 6942, "HTTP port")
	tlsCa := serverFlags.String("tls-ca", "", "TLS CA certificate")
	tlsCert := serverFlags.String("tls-cert", "", "TLS certificate")
	tlsKey := serverFlags.String("tls-key", "", "TLS key")
	tlsClientAuth := serverFlags.Bool("tls-client-auth", false, "TLS client authentication")
	generateKey := serverFlags.Bool("generate-key", false, "Generate key")
	keyFile := serverFlags.String("key", "", "Key file")
	disableEncryption := serverFlags.Bool("disable-encryption", false, "Disable encryption")
	rmKeyFile := serverFlags.Bool("rm-key-file", false, "Remove key file once loaded")
	backend := serverFlags.String("backend", "memory", "Backend type")
	backendConfig := serverFlags.String("backend-config", "", "Backend configuration JSON")
	serverFlags.Parse(os.Args[2:])
	l.WithFields(log.Fields{
		"http-port":       *httpPort,
		"tls-ca":          *tlsCa,
		"tls-cert":        *tlsCert,
		"tls-key":         *tlsKey,
		"tls-client-auth": *tlsClientAuth,
	}).Info("Starting server")
	if *tlsCert == "" || *tlsKey == "" {
		l.Fatal("TLS certificate and key are required")
	}
	var key *rsa.PrivateKey
	var err error
	if *generateKey {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
	} else if !*disableEncryption {
		key, err = memory.ReadKey(keyFile, *rmKeyFile)
		if err != nil {
			log.Fatal(err)
		}
	}
	var cfg map[string]any
	if *backendConfig != "" {
		*backendConfig = os.ExpandEnv(*backendConfig)
		if err := json.Unmarshal([]byte(*backendConfig), &cfg); err != nil {
			log.Fatal(err)
		}
	}
	if err := memory.New(memory.BackendType(*backend), cfg, key); err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := httpServer(*httpPort, *tlsCa, *tlsCert, *tlsKey, *tlsClientAuth); err != nil {
			l.WithError(err).Fatal("Failed to start HTTP server")
		}
	}()
	select {}
}

func main() {
	memoryFlags := flag.NewFlagSet("memory", flag.ExitOnError)
	logLevel := memoryFlags.String("log-level", log.GetLevel().String(), "Log level")
	memoryFlags.Parse(os.Args[1:])
	ll, err := log.ParseLevel(*logLevel)
	if err != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
	var cmd string
	if len(memoryFlags.Args()) > 0 {
		cmd = memoryFlags.Args()[0]
	}
	switch cmd {
	case "server":
		server()
	default:
		log.Fatal("Unknown command")
	}
}
