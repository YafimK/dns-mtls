package dns_mtls_forwarder

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	bindHost := flag.String("b", ":53", "binding address for dns mtls forwarder")
	serverCaCertPath := flag.String("ca", "./certs/server.crt", "path to server root ca cert")
	clientCert := flag.String("crt", "./certs/client.crt", "path to client cert (signed by server ca)")
	clientKey := flag.String("key", "./certs/client.key", "path to client key")
	upstreamDnsServer := flag.String("u", "8.8.8.8:853", "upstream dns server <host>:<port>") //TOOD: enable taking list from file
	upstreamHostName := flag.String("h", "demo.site", "upstream dns server name")                //TOOD: enable taking list from file

	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	caPath, err := filepath.Abs(*serverCaCertPath)
	if err != nil {
		log.Fatal(err)
	}
	certPath, err := filepath.Abs(*clientCert)
	if err != nil {
		log.Fatal(err)
	}
	keyPath, err := filepath.Abs(*clientKey)
	if err != nil {
		log.Fatal(err)
	}
	forwarder, err := NewDNSForwarder(caPath, certPath, keyPath, *upstreamDnsServer, *upstreamHostName)
	if err != nil {
		log.Fatal(err)
	}
	dns.HandleFunc(*bindHost, forwarder.ServeDNS)

	go serve(*bindHost)
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}

func serve(bindAddress string) {
	server := &dns.Server{Addr: bindAddress, Net: "tcp-tls", TsigSecret: nil, ReusePort: false}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to setup the server on %v due to: %s\n", err.Error())
	}
}

type Forwarder struct {
	certPool          *x509.CertPool
	certs             []tls.Certificate
	upstreamDnsServer string
	client            *dns.Client
}

func NewDNSForwarder(caCertPath, clientCertPath, clientKeyPath, upstreamServer string, upstreamHostName string) (*Forwarder, error) {
	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to build certificate: %v", err)
	}
	clientCACert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Fatal("Unable to open cert", err)
	}

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	dnsClient := &dns.Client{}

	dnsClient.Net = "tcp-tls"
	dnsClient.TLSConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: false,
		ServerName:         upstreamHostName,
		RootCAs:            clientCertPool,
	}
	return &Forwarder{
		certPool:          clientCertPool,
		certs:             []tls.Certificate{cert},
		upstreamDnsServer: upstreamServer,
		client:            dnsClient,
	}, nil
}

func (f Forwarder) ServeDNS(w dns.ResponseWriter, ir *dns.Msg) {

	r, rtt, err := f.client.Exchange(ir, f.upstreamDnsServer)
	if err == nil && r == nil {
		err = fmt.Errorf("recieved nil response")
	}
	if  err == nil && r.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf("failed to get an valid answer %+v\n", r)
	}
	if err != nil {
		log.Fatalf("failed to exchange: %v", err)
	}
	log.Printf("Got forwarded response request in [%v] with result: %+v\n", rtt, r)
}

