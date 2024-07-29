package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ngrox-io/ngrox/internal/conn"
	"github.com/ngrox-io/ngrox/internal/log"
	"github.com/ngrox-io/ngrox/internal/msg"
	"github.com/ngrox-io/ngrox/internal/util"
	"golang.org/x/crypto/sha3"
)

var defaultPortMap = map[string]int{
	"http":  80,
	"https": 443,
	"smtp":  25,
}

/**
 * Tunnel: A control connection, metadata and proxy connections which
 *         route public traffic to a firewalled endpoint.
 */
type Tunnel struct {
	// request that opened the tunnel
	req *msg.ReqTunnel

	// time when the tunnel was opened
	start time.Time

	// public url
	url string

	// tcp listener
	listener *net.TCPListener

	// control connection
	ctl *Control

	// logger
	log.Logger

	// closing
	closing int32
}

type lb_host struct {
	Hostname string
	Weight   int
}

// Common functionality for registering virtually hosted protocols
func registerVhost(t *Tunnel, protocol string, servingPort int) (err error) {
	vhost := os.Getenv("VHOST")
	if vhost == "" {
		vhost = fmt.Sprintf("%s:%d", opts.domain, servingPort)
	}

	// Canonicalize virtual host by removing default port (e.g. :80 on HTTP)
	defaultPort, ok := defaultPortMap[protocol]
	if !ok {
		return fmt.Errorf("Couldn't find default port for protocol %s", protocol)
	}

	defaultPortSuffix := fmt.Sprintf(":%d", defaultPort)
	if strings.HasSuffix(vhost, defaultPortSuffix) {
		vhost = vhost[0 : len(vhost)-len(defaultPortSuffix)]
	}

	// Canonicalize by always using lower-case
	vhost = strings.ToLower(vhost)

	// Register for specific subdomain
	subdomain := strings.ToLower(strings.TrimSpace(t.req.Subdomain))
	t.Warn("sign data %s :", subdomain)
	sign_data, _ := hexutil.Decode(subdomain)
	data := []byte("hello")
	hash := crypto.Keccak256Hash(data)
	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), sign_data)
	if err != nil {
		t.Debug("Failed to get private key: %v", err)
	}
	account := PublicKeyBytesToAddress(sigPublicKey)
	/*
		ck_wallet := IsValidAddress(fromAddress.)
		if !ck_wallet {
			return fmt.Errorf("Subdomain should be lainet wallet")
		}
		client, err := ethclient.Dial("https://rpc-l1.jibchain.net")
		if err != nil {
			t.ctl.conn.Error("Error connect rpc: %v", err)

		}
		account := fromAddress
	*/
	client, err := ethclient.Dial("https://rpc-l1.jibchain.net")
	balance, err := client.BalanceAt(context.Background(), account, nil)
	minBalance := new(big.Float)
	minBalance.SetString("100")
	fbalance := new(big.Float)
	fbalance.SetString(balance.String())
	ethValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))
	result := ethValue.Cmp(minBalance)
	if result < 0 {
		return fmt.Errorf("Balance %s  should be > 100 ", account)
	}

	subdomain = strings.ToLower(account.String())
	t.Debug("Subdomain %s :", subdomain)
	if subdomain != "" {
		t.url = fmt.Sprintf("%s://%s.%s", protocol, subdomain, vhost)
		t.Debug("URL %s :", t.url)
		return tunnelRegistry.Register(t.url, t)
	}

	// Register for specific hostname
	hostname := strings.ToLower(strings.TrimSpace(t.req.Hostname))
	if hostname != "" {
		t.url = fmt.Sprintf("%s://%s", protocol, hostname)
		// t.url = fmt.Sprintf("%s://%x.%s", protocol, rand.Int31(), vhost)
		return tunnelRegistry.Register(t.url, t)
	}

	// Register for random URL
	t.url, err = tunnelRegistry.RegisterRepeat(func() string {
		return fmt.Sprintf("%s://%x.%s", protocol, rand.Int31(), vhost)
	}, t)

	return
}

// Create a new tunnel from a registration message received
// on a control channel
func NewTunnel(m *msg.ReqTunnel, ctl *Control) (t *Tunnel, err error) {
	t = &Tunnel{
		req:    m,
		start:  time.Now(),
		ctl:    ctl,
		Logger: log.NewPrefixLogger(),
	}

	proto := t.req.Protocol
	switch proto {
	case "tcp":
		bindTcp := func(port int) error {
			if t.listener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: port}); err != nil {
				err = t.ctl.conn.Error("Error binding TCP listener: %v", err)
				return err
			}

			// create the url
			addr := t.listener.Addr().(*net.TCPAddr)
			t.url = fmt.Sprintf("tcp://%s:%d", opts.domain, addr.Port)

			// register it
			if err = tunnelRegistry.RegisterAndCache(t.url, t); err != nil {
				// This should never be possible because the OS will
				// only assign available ports to us.
				t.listener.Close()
				err = fmt.Errorf("TCP listener bound, but failed to register %s", t.url)
				return err
			}

			go t.listenTcp(t.listener)
			return nil
		}

		// use the custom remote port you asked for
		if t.req.RemotePort != 0 {
			bindTcp(int(t.req.RemotePort))
			return
		}

		// try to return to you the same port you had before
		cachedUrl := tunnelRegistry.GetCachedRegistration(t)
		if cachedUrl != "" {
			var port int
			parts := strings.Split(cachedUrl, ":")
			portPart := parts[len(parts)-1]
			port, err = strconv.Atoi(portPart)
			if err != nil {
				t.ctl.conn.Error("Failed to parse cached url port as integer: %s", portPart)
			} else {
				// we have a valid, cached port, let's try to bind with it
				if bindTcp(port) != nil {
					t.ctl.conn.Warn("Failed to get custom port %d: %v, trying a random one", port, err)
				} else {
					// success, we're done
					return
				}
			}
		}

		// Bind for TCP connections
		bindTcp(0)
		return

	case "http", "https":
		l, ok := listeners[proto]
		if !ok {
			err = fmt.Errorf("Not listening for %s connections", proto)
			return
		}

		if err = registerVhost(t, proto, l.Addr.(*net.TCPAddr).Port); err != nil {
			return
		}

	default:
		err = fmt.Errorf("Protocol %s is not supported", proto)
		return
	}

	// pre-encode the http basic auth for fast comparisons later
	if m.HttpAuth != "" {
		m.HttpAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(m.HttpAuth))
	}
	// test authen
	// err = fmt.Errorf("TCP listener bound, but failed to register %s", t.url)
	// return

	t.AddLogPrefix(t.Id())
	u, _ := url.Parse(t.url)
	t.Info("Debug url on: %s %s", t.url, u.Hostname()) // dome debug
	lbhost := lb_host{Hostname: u.Hostname(), Weight: 1}
	body, _ := json.Marshal(lbhost)
	response := make(chan *http.Response)
	go SendPostAsync("http://nginx:8081", body, response)
	t.Info("Registered new tunnel on: %s %s", t.ctl.conn.Id(), string(body)) // dome debug

	metrics.OpenTunnel(t)
	return
}

func (t *Tunnel) Shutdown() {

	t.AddLogPrefix(t.Id())
	u, _ := url.Parse(t.url)

	t.Info("Debug url on: %s %s", t.url, u.Hostname()) // dome debug
	lbhost := lb_host{Hostname: u.Hostname(), Weight: 1}
	body, _ := json.Marshal(lbhost)
	response := make(chan *http.Response)
	go SendPostAsync("http://nginx:8081/rm-host", body, response)
	t.Info("Registered new tunnel on: %s %s", t.ctl.conn.Id(), string(body)) // dome debug

	// mark that we're shutting down
	atomic.StoreInt32(&t.closing, 1)

	// if we have a public listener (this is a raw TCP tunnel), shut it down
	if t.listener != nil {
		t.listener.Close()
	}

	// remove ourselves from the tunnel registry
	tunnelRegistry.Del(t.url)

	// let the control connection know we're shutting down
	// currently, only the control connection shuts down tunnels,
	// so it doesn't need to know about it
	// t.ctl.stoptunnel <- t

	metrics.CloseTunnel(t)
}

func (t *Tunnel) Id() string {
	return t.url
}

// Listens for new public tcp connections from the internet.
func (t *Tunnel) listenTcp(listener *net.TCPListener) {
	for {
		defer func() {
			if r := recover(); r != nil {
				log.Warn("listenTcp failed with error %v", r)
			}
		}()

		// accept public connections
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			// not an error, we're shutting down this tunnel
			if atomic.LoadInt32(&t.closing) == 1 {
				return
			}

			t.Error("Failed to accept new TCP connection: %v", err)
			continue
		}

		conn := conn.Wrap(tcpConn, "pub")
		conn.AddLogPrefix(t.Id())
		conn.Info("New connection from %v", conn.RemoteAddr())

		go t.HandlePublicConnection(conn)
	}
}

func (t *Tunnel) HandlePublicConnection(publicConn conn.Conn) {
	defer publicConn.Close()
	defer func() {
		if r := recover(); r != nil {
			publicConn.Warn("HandlePublicConnection failed with error %v", r)
		}
	}()

	startTime := time.Now()
	metrics.OpenConnection(t, publicConn)

	var proxyConn conn.Conn
	var err error
	for i := 0; i < (2 * proxyMaxPoolSize); i++ {
		// get a proxy connection
		if proxyConn, err = t.ctl.GetProxy(); err != nil {
			t.Warn("Failed to get proxy connection: %v", err)
			return
		}
		defer proxyConn.Close()
		t.Info("Got proxy connection %s", proxyConn.Id())
		proxyConn.AddLogPrefix(t.Id())

		// tell the client we're going to start using this proxy connection
		startPxyMsg := &msg.StartProxy{
			Url:        t.url,
			ClientAddr: publicConn.RemoteAddr().String(),
		}

		if err = msg.WriteMsg(proxyConn, startPxyMsg); err != nil {
			proxyConn.Warn("Failed to write StartProxyMessage: %v, attempt %d", err, i)
			proxyConn.Close()
		} else {
			// success
			break
		}
	}

	if err != nil {
		// give up
		publicConn.Error("Too many failures starting proxy connection")
		return
	}

	// To reduce latency handling tunnel connections, we employ the following curde heuristic:
	// Whenever we take a proxy connection from the pool, replace it with a new one
	util.PanicToError(func() { t.ctl.out <- &msg.ReqProxy{} })

	// no timeouts while connections are joined
	proxyConn.SetDeadline(time.Time{})

	// join the public and proxy connections
	bytesIn, bytesOut := conn.Join(publicConn, proxyConn)
	//proxyConn.Read()
	metrics.CloseConnection(t, publicConn, startTime, bytesIn, bytesOut)
}
func SendPostRequest(url string, body []byte) *http.Response {
	response, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		panic(err)
	}

	return response
}
func SendPostAsync(url string, body []byte, rc chan *http.Response) {
	response, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		rc <- nil
	}

	rc <- response
}
func IsValidAddress(v string) bool {
	re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
	return re.MatchString(v)
}
func PublicKeyBytesToAddress(publicKey []byte) common.Address {
	var buf []byte

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKey[1:]) // remove EC prefix 04
	buf = hash.Sum(nil)
	address := buf[12:]

	return common.HexToAddress(hex.EncodeToString(address))
}
