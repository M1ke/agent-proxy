package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// handleConnect terminates the browser's TLS with a certificate minted by our
// own CA, then serves the plaintext requests inside it as an ordinary HTTP
// server. The CA advertises http/1.1 only, so the browser never asks for h2.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Host
	if target == "" {
		target = r.Host
	}

	client, _, err := hijack(w)
	if err != nil {
		http.Error(w, "agent-proxy: cannot hijack CONNECT", http.StatusInternalServerError)
		return
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		return
	}

	cfg := p.CA.TLSConfig()
	// Clients connecting to a bare IP send no SNI, so fall back to the host
	// the CONNECT named.
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := hello.ServerName
		if name == "" {
			name = stripPort(target)
		}
		return p.CA.LeafFor(name)
	}
	tlsConn := tls.Server(client, cfg)
	if err := tlsConn.Handshake(); err != nil {
		client.Close()
		return
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := target
		if r.Host != "" && hasPort(r.Host) {
			host = r.Host
		}
		p.forward(w, r, "https", host)
	})

	srv := &http.Server{Handler: inner, ReadHeaderTimeout: 60 * time.Second}
	// Serve returns once the single connection closes, which keeps this
	// CONNECT handler alive for the life of the tunnel.
	srv.Serve(newOneShotListener(tlsConn))
}

func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errorString("response writer is not hijackable")
	}
	return hj.Hijack()
}

func dial(scheme, host string) (net.Conn, error) {
	if !hasPort(host) {
		if scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	if scheme == "https" {
		return tls.Dial("tcp", host, &tls.Config{ServerName: stripPort(host)})
	}
	return net.Dial("tcp", host)
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(a, b); closeWrite(a) }()
	go func() { defer wg.Done(); io.Copy(b, a); closeWrite(b) }()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

func hasPort(host string) bool {
	_, _, err := net.SplitHostPort(host)
	return err == nil
}

// oneShotListener adapts a single accepted connection into a net.Listener so
// http.Server can drive it. The second Accept blocks until that connection
// closes, so Serve does not return while the tunnel is still live.
type oneShotListener struct {
	conn   *notifyConn
	once   sync.Once
	served bool
}

func newOneShotListener(c net.Conn) *oneShotListener {
	return &oneShotListener{conn: &notifyConn{Conn: c, closed: make(chan struct{})}}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if !l.served {
		l.served = true
		return l.conn, nil
	}
	<-l.conn.closed
	return nil, io.EOF
}

func (l *oneShotListener) Close() error {
	l.once.Do(func() { l.conn.Close() })
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
