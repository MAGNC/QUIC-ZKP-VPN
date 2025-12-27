package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"QUIC-ZKP-VPN/pkg/auth"
	"QUIC-ZKP-VPN/pkg/config"
	aqcrypto "QUIC-ZKP-VPN/pkg/crypto"
	"QUIC-ZKP-VPN/pkg/tun"

	"github.com/quic-go/quic-go"
)

// Config flags
var (
	configFile = flag.String("config", "", "Path to configuration file")
	authMode   = flag.String("mode", "A", "Authentication Mode: 'A' (Standard PQ mTLS) or 'B' (Anon-ZKP)")
	// addr flag kept for backward compatibility if config not provided, but mostly we use config or default
	addr = flag.String("addr", "0.0.0.0:4242", "Address to listen on")
)

// Global state for routing
var (
	clientsMap = make(map[string]quic.SendStream) // Virtual IP -> Stream
	mapMutex   sync.RWMutex
	tunDev     *tun.Device
)

func main() {
	flag.Parse()

	// 0. Load Configuration
	var cfg *config.Config
	if *configFile != "" {
		var err error
		cfg, err = config.Parse(*configFile)
		if err != nil {
			log.Fatalf("Failed to parse config: %v", err)
		}
		log.Printf("Loaded config: LocalIP=%s, Mask=%s", cfg.LocalIP, cfg.Mask)
	} else {
		// Minimal default or error? Let's just warn and assume user wants to run without TUN for test
		log.Println("No config file provided. TUN interface will NOT be created (Networking disabled).")
	}

	// 1. Setup Network Interface
	if cfg != nil && cfg.LocalIP != "" {
		var err error
		tunDev, err = tun.CreateTUN("", cfg.LocalIP, cfg.RemoteIP, cfg.Mask)
		if err != nil {
			log.Fatalf("Failed to create TUN device: %v", err)
		}

		// Start reading from TUN
		go readTunLoop()
	}

	// 2. Generate Server Identity (ML-DSA)
	log.Println("Generating Server ML-DSA Key...")
	srvSigner, err := aqcrypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Create TLS Certificate (Transport Layer - Ed25519)
	cert, err := generateTransportCert()
	if err != nil {
		log.Fatalf("Failed to generate transport cert: %v", err)
	}

	// 3. Configure TLS based on Mode
	tlsConf := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{"QUIC-ZKP-VPN-v1"},
		MinVersion:       tls.VersionTLS13,
		CipherSuites:     []uint16{tls.TLS_AES_256_GCM_SHA384},
		CurvePreferences: []tls.CurveID{tls.CurveID(0x6399), tls.X25519}, // 0x6399 is X25519Kyber768Draft00
	}

	if *authMode == "A" {
		log.Println("Starting in Mode A: Standard PQ (Mutual TLS - App Layer)")
		tlsConf.ClientAuth = tls.NoClientCert
	} else {
		log.Println("Starting in Mode B: Anon-ZKP (Server Auth Only + ZKP)")
		tlsConf.ClientAuth = tls.NoClientCert
	}

	// 4. Start QUIC Listener
	listenAddr := *addr
	if cfg != nil && cfg.ServerAddr != "" {
		// If config has address? config mostly has 'remote' for client.
		// Server config usually implies binding to all or specific.
		// We'll stick to flag for bind address.
	}

	listener, err := quic.ListenAddr(listenAddr, tlsConf, &quic.Config{
		MaxIdleTimeout:     30 * time.Second,
		MaxIncomingStreams: 1000,
	})
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	log.Printf("Listening on %s", listenAddr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConn(conn, *authMode, srvSigner)
	}
}

func handleConn(conn quic.Connection, mode string, srvKey *aqcrypto.MLDSASigner) {
	log.Printf("New Connection: %s", conn.RemoteAddr())

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Stream accept error: %v", err)
		return
	}
	// Do NOT defer close here immediately, we want to keep it open for VPN traffic.
	// But if auth fails, we close.

	if mode == "A" {
		if err := performMLDSAMutualAuth(stream, srvKey); err != nil {
			log.Printf("ML-DSA Auth Failed: %v", err)
			conn.CloseWithError(0x1, "Auth Failed")
			return
		}
		log.Printf("ML-DSA Auth Success for %s", conn.RemoteAddr())
	} else {
		if err := performZKPAuth(stream); err != nil {
			log.Printf("ZKP Auth Failed: %v", err)
			conn.CloseWithError(0x1, "Auth Failed")
			return
		}
		log.Printf("ZKP Auth Success for %s", conn.RemoteAddr())
	}

	// Post-Auth: Register Client and Route Traffic
	handleDataStreamConversation(stream)
}

func handleDataStreamConversation(stream quic.Stream) {
	defer stream.Close()
	// Handshake for IP assignment?
	// For now, let's assume the client sends its configured Virtual IP as the first packet
	// or we assign it.
	// User Requirement: "assigns virtual IP... convenient for company".
	// Ideally using DHCP-over-VPN or Push Config.
	// Simple approach for execution:
	// 1. Client sends "IP: <requested_ip>"
	// 2. Server says "OK" or "ASSIGN: <new_ip>" (Let's trust client config for now simplistically, or Static mapping)

	// Since we don't have a complex control channel, let's just LEARN the IP from the first packet
	// OR use a control message.
	// Let's implement a simple control message: "IP:<ip_string>"

	// Read IP registration
	ipBuf := make([]byte, 64) // small buffer
	n, err := stream.Read(ipBuf)
	if err != nil {
		return
	}
	msg := string(ipBuf[:n])
	var clientVIP string
	if len(msg) > 3 && msg[:3] == "IP:" {
		clientVIP = msg[3:]
		log.Printf("Client registered with Virtual IP: %s", clientVIP)

		mapMutex.Lock()
		clientsMap[clientVIP] = stream
		mapMutex.Unlock()

		defer func() {
			mapMutex.Lock()
			delete(clientsMap, clientVIP)
			mapMutex.Unlock()
			log.Printf("Client %s disconnected", clientVIP)
		}()
	} else {
		// Start forwarding immediately if not control message?
		// Unsafe. Let's assume protocol strictly requires IP registration.
		// If we are in Site-to-Site, might send Subnet.
		log.Printf("Warning: Client didn't send IP registration. Msg: %s", msg)
		// We might still allow traffic if we learn from headers, but writing BACK requires knowing IP.
		// Return for now.
		return
	}

	// 2. Network Loop: Read from Stream -> Write to TUN
	buf := make([]byte, 2000) // MTU 1500 usually
	for {
		rn, err := stream.Read(buf)
		if err != nil {
			log.Printf("Client stream read error: %v", err)
			return
		}

		data := buf[:rn]

		// If TUN is active, write to it
		if tunDev != nil {
			if _, err := tunDev.Write(data); err != nil {
				log.Printf("TUN write error: %v", err)
			}
		}
	}
}

func readTunLoop() {
	buf := make([]byte, 2000)
	for {
		n, err := tunDev.Read(buf)
		if err != nil {
			log.Fatalf("TUN read error: %v", err)
		}
		packet := buf[:n]

		// Parse IPv4 Destination
		if len(packet) < 20 {
			continue
		}
		// Version is high nibble of byte 0.
		if (packet[0] >> 4) != 4 {
			continue // Only Support IPv4 for now
		}

		destIP := net.IP(packet[16:20])
		destIPStr := destIP.String()

		// Route
		mapMutex.RLock()
		stream, ok := clientsMap[destIPStr]
		mapMutex.RUnlock()

		if ok {
			// Write to that stream
			if _, err := stream.Write(packet); err != nil {
				// Log but don't crash, stream might be closing
				// log.Printf("Failed to route packet to %s: %v", destIPStr, err)
			}
		} else {
			// Unknown destination. Drop or Broadcast?
			log.Printf("Dropping packet for unknown info: DestIP=%s", destIPStr)
			// Drop.
		}
	}
}

// ... include auth helpers (performMLDSAMutualAuth, etc) ...

func performMLDSAMutualAuth(stream quic.Stream, srvKey *aqcrypto.MLDSASigner) error {
	// 0. Read Preamble
	preamble := make([]byte, 4)
	if _, err := io.ReadFull(stream, preamble); err != nil {
		return fmt.Errorf("failed to read preamble: %w", err)
	}
	if string(preamble) != "HELO" {
		return fmt.Errorf("invalid preamble: %x", preamble)
	}

	// 1. Send PubKey + NonceS
	srvPubBytes, err := srvKey.PublicBytes()
	if err != nil {
		return err
	}

	nonceS := make([]byte, 32)
	if _, err := rand.Read(nonceS); err != nil {
		return err
	}

	if err := sendFramed(stream, srvPubBytes); err != nil {
		return err
	}
	if _, err := stream.Write(nonceS); err != nil {
		return err
	}

	// 2. Receive C -> S
	clientPubBytes, err := readFramed(stream)
	if err != nil {
		return fmt.Errorf("failed to read client pub: %w", err)
	}
	nonceC := make([]byte, 32)
	if _, err := io.ReadFull(stream, nonceC); err != nil {
		return fmt.Errorf("failed to read client nonce: %w", err)
	}

	// 3. Send Signature_S
	sigS, err := srvKey.Sign(rand.Reader, nonceC, crypto.Hash(0))
	if err != nil {
		return err
	}
	if err := sendFramed(stream, sigS); err != nil {
		return err
	}

	// 4. Receive Signature_C
	sigC, err := readFramed(stream)
	if err != nil {
		return fmt.Errorf("failed to read client sig: %w", err)
	}

	if err := aqcrypto.VerifyMLDSA(clientPubBytes, nonceS, sigC); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}

func performZKPAuth(stream quic.Stream) error {
	preamble := make([]byte, 4)
	if _, err := io.ReadFull(stream, preamble); err != nil {
		return fmt.Errorf("failed to read preamble: %w", err)
	}
	if string(preamble) != "HELO" {
		return fmt.Errorf("invalid preamble: %x", preamble)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if _, err := stream.Write(nonce); err != nil {
		return err
	}

	buf := make([]byte, 64)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return fmt.Errorf("read proof failed: %w", err)
	}

	proof := &auth.ZKPProof{
		R: buf[:32],
		Z: buf[32:],
	}

	PBytes := make([]byte, 32)
	if _, err := io.ReadFull(stream, PBytes); err != nil {
		return err
	}

	if err := auth.VerifyZKPSession(PBytes, nonce, proof); err != nil {
		return err
	}
	return nil
}

func generateTransportCert() (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Antigravity-VPN-Transport"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func sendFramed(w io.Writer, data []byte) error {
	l := uint32(len(data))
	lenBuf := []byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readFramed(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	l := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
