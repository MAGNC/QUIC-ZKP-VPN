package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/quic-go/quic-go"

	"QUIC-ZKP-VPN/pkg/auth"
	"QUIC-ZKP-VPN/pkg/config"
	aqcrypto "QUIC-ZKP-VPN/pkg/crypto"
	"QUIC-ZKP-VPN/pkg/tun"
)

var (
	configFile = flag.String("config", "", "Path to configuration file")
	authMode   = flag.String("mode", "A", "Authentication Mode: 'A' (Standard PQ mTLS) or 'B' (Anon-ZKP)")
	serverAddr = flag.String("server", "localhost:4242", "Server address")
)

var (
	tunDev *tun.Device
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

		// Priority: Flag overrides Config for server address
		if cfg.ServerAddr != "" && *serverAddr == "localhost:4242" {
			// If flag was default, use config
			*serverAddr = cfg.ServerAddr
		}
	} else {
		log.Println("No config file provided. TUN interface will NOT be created (Networking disabled).")
	}

	// 1. Setup Network Interface
	if cfg != nil && cfg.LocalIP != "" {
		var err error
		tunDev, err = tun.CreateTUN("", cfg.LocalIP, cfg.RemoteIP, cfg.Mask)
		if err != nil {
			log.Fatalf("Failed to create TUN device: %v", err)
		}
	}

	log.Printf("Starting Client in Mode %s...", *authMode)

	// 2. Prepare TLS Configuration
	tlsConf := &tls.Config{
		NextProtos:         []string{"QUIC-ZKP-VPN-v1"},
		InsecureSkipVerify: true,                                           // DEMO ONLY
		CurvePreferences:   []tls.CurveID{tls.CurveID(0x6399), tls.X25519}, // 0x6399 is X25519Kyber768Draft00
	}

	var clientSigner *aqcrypto.MLDSASigner
	var err error

	if *authMode == "A" {
		log.Println("Generating Client ML-DSA Key for App-Layer mTLS...")
		clientSigner, err = aqcrypto.GenerateKey()
		if err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}
	} else {
		log.Println("Mode B selected: No Client Certificate used for TLS.")
	}

	// 3. Dial Server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, *serverAddr, tlsConf, &quic.Config{
		MaxIdleTimeout:     30 * time.Second,
		KeepAlivePeriod:    15 * time.Second,
		MaxIncomingStreams: 1000,
	})
	if err != nil {
		log.Fatalf("Failed to dial server: %v", err)
	}
	defer conn.CloseWithError(0, "Client closing")

	log.Printf("Connected to %s", conn.RemoteAddr())

	// 4. Open Stream
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatalf("Failed to open stream: %v", err)
	}
	defer stream.Close()

	// 5. Handle Authentication flows
	if *authMode == "A" {
		log.Println("Performing ML-DSA Mutual Authentication...")
		if err := performMLDSAMutualAuth(stream, clientSigner); err != nil {
			log.Fatalf("ML-DSA Auth Failed: %v", err)
		}
		log.Println("ML-DSA Authentication Successful!")
	} else if *authMode == "B" {
		log.Println("Performing ZKP Authentication...")
		if err := performZKPClientAuth(stream); err != nil {
			log.Fatalf("ZKP Auth Failed: %v", err)
		}
		log.Println("ZKP Authentication Successful!")
	}

	// 6. Post-Auth: Update Routes and Start Networking
	if cfg != nil && cfg.LocalIP != "" {
		// Send registration "IP:<localUL>" for server routing
		msg := fmt.Sprintf("IP:%s", cfg.LocalIP)
		if _, err := stream.Write([]byte(msg)); err != nil {
			log.Printf("Failed to send IP registration: %v", err)
		}
		log.Printf("Sent IP Registration: %s", msg)

		// Configure OS Routes for Server side networks?
		// User config `route` lines
		for _, r := range cfg.Routes {
			// exec command "route add -net <network> netmask <mask> gw <serverIP/tun>"
			// Implementation tricky cross platform.
			// pkg/tun could handle this.
			// wrapper for now:
			addRoute(r.Network, r.Netmask, tunDev.Name)
		}

		// Start TUN read loop
		go readTunLoop(stream)

		// Read from Stream -> Write to TUN
		handleDataStream(stream)
	} else {
		// Just echo loop for demo without config
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
		} else {
			log.Printf("Server says: %s", string(buf[:n]))
		}
		select {}
	}
}

func readTunLoop(stream quic.Stream) {
	buf := make([]byte, 2000)
	for {
		n, err := tunDev.Read(buf)
		if err != nil {
			log.Fatalf("TUN read error: %v", err)
		}
		if _, err := stream.Write(buf[:n]); err != nil {
			log.Printf("Failed to write to stream: %v", err)
			return
		}
	}
}

func handleDataStream(stream quic.Stream) {
	buf := make([]byte, 2000)
	for {
		rn, err := stream.Read(buf)
		if err != nil {
			log.Printf("Stream read error: %v", err)
			return
		}
		if _, err := tunDev.Write(buf[:rn]); err != nil {
			log.Printf("TUN write error: %v", err)
		}
	}
}

func addRoute(network, mask, devName string) {
	// Simple wrapper, platform specific
	// MacOS: route add -net 192.168.10.0 -netmask 255.255.255.0 -interface utunX
	log.Printf("Adding route %s mask %s via %s", network, mask, devName)
	// TODO: implement actual exec.Command
}

func performZKPClientAuth(stream quic.Stream) error {
	// Protocol:
	// 0. C -> S: Preamble "HELO"
	// 1. Server -> Client: Nonce (32 bytes)
	// 2. Client -> Server: Proof (Commitment + Response)
	// 3. Client -> Server: Public Key (Identity) - For demo/verifier to know who we are claiming to be

	// 0. Send Preamble
	if _, err := stream.Write([]byte("HELO")); err != nil {
		return fmt.Errorf("failed to send preamble: %w", err)
	}

	// 1. Receive Nonce
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(stream, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	// 2. Generate Identity (Ephemeral for demo, or load from disk)
	// In Mode B, this identity is long-term registered logic.
	x, P, err := auth.GenerateIdentity()
	if err != nil {
		return err
	}

	// 3. Generate Proof
	proof, err := auth.GenerateZKPSession(x, P, nonce)
	if err != nil {
		return fmt.Errorf("proof generation failed: %w", err)
	}

	// 4. Send Proof
	// Wire format: R (32) || Z (32)
	// Need to be careful about buffer concat
	wireProof := make([]byte, 0, 64)
	wireProof = append(wireProof, proof.R...)
	wireProof = append(wireProof, proof.Z...)

	if _, err := stream.Write(wireProof); err != nil {
		return err
	}

	// 5. Send Public Key (Identity)
	// In a privacy preserving system, this P might be a blind tag or ephemeral ID
	// derived from the real identity, or the server tries to match.
	// For this spec "Client proves possession of a registered secret key",
	// the server typically needs to know WHICH key.
	// We send P here.
	PBytes, _ := P.MarshalBinary()
	if _, err := stream.Write(PBytes); err != nil {
		return err
	}

	return nil
}

func performMLDSAMutualAuth(stream quic.Stream, clientKey *aqcrypto.MLDSASigner) error {
	// Protocol (Match Server):
	// 0. C -> S: Preamble "HELO"
	// 1. S -> C: Server PubKey + NonceS
	// 2. C -> S: Client PubKey + NonceC
	// 3. S -> C: Signature_S(NonceC)
	// 4. C -> S: Signature_C(NonceS)

	// 0. Send Preamble
	if _, err := stream.Write([]byte("HELO")); err != nil {
		return fmt.Errorf("failed to send preamble: %w", err)
	}

	// 1. Receive S -> C: Server Pub + NonceS
	srvPubBytes, err := readFramed(stream)
	if err != nil {
		return fmt.Errorf("failed to read server pub: %w", err)
	}
	nonceS := make([]byte, 32)
	if _, err := io.ReadFull(stream, nonceS); err != nil {
		return fmt.Errorf("failed to read server nonce: %w", err)
	}

	// 2. Send C -> S: Client Pub + NonceC
	clientPubBytes, err := clientKey.PublicBytes()
	if err != nil {
		return err
	}
	nonceC := make([]byte, 32)
	if _, err := rand.Read(nonceC); err != nil {
		return err
	}

	if err := sendFramed(stream, clientPubBytes); err != nil {
		return err
	}
	if _, err := stream.Write(nonceC); err != nil {
		return err
	}

	// 3. Receive Signature_S(NonceC)
	sigS, err := readFramed(stream)
	if err != nil {
		return fmt.Errorf("failed to read server sig: %w", err)
	}

	// Verify Server Signature
	if err := aqcrypto.VerifyMLDSA(srvPubBytes, nonceC, sigS); err != nil {
		return fmt.Errorf("server signature invalid: %w", err)
	}

	// 4. Send Signature_C(NonceS)
	sigC, err := clientKey.Sign(rand.Reader, nonceS, crypto.Hash(0))
	if err != nil {
		return err
	}
	if err := sendFramed(stream, sigC); err != nil {
		return err
	}

	return nil
}

// Helpers for framing (Duplicated for demo simplicity)
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
