package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config represents the parsed configuration
type Config struct {
	LocalIP    string
	RemoteIP   string // For P2P remote endpoint if needed, or mask
	Mask       string
	Routes     []Route
	ServerAddr string // "remote <host> <port>"
}

type Route struct {
	Network string
	Netmask string
}

// Parse loads a config file and returns a Config struct
func Parse(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]

		switch cmd {
		case "ifconfig":
			// ifconfig <local> <remote/mask>
			if len(parts) >= 3 {
				cfg.LocalIP = parts[1]
				// Basic heuristic: if 3rd arg is like a mask, treat as mask, else remote IP
				if strings.Contains(parts[2], "255") {
					cfg.Mask = parts[2]
				} else {
					// It's a P2P peer IP. For TUN, we often just need Local and a Mask.
					// If user gives "10.8.0.1 10.8.0.2", we might need to derive mask
					// or just treat the second as peer.
					// For this simplified logic: assume Subnet topology if mask is explicitly set elsewhere
					// or just use /30 or /24?
					// Let's assume the user provides: "ifconfig 10.8.0.1 255.255.255.0" for subnet mode
					// OR "ifconfig 10.8.0.1 10.8.0.2" for p2p.

					// Let's treat the second arg as Mask if it looks like one, otherwise ignore or store as peer
					// For now: Require explicit netmask style?
					// Actually OpenVPN `ifconfig` is `local remote_netmask` for point-to-point.
					// But usually `ifconfig 10.8.0.1 10.8.0.2` implies p2p topology.

					// Let's stick to our Plan: user said "assigns IP... convenient for company".
					// Probably "ifconfig 10.8.0.1 255.255.255.0" is preferred for ease?
					// Let's assume second arg is Mask if it starts with 255?
					if strings.HasPrefix(parts[2], "255") {
						cfg.Mask = parts[2]
					} else {
						// Assume P2P style 'local remote'
						// We'll treat 'remote' as P2P peer
						cfg.RemoteIP = parts[2]
						cfg.Mask = "255.255.255.255" // P2P usually
					}
				}
			}
		case "route":
			// route <network> <mask>
			if len(parts) >= 3 {
				cfg.Routes = append(cfg.Routes, Route{
					Network: parts[1],
					Netmask: parts[2],
				})
			}
		case "remote":
			// remote <host> <port>
			if len(parts) >= 2 {
				host := parts[1]
				port := "4242"
				if len(parts) >= 3 {
					port = parts[2]
				}
				cfg.ServerAddr = fmt.Sprintf("%s:%s", host, port)
			}

		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Defaults if missing
	if cfg.Mask == "" {
		cfg.Mask = "255.255.255.0"
	}

	return cfg, nil
}
