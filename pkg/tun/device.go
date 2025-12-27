package tun

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"

	"github.com/songgao/water"
)

// Device wraps the water interface and provides helpers
type Device struct {
	*water.Interface
	Name     string
	IP       string
	RemoteIP string
	Mask     string
}

// Read wraps the underlying water.Interface.Read to handle platform-specifics (PI header on macOS)
func (d *Device) Read(p []byte) (n int, err error) {
	n, err = d.Interface.Read(p)
	if err != nil {
		return n, err
	}
	// Debug: Log packet header to verify raw IP
	// if n >= 4 {
	// 	log.Printf("TUN Read Raw: %x (Total %d)", p[:4], n)
	// }
	// No PI header stripping needed for water on macOS apparently
	return n, nil
}

// Write wraps the underlying water.Interface.Write to handle platform-specifics (PI header on macOS)
func (d *Device) Write(p []byte) (n int, err error) {
	// Debug: Log packet header
	// if len(p) >= 4 {
	// 	log.Printf("TUN Write Raw: %x (Total %d)", p[:4], len(p))
	// }
	// No PI header adding needed
	return d.Interface.Write(p)
}

// CreateTUN creates a new TUN device and configures it with the given IP/Remote/Mask
// ip: e.g. "10.8.0.1"
// remote: e.g. "10.8.0.2" (P2P Peer) or empty (subnet mode, usually implies point-to-point on utun anyway)
// mask: e.g. "255.255.255.0"
func CreateTUN(name string, ip string, remote string, mask string) (*Device, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	// Note: On macOS, we can't easily specify the name in config for utun usually,
	// but water supports it if we want. For now, let water pick (utunX) or try simple config.
	// On Linux, we can set the Name.

	if runtime.GOOS == "linux" && name != "" {
		config.PlatformSpecificParams = water.PlatformSpecificParams{
			Name: name,
		}
	}

	ifce, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	dev := &Device{
		Interface: ifce,
		Name:      ifce.Name(),
		IP:        ip,
		RemoteIP:  remote,
		Mask:      mask,
	}

	log.Printf("TUN device created: %s", dev.Name)

	if err := dev.Configure(); err != nil {
		ifce.Close()
		return nil, err
	}

	return dev, nil
}

// Configure sets the IP address on the interface
func (d *Device) Configure() error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		// MacOS: usually P2P. logic:
		// ifconfig utunX <local_ip> <remote_ip> netmask <mask> up

		dest := d.RemoteIP
		if dest == "" {
			// If no remote specified, some guides suggest using the IP itself, but that breaks routing loopback.
			// Ideally we have a peer. If not, maybe we can omit it?
			// `ifconfig` on macOS for utun REQUIRES a destination address.
			// If we are server, maybe use the NETWORK address or BROADCAST?
			// Let's default to d.IP for backward compat but log warning.
			dest = d.IP
			log.Printf("Warning: No RemoteIP specified for macOS TUN. Using LocalIP as dest (may cause routing issues).")
		}

		// Using: ifconfig <dev> inet <ip> netmask <mask> <dest_ip> up
		// Note: `ifconfig` syntax on darwin can be: `ifconfig interface address dest_address`
		// or `ifconfig interface inet address netmask mask dest_address`
		// The `dest_address` is usually the positional argument for POINTOPOINT.

		// Correct syntax often: `ifconfig utunX 10.8.0.1 10.8.0.2 netmask 255.255.255.0 up`
		cmd = exec.Command("ifconfig", d.Name, "inet", d.IP, "netmask", d.Mask, dest, "up")

	case "linux":
		// Linux:
		// ip addr add <ip>/<mask> dev <name>
		// ip link set dev <name> up

		// We need to convert mask 255.255.255.0 to CIDR or just use ifconfig if available.
		// Let's use `ip` command as it's standard modern Linux.
		// Need to convert mask to prefix length.
		cidrLen, err := maskToCIDR(d.Mask)
		if err != nil {
			return err
		}
		cidr := fmt.Sprintf("%s/%d", d.IP, cidrLen)
		if d.RemoteIP != "" {
			// Linux P2P: ip addr add LOCAL peer REMOTE dev NAME
			// cidr = fmt.Sprintf("%s peer %s/%d", d.IP, d.RemoteIP, cidrLen) // Wait, /32 usually for peer?
			// Let's stick to standard subnet for Linux if possible unless specific P2P needed.
			// Usually Linux TUN can be subnet topology.
			// Ignoring RemoteIP for Linux basic subnet setup for now unless specific P2P requested.
			// Reverting to simple CIDR for Linux as it was working/standard for "subnet" style.
			cidr = fmt.Sprintf("%s/%d", d.IP, cidrLen)
		}

		// We execute two commands, so we can't just assign `cmd`.
		// Quick hack: exec separate.
		if err := exec.Command("ip", "addr", "add", cidr, "dev", d.Name).Run(); err != nil {
			return fmt.Errorf("failed to add ip: %w", err)
		}
		cmd = exec.Command("ip", "link", "set", "dev", d.Name, "up")

	default:
		return fmt.Errorf("OS %s not supported", runtime.GOOS)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure interface (%s): %v, output: %s", d.Name, err, string(out))
	}

	log.Printf("Interface %s configured with IP %s Remote %s Mask %s", d.Name, d.IP, d.RemoteIP, d.Mask)
	return nil
}

func maskToCIDR(maskStr string) (int, error) {
	maskIP := net.ParseIP(maskStr)
	if maskIP == nil {
		return 0, fmt.Errorf("invalid mask: %s", maskStr)
	}
	mask := net.IPMask(maskIP.To4())
	ones, _ := mask.Size()
	return ones, nil
}
