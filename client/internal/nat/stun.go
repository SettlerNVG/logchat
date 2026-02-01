package nat

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
	"github.com/rs/zerolog/log"
)

// STUNResult contains NAT discovery results
type STUNResult struct {
	PublicIP   string
	PublicPort int
	LocalIP    string
	LocalPort  int
	NATType    string
	CanAccept  bool
}

// DiscoverNAT performs STUN discovery to determine public address and NAT type
func DiscoverNAT(stunServer string, localPort int) (*STUNResult, error) {
	// Create UDP connection
	localAddr := fmt.Sprintf("0.0.0.0:%d", localPort)
	conn, err := net.ListenPacket("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	// Set timeout
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Resolve STUN server address
	stunAddr, err := net.ResolveUDPAddr("udp", stunServer)
	if err != nil {
		return nil, fmt.Errorf("resolve STUN server: %w", err)
	}

	// Create STUN binding request
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Send request
	_, err = conn.WriteTo(message.Raw, stunAddr)
	if err != nil {
		return nil, fmt.Errorf("send STUN request: %w", err)
	}

	log.Debug().Str("stun_server", stunServer).Msg("Sent STUN binding request")

	// Receive response
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("receive STUN response: %w", err)
	}

	// Parse response
	msg := new(stun.Message)
	msg.Raw = buf[:n]
	if err := msg.Decode(); err != nil {
		return nil, fmt.Errorf("decode STUN response: %w", err)
	}

	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(msg); err != nil {
		return nil, fmt.Errorf("parse STUN response: %w", err)
	}

	// Get local address
	localUDPAddr := conn.LocalAddr().(*net.UDPAddr)

	// Determine NAT type (simplified)
	natType := detectNATType(localUDPAddr.IP.String(), xorAddr.IP.String())

	result := &STUNResult{
		PublicIP:   xorAddr.IP.String(),
		PublicPort: xorAddr.Port,
		LocalIP:    localUDPAddr.IP.String(),
		LocalPort:  localUDPAddr.Port,
		NATType:    natType,
		CanAccept:  natType == "None" || natType == "Full Cone",
	}

	log.Info().
		Str("public_ip", result.PublicIP).
		Int("public_port", result.PublicPort).
		Str("local_ip", result.LocalIP).
		Int("local_port", result.LocalPort).
		Str("nat_type", result.NATType).
		Bool("can_accept", result.CanAccept).
		Msg("STUN discovery completed")

	return result, nil
}

// detectNATType performs simplified NAT type detection
func detectNATType(localIP, publicIP string) string {
	// If local IP equals public IP, no NAT
	if localIP == publicIP {
		return "None"
	}

	// Check if it's a private IP or unspecified address
	if isPrivateIP(localIP) || localIP == "::" || localIP == "0.0.0.0" {
		// Simplified: assume Full Cone NAT
		// Full NAT type detection requires multiple STUN servers and tests
		// See RFC 5780 for complete implementation
		return "Full Cone"
	}

	return "Unknown"
}

// isPrivateIP checks if IP is in private range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet != nil && subnet.Contains(ip) {
			return true
		}
	}

	return false
}

// DiscoverWithFallback tries multiple STUN servers
func DiscoverWithFallback(stunServers []string, localPort int) (*STUNResult, error) {
	var lastErr error

	for _, server := range stunServers {
		result, err := DiscoverNAT(server, localPort)
		if err == nil {
			return result, nil
		}

		log.Warn().Err(err).Str("server", server).Msg("STUN server failed, trying next")
		lastErr = err
	}

	return nil, fmt.Errorf("all STUN servers failed: %w", lastErr)
}
