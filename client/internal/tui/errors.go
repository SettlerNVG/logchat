package tui

import (
	"strings"
)

// friendlyError converts technical errors to user-friendly messages
func friendlyError(err error) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Connection errors
	if strings.Contains(errStr, "connection refused") {
		return "Cannot connect to server. Please check if server is running."
	}
	if strings.Contains(errStr, "context deadline exceeded") {
		return "Connection timeout. Please check your internet connection."
	}
	if strings.Contains(errStr, "no such host") {
		return "Server not found. Please check the server address."
	}

	// Authentication errors
	if strings.Contains(errStr, "invalid credentials") || strings.Contains(errStr, "Unauthenticated") {
		return "Invalid username or password."
	}
	if strings.Contains(errStr, "username already taken") || strings.Contains(errStr, "AlreadyExists") {
		return "Username already taken. Please choose another."
	}
	if strings.Contains(errStr, "password must be at least") {
		return "Password must be at least 8 characters."
	}
	if strings.Contains(errStr, "username must be") {
		return "Username must be 3-50 alphanumeric characters."
	}

	// Rate limiting
	if strings.Contains(errStr, "rate limit exceeded") || strings.Contains(errStr, "ResourceExhausted") {
		return "Too many requests. Please wait a moment and try again."
	}

	// Session errors
	if strings.Contains(errStr, "no connection path available") {
		return "Cannot establish P2P connection. Both users may be behind strict NAT."
	}
	if strings.Contains(errStr, "user is offline") {
		return "User is offline."
	}
	if strings.Contains(errStr, "user not found") {
		return "User not found."
	}
	if strings.Contains(errStr, "already in active session") {
		return "User is already in another chat."
	}

	// Network errors
	if strings.Contains(errStr, "network is unreachable") {
		return "Network unreachable. Please check your internet connection."
	}

	// TLS errors
	if strings.Contains(errStr, "certificate") {
		return "Security certificate error. Please contact server administrator."
	}

	// Generic gRPC errors - hide technical details
	if strings.Contains(errStr, "rpc error:") {
		// Extract just the description part if possible
		if idx := strings.Index(errStr, "desc = "); idx != -1 {
			desc := errStr[idx+7:]
			// Clean up common technical terms
			desc = strings.ReplaceAll(desc, "failed to ", "")
			desc = strings.ReplaceAll(desc, "error: ", "")
			return capitalizeFirst(desc)
		}
		return "Operation failed. Please try again."
	}

	// If we don't recognize the error, return a generic message
	// Don't expose internal error details to users
	return "Something went wrong. Please try again."
}

func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
