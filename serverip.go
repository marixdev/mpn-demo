package web

// The demo's stand-in for mini-panel/internal/web/serverip.go, laid over it by build.sh. The real one asks the machine
// which address it uses to reach the Internet, which on the demo host is that host's real public address. The demo
// pretends to be a server, so it shows a documentation address (RFC 5737) instead, whatever the visitor typed.
func serverIP(hostHeader string) string {
	return demoServerIP
}

const demoServerIP = "203.0.113.20"
