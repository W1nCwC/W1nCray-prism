package mieru

import (
	"github.com/sagernet/sing-box/option"
)

// Options is the config of a Prism mieru inbound. The listen address and port
// come from the common listen options; the port must be a single port.
type Options struct {
	option.ListenOptions
	// Transport is "tcp" (default) or "udp".
	Transport string `json:"transport,omitempty"`
	// TrafficPattern is the base64 traffic pattern of this server; it does not
	// have to equal the client's.
	TrafficPattern string `json:"traffic_pattern,omitempty"`
	// Users must stay empty: users travel over the IPC.
	Users []any `json:"users,omitempty"`
}
