package mieru

import (
	"net"
	"strconv"

	"github.com/W1nCwC/W1nCray-prism/gate"
)

// UpdateUsers replaces the user set. The names are the stable panel ids; the
// passwords are the uuids. An empty set is fine: nobody can then log in.
// Sessions of users that are gone are closed here, before the gate's own kick.
func (h *Inbound) UpdateUsers(users []gate.User) error {
	list := make([]credential, 0, len(users))
	keep := make(map[string]bool, len(users))
	for _, u := range users {
		c := credential{name: strconv.Itoa(u.ID), password: u.UUID}
		if err := checkCredential(c); err != nil {
			return err
		}
		list = append(list, c)
		keep[c.name] = true
	}
	h.mu.Lock()
	h.users, h.known = list, keep
	m := h.mux
	var gone []net.Conn
	for c, name := range h.conns {
		if !keep[name] {
			gone = append(gone, c)
		}
	}
	h.mu.Unlock()
	if m != nil {
		m.setUsers(list)
	}
	for _, c := range gone {
		_ = c.Close()
	}

	return nil
}
