// Package ipc is the control API the W1nCray agent uses: HTTP/1.1 with JSON
// bodies over a Unix socket (docs/IPC.md). The agent and this program define
// their own types; nothing is shared between the two code bases.
package ipc

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray-prism/engine"
	"github.com/W1nCwC/W1nCray-prism/gate"
)

const maxBody = 32 << 20

// New returns the API handler.
func New(e *engine.Engine, g *gate.Gate) http.Handler {
	s := &server{e: e, g: g}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("PUT /v1/config", s.putConfig)
	mux.HandleFunc("POST /v1/check", s.check)
	mux.HandleFunc("PUT /v1/users/{tag}", s.putUsers)
	mux.HandleFunc("PUT /v1/devices/{tag}", s.putDevices)
	mux.HandleFunc("GET /v1/stats", s.stats)
	mux.HandleFunc("POST /v1/stats/commit", s.commit)

	return versioned(mux)
}

type server struct {
	e *engine.Engine
	g *gate.Gate
}

// versioned insists on the API header; a missing or different version is
// refused so a newer agent never talks to an older program by accident.
func versioned(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Prism-Api") != strconv.Itoa(engine.APIVersion) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "api", "message": "X-Prism-Api: " + strconv.Itoa(engine.APIVersion) + " is required"})

			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.e.Status())
}

type configBody struct {
	Hash   string          `json:"hash"`
	Config json.RawMessage `json:"config"`
}

func (s *server) putConfig(w http.ResponseWriter, r *http.Request) {
	var body configBody
	if !decode(w, r, &body) {
		return
	}
	if body.Hash == "" || len(body.Config) == 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid", "message": "hash and config are required"})

		return
	}
	noop, err := s.e.Apply(body.Hash, body.Config)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"applied": body.Hash, "noop": noop})
	case errors.Is(err, engine.ErrInvalid):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid", "message": err.Error(), "kept": s.e.Status().ConfigHash})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "start_failed", "message": err.Error(), "kept": s.e.Status().ConfigHash})
	}
}

func (s *server) check(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config json.RawMessage `json:"config"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.e.Check(body.Config); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid", "message": err.Error()})

		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type usersBody struct {
	Seq   int64       `json:"seq"`
	Users []gate.User `json:"users"`
}

func (s *server) putUsers(w http.ResponseWriter, r *http.Request) {
	var body usersBody
	if !decode(w, r, &body) {
		return
	}
	added, removed, kicked, applied, err := s.e.SetUsers(r.PathValue("tag"), body.Seq, body.Users)
	switch {
	case errors.Is(err, os.ErrNotExist):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found", "message": "no such inbound"})
	case errors.Is(err, engine.ErrInvalid):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid", "message": err.Error()})
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal", "message": err.Error()})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"applied": applied, "users": len(body.Users), "added": added, "removed": removed, "kicked": kicked})
	}
}

func (s *server) putDevices(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alive map[string]int `json:"alive"`
	}
	if !decode(w, r, &body) {
		return
	}
	alive := make(map[int]int, len(body.Alive))
	for k, v := range body.Alive {
		if id, err := strconv.Atoi(k); err == nil {
			alive[id] = v
		}
	}
	s.g.SetAlive(r.PathValue("tag"), alive)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	id, traffic, alive, ok := s.g.Snapshot(tag)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found", "message": "no such inbound"})

		return
	}
	if traffic == nil {
		traffic = []gate.Traffic{}
	}
	if alive == nil {
		alive = []gate.Alive{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"boot_id": s.e.BootID(), "snapshot": id, "traffic": traffic, "alive": alive})
}

func (s *server) commit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tag      string `json:"tag"`
		Snapshot uint64 `json:"snapshot"`
		BootID   string `json:"boot_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	if (body.BootID != "" && body.BootID != s.e.BootID()) || !s.g.Commit(body.Tag, body.Snapshot) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "stale", "message": "the snapshot is not the current one"})

		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	if err := dec.Decode(v); err != nil && !strings.Contains(err.Error(), "EOF") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_request", "message": err.Error()})

		return false
	}

	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
