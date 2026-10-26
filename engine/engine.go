// Package engine owns the lifecycle of the embedded proxy core: it validates
// a config, builds it with the core's own builder (nothing is bound yet),
// swaps it in and falls back to the last good config when the new one cannot
// start (handoff 69 §1).
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"github.com/W1nCwC/W1nCray-prism/gate"
	"github.com/W1nCwC/W1nCray-prism/inbound/hot"
)

// Version is the program version; CoreVersion the embedded core's.
const (
	Version     = "0.3.2"
	CoreVersion = "1.14.3"
	APIVersion  = 1
)

// ErrInvalid marks a config that cannot be built (422); ErrStart one that
// built but could not start (500). Both leave the previous config running.
var (
	ErrInvalid = errors.New("invalid")
	ErrStart   = errors.New("start_failed")
)

// allowed lists the inbound types this program serves.
var allowed = map[string]bool{"tuic": true, "hysteria": true, "hysteria2": true, "anytls": true, "naive": true, "vless": true, "trojan": true, "mieru": true}

// Engine is safe for concurrent use.
type Engine struct {
	dir  string
	gate *gate.Gate
	boot string

	mu       sync.Mutex
	ctx      context.Context
	cur      *running
	good     []byte
	goodHash string
	rejected string
	lastErr  string
	started  time.Time
}

type running struct {
	box   *box.Box
	hash  string
	tags  []string
	types map[string]string
}

// New creates an engine that keeps its state in dir (created 0700).
func New(dir string, g *gate.Gate) (*Engine, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	e := &Engine{dir: dir, gate: g, boot: randomID(), started: time.Now()}
	e.ctx = gate.WithContext(newContext(), g)

	return e, nil
}

// BootID changes on every process start so the agent can detect a restart.
func (e *Engine) BootID() string { return e.boot }

// Check builds raw without keeping it (the core's own check).
func (e *Engine) Check(raw []byte) error {
	b, _, err := e.build(raw)
	if err != nil {
		return err
	}

	return b.Close()
}

func (e *Engine) build(raw []byte) (*box.Box, *parsed, error) {
	opts, err := sjson.UnmarshalExtendedContext[option.Options](e.ctx, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	p, err := validate(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	b, err := box.New(box.Options{Context: e.ctx, Options: opts})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	return b, p, nil
}

type parsed struct {
	tags  []string
	types map[string]string
}

func validate(o option.Options) (*parsed, error) {
	if o.Experimental != nil {
		return nil, errors.New("experimental is not offered by this program")
	}
	p := &parsed{types: map[string]string{}}
	for i, in := range o.Inbounds {
		if in.Tag == "" {
			return nil, fmt.Errorf("inbounds[%d]: tag is required", i)
		}
		if !allowed[in.Type] {
			return nil, fmt.Errorf("inbounds[%d]: type %q is not served by this program", i, in.Type)
		}
		if _, dup := p.types[in.Tag]; dup {
			return nil, fmt.Errorf("inbounds[%d]: duplicate tag %q", i, in.Tag)
		}
		p.types[in.Tag] = in.Type
		p.tags = append(p.tags, in.Tag)
	}

	return p, nil
}

// Apply installs the config identified by hash. When hash equals the running
// one nothing happens (noop=true).
func (e *Engine) Apply(hash string, raw []byte) (noop bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur != nil && e.cur.hash == hash {
		return true, nil
	}
	cand, p, err := e.build(raw)
	if err != nil {
		e.rejected, e.lastErr = hash, err.Error()

		return false, err
	}
	cand.Router().AppendTracker(e.gate)
	keep := map[string]bool{}
	for _, tag := range p.tags {
		keep[tag] = true
	}
	e.gate.Drop(keep)
	e.pushUsers(cand, p.tags)

	old := e.cur
	e.cur = nil
	if old != nil {
		_ = old.box.Close()
	}
	if err := cand.Start(); err != nil {
		_ = cand.Close()
		e.rejected, e.lastErr = hash, "start: "+err.Error()
		e.restoreLocked()

		return false, fmt.Errorf("%w: %v", ErrStart, err)
	}
	e.cur = &running{box: cand, hash: hash, tags: p.tags, types: p.types}
	e.good, e.goodHash, e.rejected, e.lastErr = append([]byte(nil), raw...), hash, "", ""
	e.persistConfigLocked()

	return false, nil
}

// restoreLocked rebuilds the last good config after a failed start.
func (e *Engine) restoreLocked() {
	if e.good == nil {
		return
	}
	b, p, err := e.build(e.good)
	if err != nil {
		e.lastErr += "; restore: " + err.Error()

		return
	}
	b.Router().AppendTracker(e.gate)
	e.pushUsers(b, p.tags)
	if err := b.Start(); err != nil {
		_ = b.Close()
		e.lastErr += "; restore start: " + err.Error()

		return
	}
	e.cur = &running{box: b, hash: e.goodHash, tags: p.tags, types: p.types}
}

// pushUsers hands the gate's current user tables to the inbounds of b.
func (e *Engine) pushUsers(b *box.Box, tags []string) {
	for _, tag := range tags {
		in, ok := b.Inbound().Get(tag)
		if !ok {
			continue
		}
		if u, ok := in.(hot.Updater); ok {
			_ = u.UpdateUsers(e.gate.Users(tag))
		}
	}
}

// SetUsers replaces the user set of an inbound; applied=false means the
// request was older than one already applied.
func (e *Engine) SetUsers(tag string, seq int64, users []gate.User) (added, removed, kicked int, applied bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur == nil || e.cur.types[tag] == "" {
		return 0, 0, 0, false, os.ErrNotExist
	}
	in, ok := e.cur.box.Inbound().Get(tag)
	if !ok {
		return 0, 0, 0, false, os.ErrNotExist
	}
	updater, ok := in.(hot.Updater)
	if !ok {
		return 0, 0, 0, false, fmt.Errorf("inbound %q does not take users", tag)
	}
	for _, u := range users {
		if u.ID <= 0 || u.UUID == "" {
			return 0, 0, 0, false, fmt.Errorf("%w: user %d needs a positive id and a uuid", ErrInvalid, u.ID)
		}
	}
	added, removed, kicked, applied = e.gate.Replace(tag, seq, users)
	if !applied {
		return 0, 0, 0, false, nil
	}
	if err := updater.UpdateUsers(e.gate.Users(tag)); err != nil {
		return added, removed, kicked, true, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	e.persistUsersLocked()

	return added, removed, kicked, true, nil
}

// Status is the GET /v1/status body.
type Status struct {
	API          int             `json:"api"`
	Version      string          `json:"version"`
	Core         string          `json:"core"`
	BootID       string          `json:"boot_id"`
	State        string          `json:"state"`
	ConfigHash   *string         `json:"config_hash"`
	RejectedHash *string         `json:"rejected_hash"`
	LastError    string          `json:"last_error"`
	Inbounds     []InboundStatus `json:"inbounds"`
	StartedAt    int64           `json:"started_at"`
}

// InboundStatus describes one running inbound.
type InboundStatus struct {
	Tag   string `json:"tag"`
	Type  string `json:"type"`
	Users int    `json:"users"`
	Conns int    `json:"conns"`
}

// Status reports the running state.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{API: APIVersion, Version: Version, Core: CoreVersion, BootID: e.boot, State: "idle", LastError: e.lastErr, StartedAt: e.started.Unix(), Inbounds: []InboundStatus{}}
	if e.cur != nil {
		h := e.cur.hash
		s.ConfigHash = &h
		if len(e.cur.tags) > 0 {
			s.State = "running"
		}
		for _, tag := range e.cur.tags {
			users, conns := e.gate.Counts(tag)
			s.Inbounds = append(s.Inbounds, InboundStatus{Tag: tag, Type: e.cur.types[tag], Users: users, Conns: conns})
		}
	} else if e.lastErr != "" {
		s.State = "failed"
	}
	if e.rejected != "" {
		r := e.rejected
		s.RejectedHash = &r
	}
	sort.Slice(s.Inbounds, func(i, j int) bool { return s.Inbounds[i].Tag < s.Inbounds[j].Tag })

	return s
}

// Close stops the core.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur == nil {
		return nil
	}
	err := e.cur.box.Close()
	e.cur = nil

	return err
}

// ---- persistence --------------------------------------------------------------

type configFile struct {
	Hash   string          `json:"hash"`
	Config json.RawMessage `json:"config"`
}

type usersFile map[string]struct {
	Seq   int64       `json:"seq"`
	Users []gate.User `json:"users"`
}

func (e *Engine) persistConfigLocked() {
	b, _ := json.Marshal(configFile{Hash: e.goodHash, Config: e.good})
	_ = writeAtomic(filepath.Join(e.dir, "config.json"), b)
}

func (e *Engine) persistUsersLocked() {
	out := usersFile{}
	if e.cur != nil {
		for _, tag := range e.cur.tags {
			out[tag] = struct {
				Seq   int64       `json:"seq"`
				Users []gate.User `json:"users"`
			}{Seq: e.gate.Seq(tag), Users: e.gate.Users(tag)}
		}
	}
	b, _ := json.Marshal(out)
	_ = writeAtomic(filepath.Join(e.dir, "users.json"), b)
}

// Restore loads the persisted users and config so the previous state serves
// before the agent reconnects. A broken state file is ignored.
func (e *Engine) Restore() {
	if b, err := os.ReadFile(filepath.Join(e.dir, "users.json")); err == nil {
		var uf usersFile
		if json.Unmarshal(b, &uf) == nil {
			for tag, v := range uf {
				e.gate.Replace(tag, v.Seq, v.Users)
			}
		}
	}
	b, err := os.ReadFile(filepath.Join(e.dir, "config.json"))
	if err != nil {
		return
	}
	var cf configFile
	if json.Unmarshal(b, &cf) != nil || cf.Hash == "" {
		return
	}
	if _, err := e.Apply(cf.Hash, cf.Config); err != nil {
		e.mu.Lock()
		e.lastErr = "restore: " + err.Error()
		e.mu.Unlock()
	}
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
