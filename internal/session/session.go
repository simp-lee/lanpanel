// Package session owns in-memory Management browser sessions and socket invalidation.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	SelectorCookie  = "lanpanel_session"
	ProofHeader     = "X-LanPanel-Session-Proof"
	CSRFHeader      = "X-LanPanel-CSRF"
	InactivityLimit = 30 * time.Minute
	AbsoluteLimit   = 12 * time.Hour
)

type (
	Credentials struct{ Selector, Proof, CSRF string }
	Principal   struct {
		Selector   string
		Generation uint64
	}
)

type (
	Socket       interface{ Close() error }
	SocketSender func() error
	Options      struct {
		Now           func() time.Time
		Random        io.Reader
		SweepInterval time.Duration
	}
)

type entry struct {
	proof, csrf         [32]byte
	fingerprint, origin string
	generation          uint64
	issued, last        time.Time
	sockets             map[Socket]struct{}
}
type Manager struct {
	mu          sync.Mutex
	entries     map[string]*entry
	generation  uint64
	fingerprint string
	closed      bool
	now         func() time.Time
	random      io.Reader
	stop        chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
}

func New(fingerprint string, options Options) (*Manager, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("token fingerprint is required")
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	interval := options.SweepInterval
	if interval == 0 {
		interval = time.Second
	}
	if interval < time.Millisecond || interval > time.Minute {
		return nil, fmt.Errorf("session sweep interval is invalid")
	}
	manager := &Manager{entries: map[string]*entry{}, generation: 1, fingerprint: fingerprint, now: now, random: random, stop: make(chan struct{}), done: make(chan struct{})}
	go manager.sweep(interval)
	return manager, nil
}

func (m *Manager) Issue(origin, fingerprint string) (Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || origin == "" || fingerprint != m.fingerprint {
		return Credentials{}, fmt.Errorf("session authority changed")
	}
	selector, err := randomHex(m.random)
	if err != nil {
		return Credentials{}, err
	}
	proof, err := randomHex(m.random)
	if err != nil {
		return Credentials{}, err
	}
	csrf, err := randomHex(m.random)
	if err != nil {
		return Credentials{}, err
	}
	stamp := m.now().UTC()
	m.entries[selector] = &entry{proof: sha256.Sum256([]byte(proof)), csrf: sha256.Sum256([]byte(csrf)), fingerprint: fingerprint, origin: origin, generation: m.generation, issued: stamp, last: stamp, sockets: map[Socket]struct{}{}}
	return Credentials{selector, proof, csrf}, nil
}

func (m *Manager) Authenticate(selector, proof, csrf, origin, fingerprint string, mutation bool) (Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.entries[selector]
	now := m.now().UTC()
	if m.closed || !ok || expired(value, now) || value.generation != m.generation || value.fingerprint != m.fingerprint || fingerprint != m.fingerprint || value.origin != origin || !digestEqual(value.proof, proof) || mutation && !digestEqual(value.csrf, csrf) {
		return Principal{}, fmt.Errorf("session authentication failed")
	}
	value.last = now
	return Principal{selector, m.generation}, nil
}

// AuthenticateSocket validates the initial proof without extending inactivity.
func (m *Manager) AuthenticateSocket(selector, proof, origin, fingerprint string) (Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.entries[selector]
	now := m.now().UTC()
	if m.closed || !ok || expired(value, now) || value.generation != m.generation || value.fingerprint != m.fingerprint || fingerprint != m.fingerprint || value.origin != origin || !digestEqual(value.proof, proof) {
		return Principal{}, fmt.Errorf("socket authentication failed")
	}
	return Principal{selector, m.generation}, nil
}

func (m *Manager) Valid(principal Principal) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.entries[principal.Selector]
	return !m.closed && ok && !expired(value, m.now().UTC()) && principal.Generation == m.generation && value.generation == m.generation && value.fingerprint == m.fingerprint
}

func (m *Manager) Attach(principal Principal, socket Socket) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.entries[principal.Selector]
	if m.closed || !ok || principal.Generation != m.generation || socket == nil {
		return fmt.Errorf("socket session is invalid")
	}
	value.sockets[socket] = struct{}{}
	return nil
}

func (m *Manager) Detach(principal Principal, socket Socket) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if value := m.entries[principal.Selector]; value != nil {
		delete(value.sockets, socket)
	}
}

func (m *Manager) Send(principal Principal, fingerprint string, send SocketSender) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.entries[principal.Selector]
	if m.closed || !ok || expired(value, m.now().UTC()) || principal.Generation != m.generation || value.generation != m.generation || fingerprint != m.fingerprint || send == nil {
		return fmt.Errorf("socket session expired")
	}
	return send()
}

func (m *Manager) Logout(principal Principal) {
	m.mu.Lock()
	sockets := m.removeLocked(principal.Selector, m.entries[principal.Selector])
	m.mu.Unlock()
	closeSockets(sockets)
}
func (m *Manager) CommitTokenRotation(fingerprint string) { m.InvalidateFingerprint(fingerprint) }
func (m *Manager) InvalidateFingerprint(fingerprint string) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	sockets := m.invalidateLocked(fingerprint)
	m.mu.Unlock()
	closeSockets(sockets)
}

func (m *Manager) RequireFingerprint(fingerprint string) bool {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false
	}
	if fingerprint != "" && fingerprint == m.fingerprint {
		m.mu.Unlock()
		return true
	}
	sockets := m.invalidateLocked(fingerprint)
	m.mu.Unlock()
	closeSockets(sockets)
	return false
}

func (m *Manager) invalidateLocked(fingerprint string) []Socket {
	m.generation++
	m.fingerprint = fingerprint
	sockets := []Socket{}
	for selector, value := range m.entries {
		sockets = append(sockets, m.removeLocked(selector, value)...)
	}
	return sockets
}

func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		sockets := m.invalidateLocked("closed")
		m.mu.Unlock()
		close(m.stop)
		closeSockets(sockets)
		<-m.done
	})
}

func (m *Manager) sweep(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(m.done)
	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			now := m.now().UTC()
			sockets := []Socket{}
			for selector, value := range m.entries {
				if expired(value, now) {
					sockets = append(sockets, m.removeLocked(selector, value)...)
				}
			}
			m.mu.Unlock()
			closeSockets(sockets)
		case <-m.stop:
			return
		}
	}
}

func (m *Manager) removeLocked(selector string, value *entry) []Socket {
	if value == nil {
		return nil
	}
	delete(m.entries, selector)
	sockets := make([]Socket, 0, len(value.sockets))
	for socket := range value.sockets {
		sockets = append(sockets, socket)
	}
	return sockets
}

func closeSockets(sockets []Socket) {
	for _, socket := range sockets {
		_ = socket.Close()
	}
}

func expired(value *entry, now time.Time) bool {
	return now.Sub(value.last) >= InactivityLimit || now.Sub(value.issued) >= AbsoluteLimit || now.Before(value.issued)
}

func randomHex(reader io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", err
	}
	defer clear(raw)
	return hex.EncodeToString(raw), nil
}

func digestEqual(expected [32]byte, value string) bool {
	actual := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(expected[:], actual[:]) == 1
}
