// Package link is the bridge's end of the keeper link (PROTOCOL.md section 1): Noise KK
// over TCP with the keeper dialling in, byte-compatible with the keeper's
// compartment channel (the keeper's cah.mjs serveChannel and
// openChannel):
//
//   - Noise_KK_25519_ChaChaPoly_SHA256, prologue "eggomi/cah-channel/v1",
//     the keeper as initiator, this bridge as responder, empty payloads;
//   - frames are a u16 big-endian length (1..65535) and the body;
//   - the handshake frames are 0x01 followed by the Noise message;
//   - after it, each frame is one transport message carrying one JSON
//     request {id, method, params} or reply {id, result} / {id, error}.
//
// Only the pinned keeper key completes the handshake. Requests on one
// connection are answered in order; the keeper opens a second connection
// for long polls.
package link

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/flynn/noise"
	"github.com/rs/zerolog"
)

// Prologue is the keeper channel's Noise prologue.
var Prologue = []byte("eggomi/cah-channel/v1")

const (
	hello = 0x01
	// MaxMessage is Noise's message limit; a frame never exceeds it.
	MaxMessage = 65535
	tagSize    = 16
	// MaxPayload is the largest plaintext one transport message carries.
	MaxPayload = MaxMessage - tagSize
	maxSafeInt = 1<<53 - 1
)

// Error is a coded failure the keeper receives as {error: {code}}. Nothing
// else about a failure leaves the bridge.
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

// Errorf-free helpers for handlers.
func Code(code string) error { return &Error{Code: code} }

// Handler answers one request. ctx is cancelled when the connection closes.
type Handler interface {
	Handle(ctx context.Context, method string, params json.RawMessage) (any, error)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, method string, params json.RawMessage) (any, error)

func (f HandlerFunc) Handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	return f(ctx, method, params)
}

// Server is the bridge's link listener.
type Server struct {
	StaticPrivate []byte // this bridge's X25519 private key (32 bytes)
	KeeperPublic  []byte // the one peer key that completes the handshake
	Handler       Handler
	Log           zerolog.Logger

	// HandshakeTimeout bounds the handshake and the first request.
	HandshakeTimeout time.Duration
	// IdleTimeout closes a connection with no frame for this long.
	IdleTimeout time.Duration
	// MaxConns bounds open sockets (authenticated or not).
	MaxConns int
	// MaxPending bounds requests queued on one connection.
	MaxPending int

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	ln     net.Listener
	closed bool
	wg     sync.WaitGroup
}

func (s *Server) defaults() {
	if s.HandshakeTimeout == 0 {
		s.HandshakeTimeout = 5 * time.Second
	}
	if s.IdleTimeout == 0 {
		s.IdleTimeout = 120 * time.Second
	}
	if s.MaxConns == 0 {
		s.MaxConns = 4
	}
	if s.MaxPending == 0 {
		s.MaxPending = 16
	}
}

// PublicKey derives the X25519 public key of a private key.
func PublicKey(private []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ln net.Listener) error {
	s.defaults()
	if len(s.KeeperPublic) != 32 {
		return fmt.Errorf("keeper public key must be 32 bytes")
	}
	if _, err := PublicKey(s.StaticPrivate); err != nil {
		return fmt.Errorf("bad link private key")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.ln = ln
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.mu.Unlock()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		s.mu.Lock()
		if s.closed || len(s.conns) >= s.MaxConns {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			s.serveConn(conn)
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
		}()
	}
}

// Close stops the listener and every connection, and waits for handlers.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	if s.ln != nil {
		s.ln.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// ReadFrame reads one u16-length-prefixed frame; a zero length is an error.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return nil, errors.New("empty frame")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, body []byte) error {
	if len(body) < 1 || len(body) > MaxMessage {
		return errors.New("frame size")
	}
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out, uint16(len(body)))
	copy(out[2:], body)
	_, err := w.Write(out)
	return err
}

// CipherSuite is the channel's Noise suite.
var CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// Respond runs the responder's half of KK on the keeper's first message and
// returns the second message and the transport ciphers (receive, send).
// rng is nil (crypto/rand) outside tests; flynn/noise draws the "e" token's
// key from it and ignores Config.EphemeralKeypair for written tokens.
func Respond(staticPrivate, keeperPublic []byte, rng io.Reader, msg1 []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	if len(msg1) < 48 {
		return nil, nil, nil, errors.New("short handshake message")
	}
	pub, err := PublicKey(staticPrivate)
	if err != nil {
		return nil, nil, nil, err
	}
	cfg := noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeKK,
		Initiator:     false,
		Prologue:      Prologue,
		StaticKeypair: noise.DHKey{Private: staticPrivate, Public: pub},
		PeerStatic:    keeperPublic,
	}
	if rng != nil {
		cfg.Random = rng
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, _, _, err = hs.ReadMessage(nil, msg1); err != nil {
		return nil, nil, nil, err
	}
	msg2, toResponder, toInitiator, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if toResponder == nil || toInitiator == nil {
		return nil, nil, nil, errors.New("handshake incomplete")
	}
	return msg2, toResponder, toInitiator, nil
}

type request struct {
	id     json.Number
	method string
	params json.RawMessage
}

type wireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type reply struct {
	ID     json.Number `json:"id"`
	Result any         `json:"result,omitempty"`
	Error  *wireError  `json:"error,omitempty"`
}

// marshalReply renders {id, result} with an explicit null result.
func marshalReply(id json.Number, result any, err error) []byte {
	if err != nil {
		code := "error"
		var le *Error
		if errors.As(err, &le) {
			code = le.Code
		}
		b, _ := json.Marshal(reply{ID: id, Error: &wireError{Code: code, Message: code}})
		return b
	}
	res, mErr := json.Marshal(result)
	if mErr != nil {
		b, _ := json.Marshal(reply{ID: id, Error: &wireError{Code: "error", Message: "error"}})
		return b
	}
	var buf bytes.Buffer
	buf.WriteString(`{"id":`)
	buf.WriteString(id.String())
	buf.WriteString(`,"result":`)
	buf.Write(res)
	buf.WriteString(`}`)
	return buf.Bytes()
}

func parseRequest(plaintext []byte) (*request, bool) {
	if !utf8.Valid(plaintext) {
		return nil, false
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil || raw == nil {
		return nil, false
	}
	var id json.Number
	if err := json.Unmarshal(raw["id"], &id); err != nil {
		return nil, false
	}
	n, err := id.Int64()
	if err != nil || n > maxSafeInt || n < -maxSafeInt {
		return nil, false
	}
	var method string
	if err := json.Unmarshal(raw["method"], &method); err != nil || len(method) > 128 {
		return nil, false
	}
	params := raw["params"]
	if len(params) == 0 || string(params) == "null" {
		params = json.RawMessage("{}")
	}
	return &request{id: json.Number(fmt.Sprint(n)), method: method, params: params}, true
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	log := s.Log.With().Str("component", "link").Logger()
	refuse := func(reason string) { log.Warn().Str("reason", reason).Msg("channel refused") }

	deadline := time.Now().Add(s.HandshakeTimeout)
	conn.SetDeadline(deadline)
	br := bufio.NewReaderSize(conn, 4096)

	body, err := ReadFrame(br)
	if err != nil || len(body) < 1 || body[0] != hello {
		refuse("handshake")
		return
	}
	msg2, recv, send, err := Respond(s.StaticPrivate, s.KeeperPublic, nil, body[1:])
	if err != nil {
		refuse("handshake")
		return
	}
	if err := WriteFrame(conn, append([]byte{hello}, msg2...)); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reqs := make(chan *request, s.MaxPending)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for req := range reqs {
			result, herr := s.handle(ctx, req)
			out := marshalReply(req.id, result, herr)
			if len(out) > MaxPayload {
				out = marshalReply(req.id, nil, Code("error"))
			}
			ct, err := send.Encrypt(nil, nil, out)
			if err != nil {
				conn.Close()
				return
			}
			conn.SetWriteDeadline(time.Now().Add(s.IdleTimeout))
			if err := WriteFrame(conn, ct); err != nil {
				conn.Close()
				return
			}
		}
	}()

	first := true
	for {
		if !first {
			conn.SetReadDeadline(time.Now().Add(s.IdleTimeout))
		}
		body, err := ReadFrame(br)
		if err != nil {
			break
		}
		plaintext, err := recv.Decrypt(nil, nil, body)
		if err != nil {
			refuse("frame")
			break
		}
		req, ok := parseRequest(plaintext)
		if !ok {
			refuse("request")
			break
		}
		if first {
			first = false
			conn.SetDeadline(time.Time{})
		}
		select {
		case reqs <- req:
		default:
			refuse("over-budget")
			cancel()
			close(reqs)
			<-done
			return
		}
	}
	cancel()
	close(reqs)
	<-done
}

func (s *Server) handle(ctx context.Context, req *request) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.Log.Error().Str("method", req.method).Msg("handler panic")
			result, err = nil, Code("error")
		}
	}()
	return s.Handler.Handle(ctx, req.method, req.params)
}

// --- client (tests, and a Go keeper stand-in) ---

// Client is the keeper's side of the channel (cah.mjs openChannel).
type Client struct {
	conn   net.Conn
	br     *bufio.Reader
	send   *noise.CipherState
	recv   *noise.CipherState
	mu     sync.Mutex
	nextID int64
}

// RemoteError is a coded error answer.
type RemoteError struct{ Code string }

func (e *RemoteError) Error() string { return e.Code }

// Dial opens a channel to the bridge, proving keeperPrivate.
func Dial(addr string, keeperPrivate, bridgePublic []byte) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	pub, err := PublicKey(keeperPrivate)
	if err != nil {
		conn.Close()
		return nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeKK,
		Initiator:     true,
		Prologue:      Prologue,
		StaticKeypair: noise.DHKey{Private: keeperPrivate, Public: pub},
		PeerStatic:    bridgePublic,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := WriteFrame(conn, append([]byte{hello}, msg1...)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	body, err := ReadFrame(br)
	if err != nil || len(body) < 1 || body[0] != hello {
		conn.Close()
		return nil, &RemoteError{Code: "closed"}
	}
	_, toResponder, toInitiator, err := hs.ReadMessage(nil, body[1:])
	if err != nil {
		conn.Close()
		return nil, &RemoteError{Code: "closed"}
	}
	conn.SetDeadline(time.Time{})
	return &Client{conn: conn, br: br, send: toResponder, recv: toInitiator, nextID: 1}, nil
}

// Call sends one request and waits for its reply (one call at a time).
func (c *Client) Call(method string, params any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID
	c.nextID++
	if c.nextID > math.MaxInt32 {
		c.nextID = 1
	}
	body, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		return err
	}
	ct, err := c.send.Encrypt(nil, nil, body)
	if err != nil {
		return err
	}
	if err := WriteFrame(c.conn, ct); err != nil {
		return err
	}
	frame, err := ReadFrame(c.br)
	if err != nil {
		return &RemoteError{Code: "closed"}
	}
	plaintext, err := c.recv.Decrypt(nil, nil, frame)
	if err != nil {
		return &RemoteError{Code: "closed"}
	}
	var rep struct {
		ID     int64           `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *wireError      `json:"error"`
	}
	if err := json.Unmarshal(plaintext, &rep); err != nil {
		return err
	}
	if rep.ID != id {
		return fmt.Errorf("reply id %d for request %d", rep.ID, id)
	}
	if rep.Error != nil {
		return &RemoteError{Code: rep.Error.Code}
	}
	if out != nil && len(rep.Result) > 0 {
		return json.Unmarshal(rep.Result, out)
	}
	return nil
}

// Close closes the channel.
func (c *Client) Close() error { return c.conn.Close() }
