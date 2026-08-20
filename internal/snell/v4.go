package snell

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/soffchen/oixproxy/internal/identity"
)

const (
	Version4 = 4

	cmdConnect   byte = 1
	cmdConnectV2 byte = 5
	cmdUDP       byte = 6
	cmdTunnel    byte = 0
	cmdError     byte = 2

	headerVersion byte = 1

	saltSize         = 16
	nonceSize        = 12
	headerPlainSize  = 7
	headerCipherSize = headerPlainSize + 16
	maxPayload       = 0x3FFF
	frameSize        = 1460
	initialPadMin    = 0x100
	initialPadSpan   = 0x100
)

func kdf(psk, salt []byte) []byte {
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Conn is a Snell v4 stream. When exporter is set, the first client frame
// carries a DLSNID02 identity prefix after the salt (inside the TLS record).
type Conn struct {
	net.Conn
	psk             []byte
	exporter        []byte
	identityVersion int
	r               *v4Reader
	w               *v4Writer
	reply           bool
}

func NewConn(raw net.Conn, psk, exporter []byte) *Conn {
	return NewConnIdentity(raw, psk, exporter, 2)
}

func NewConnIdentity(raw net.Conn, psk, exporter []byte, identityVersion int) *Conn {
	if identityVersion == 0 {
		identityVersion = 2
	}
	return &Conn{
		Conn:            raw,
		psk:             append([]byte(nil), psk...),
		exporter:        append([]byte(nil), exporter...),
		identityVersion: identityVersion,
	}
}

func (c *Conn) initWriter() error {
	w, err := newWriter(c.Conn, c.psk, c.exporter, c.identityVersion)
	if err != nil {
		return err
	}
	c.w = w
	return nil
}

func (c *Conn) initReader() error {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, err := newAESGCM(kdf(c.psk, salt))
	if err != nil {
		return err
	}
	c.r = &v4Reader{r: c.Conn, aead: aead}
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.ReadReply(); err != nil {
		return 0, err
	}
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *Conn) ReadReply() error {
	if c.reply {
		return nil
	}
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return err
		}
	}
	var cmd [1]byte
	if _, err := io.ReadFull(c.r, cmd[:]); err != nil {
		return err
	}
	c.reply = true
	switch cmd[0] {
	case cmdTunnel:
		return nil
	case cmdError:
		var rest [2]byte
		if _, err := io.ReadFull(c.r, rest[:]); err != nil {
			return err
		}
		msg := make([]byte, int(rest[1]))
		if _, err := io.ReadFull(c.r, msg); err != nil {
			return err
		}
		return fmt.Errorf("snell server code %d: %s", rest[0], msg)
	default:
		return fmt.Errorf("snell unexpected reply %d", cmd[0])
	}
}

// WriteConnect sends a TCP CONNECT (or reuse CONNECT-V2) request.
func (c *Conn) WriteConnect(host string, port uint16, reuse bool) error {
	if len(host) > 255 {
		return errors.New("snell host too long")
	}
	cmd := cmdConnect
	if reuse {
		cmd = cmdConnectV2
	}
	buf := make([]byte, 0, 5+len(host)+2)
	buf = append(buf, headerVersion, cmd, 0, byte(len(host)))
	buf = append(buf, host...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	buf = append(buf, p[:]...)
	_, err := c.Write(buf)
	return err
}

func (c *Conn) WriteUDP() error {
	_, err := c.Write([]byte{headerVersion, cmdUDP, 0})
	return err
}

type v4Reader struct {
	r     io.Reader
	aead  cipher.AEAD
	nonce [nonceSize]byte
	buf   []byte
	mu    sync.Mutex
}

func (r *v4Reader) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		payload, err := r.readFrame()
		if err != nil {
			return 0, err
		}
		r.buf = payload
	}
	n := copy(b, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *v4Reader) readFrame() ([]byte, error) {
	headerCipher := make([]byte, headerCipherSize)
	if _, err := io.ReadFull(r.r, headerCipher); err != nil {
		return nil, err
	}
	header, err := r.aead.Open(headerCipher[:0], r.nonce[:], headerCipher, nil)
	incNonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	if len(header) != headerPlainSize || header[0] != 4 {
		return nil, errors.New("snell v4 invalid frame header")
	}
	padLen := int(binary.BigEndian.Uint16(header[3:5]))
	payLen := int(binary.BigEndian.Uint16(header[5:7]))
	if payLen == 0 {
		if padLen != 0 {
			return nil, errors.New("snell v4 zero chunk with padding")
		}
		return nil, io.EOF
	}
	if payLen > maxPayload || padLen > maxPayload {
		return nil, errors.New("snell v4 frame too large")
	}
	frame := make([]byte, padLen+payLen+r.aead.Overhead())
	if _, err := io.ReadFull(r.r, frame); err != nil {
		return nil, err
	}
	if padLen > 0 {
		swapPadding(frame[:padLen], frame[padLen:])
	}
	payload, err := r.aead.Open(frame[padLen:padLen], r.nonce[:], frame[padLen:], nil)
	incNonce(r.nonce[:])
	return payload, err
}

type v4Writer struct {
	w               io.Writer
	aead            cipher.AEAD
	nonce           [nonceSize]byte
	salt            [saltSize]byte
	exporter        []byte
	psk             []byte
	identityVersion int
	saltSent        bool
	initPad         uint16
	payLimit        uint16
	lastWrite       time.Time
	mu              sync.Mutex
}

func newWriter(w io.Writer, psk, exporter []byte, identityVersion int) (*v4Writer, error) {
	var salt [saltSize]byte
	if _, err := io.ReadFull(cryptorand.Reader, salt[:]); err != nil {
		return nil, err
	}
	aead, err := newAESGCM(kdf(psk, salt[:]))
	if err != nil {
		return nil, err
	}
	delta, err := randInt(initialPadSpan)
	if err != nil {
		return nil, err
	}
	return &v4Writer{
		w:               w,
		aead:            aead,
		salt:            salt,
		exporter:        append([]byte(nil), exporter...),
		psk:             append([]byte(nil), psk...),
		identityVersion: identityVersion,
		initPad:         uint16(initialPadMin + delta),
	}, nil
}

func (w *v4Writer) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(b) == 0 {
		return 0, w.writeFrame(nil, 0)
	}
	written := 0
	for written < len(b) {
		limit := int(w.nextPayloadLimit())
		if limit <= 0 || limit > maxPayload {
			limit = maxPayload
		}
		end := written + limit
		if end > len(b) {
			end = len(b)
		}
		pad := 0
		if !w.saltSent {
			pad = int(w.initPad)
		}
		if err := w.writeFrame(b[written:end], pad); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (w *v4Writer) nextPayloadLimit() uint16 {
	now := time.Now()
	var limit uint16
	switch {
	case w.lastWrite.IsZero():
		limit = uint16(int(frameSize) - 55 - int(w.initPad))
	case now.Sub(w.lastWrite) > 30*time.Second:
		limit = frameSize - 39
	default:
		limit = w.payLimit
	}
	w.lastWrite = now
	next := int(limit) + frameSize - 39
	if next > maxPayload {
		next = maxPayload
	}
	w.payLimit = uint16(next)
	return limit
}

func (w *v4Writer) writeFrame(payload []byte, padLen int) error {
	if len(payload) > maxPayload || padLen > maxPayload {
		return errors.New("snell v4 frame too large")
	}
	if len(payload) == 0 && padLen != 0 {
		return errors.New("snell v4 zero chunk with padding")
	}

	header := make([]byte, headerPlainSize)
	header[0] = 4
	binary.BigEndian.PutUint16(header[3:5], uint16(padLen))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))
	headerCipher := w.aead.Seal(nil, w.nonce[:], header, nil)
	incNonce(w.nonce[:])

	var payloadCipher []byte
	if len(payload) > 0 {
		payloadCipher = w.aead.Seal(nil, w.nonce[:], payload, nil)
		incNonce(w.nonce[:])
	}

	var prefix []byte
	if !w.saltSent {
		prefix = append(prefix, w.salt[:]...)
		switch w.identityVersion {
		case 1:
			prefix = append(prefix, identity.PrefixV1(w.psk)...)
		default:
			if len(w.exporter) == identity.ExporterSize {
				id, err := identity.PrefixV2(w.psk, w.exporter, w.salt[:])
				if err != nil {
					return err
				}
				prefix = append(prefix, id...)
			}
		}
		w.saltSent = true
	}

	var padding []byte
	if padLen > 0 {
		var err error
		padding, err = makePadding(payloadCipher, padLen)
		if err != nil {
			return err
		}
		swapPadding(padding, payloadCipher)
	}

	frame := make([]byte, 0, len(prefix)+len(headerCipher)+len(padding)+len(payloadCipher))
	frame = append(frame, prefix...)
	frame = append(frame, headerCipher...)
	frame = append(frame, padding...)
	frame = append(frame, payloadCipher...)
	_, err := w.w.Write(frame)
	return err
}

func swapPadding(padding, payloadCipher []byte) {
	limit := len(padding)
	if len(payloadCipher) < limit {
		limit = len(payloadCipher)
	}
	for i := 0; i < limit; i += 2 {
		padding[i], payloadCipher[i] = payloadCipher[i], padding[i]
	}
}

func makePadding(payloadCipher []byte, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	ones := 0
	limit := len(payloadCipher) &^ 3
	for _, b := range payloadCipher[:limit] {
		ones += bits.OnesCount8(b)
	}
	zeros := 8*len(payloadCipher) - ones
	if zeros <= 0 {
		return randomBytes(n)
	}
	ratio := float64(ones) / float64(zeros)
	if ratio <= 0.5 || ratio >= 1.6 {
		return randomBytes(n)
	}
	targetBase := 1.6
	if zeros < ones {
		targetBase = 0.4
	}
	j, err := randUnit()
	if err != nil {
		return nil, err
	}
	target := targetBase + j/10
	totalBits := 8 * (n + len(payloadCipher))
	targetOnes := int(float64(totalBits)*(target/(target+1)) - float64(ones))
	if targetOnes < 0 || targetOnes > 8*n {
		return randomBytes(n)
	}
	return bitCountPadding(n, targetOnes)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(cryptorand.Reader, b)
	return b, err
}

func bitCountPadding(length, oneBits int) ([]byte, error) {
	total := 8 * length
	bits := make([]byte, total)
	for i := 0; i < oneBits; i++ {
		bits[i] = 1
	}
	for i := total - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return nil, err
		}
		bits[i], bits[j] = bits[j], bits[i]
	}
	out := make([]byte, length)
	for i, bit := range bits {
		if bit == 1 {
			out[i/8] |= 1 << uint(i%8)
		}
	}
	return out, nil
}

func randInt(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func randUnit() (float64, error) {
	n, err := cryptorand.Int(cryptorand.Reader, new(big.Int).Lsh(big.NewInt(1), 53))
	if err != nil {
		return 0, err
	}
	return float64(n.Int64()) / (1 << 53), nil
}

func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}
