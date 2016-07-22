package brk

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/gob"
	"io"
	"net"
	"sync"
)

// HashSize dictates the standard hash size
const HashSize = 64

// Conn represents a network connection
type Brk struct {
	PrivateKey *rsa.PrivateKey
	blocks     map[[HashSize]byte]*WireBlock
	Blocks     chan *Block // blocks addressed to me
	conns      []*Conn
}

func NewBrk(pk *rsa.PrivateKey) (*Brk, error) {
	b := &Brk{
		PrivateKey: pk,
		blocks:     make(map[[HashSize]byte]*WireBlock),
		Blocks:     make(chan *Block),
	}

	return b, nil
}

type Node struct {
	PublicKey *rsa.PublicKey
}

func (n *Node) ID() ([HashSize]byte, error) {
	b := [HashSize]byte{}
	h := sha512.New()
	if err := gob.NewEncoder(h).Encode(n); err != nil {
		return b, err
	}
	copy(b[:], h.Sum([]byte{}))
	return b, nil
}

type Conn struct {
	Brk  *Brk
	Conn net.Conn
}

func (b *Brk) AddConn(c net.Conn) error {
	// TODO: generate Node from initial message exchange
	// TODO: implement Ping(), Pong() message generation functions
	// for simplified handshake
	conn := &Conn{
		Brk:  b,
		Conn: c,
	}

	// Add to connection map
	b.conns = append(b.conns, conn)

	go func() {
		conn.Listen()
	}()

	return nil
}

type Sender struct {
	*Node
	Brk *Brk
	buf bytes.Buffer
}

func (b *Brk) NewSender(n *Node) io.WriteCloser {
	s := &Sender{
		Node: n,
		Brk:  b,
	}

	return s
}

func (s *Sender) Write(p []byte) (int, error) {
	return s.buf.Write(p)
}

// Write writes bytes as a block message
func (s *Sender) Close() error {
	// Generate a new Block
	blk, err := s.Brk.NewBlock(s.Node, [][HashSize]byte{}, s.buf.Bytes())
	if err != nil {
		return err
	}

	w, err := blk.Encode()
	if err != nil {
		return err
	}

	if err := s.Brk.Broadcast(w); err != nil {
		return err
	}

	return nil
}

func (c *Conn) Send(w *WireBlock) error {
	// Write to network in gob format
	if err := gob.NewEncoder(c.Conn).Encode(w); err != nil {
		return err
	}
	return nil
}

func (c *Conn) Rcv(w *WireBlock) error {
	// Read from network in gob format
	if err := gob.NewDecoder(c.Conn).Decode(w); err != nil {
		return err
	}
	return nil
}

func (b *Brk) Graph(in chan *WireBlock, out chan *WireBlock) {
	// Build graph and emit chains when they become readable

}

func (h *Head) IsTo(n *Node) bool {
	// compare public key
	return h.To.PublicKey.N.Cmp(n.PublicKey.N) == 0 && h.To.PublicKey.E == n.PublicKey.E
}

func (t *Tail) IsFrom(n *Node) bool {
	// compare public key
	return t.From.PublicKey.N.Cmp(n.PublicKey.N) == 0 && t.From.PublicKey.E == n.PublicKey.E
}

func (c *Conn) Listen() {
	for {
		w := &WireBlock{}
		if err := c.Rcv(w); err != nil {
			panic(err)
		}

		go func(w *WireBlock) {

			// Add to blocks
			h, err := w.Hash()
			if err != nil {
				panic(err)
			}

			// Skip if already received this block
			if c.Brk.blocks[h] != nil {
				return
			}

			c.Brk.blocks[h] = w

			// Pass this block to neighbors
			if err := c.Brk.Broadcast(w); err != nil {
				panic(err)
			}

			// See if it is addressed to us
			if w.Head.IsTo(&Node{PublicKey: &c.Brk.PrivateKey.PublicKey}) {
				// Decode and decrypt block
				b, err := c.Brk.Decode(w)
				if err != nil {
					panic(err)
				}

				// Verify signature
				if err := b.Verify(); err != nil {
					panic(err)
				}

				c.Brk.Blocks <- b
			}
		}(w)
	}
}

func (b *Brk) Broadcast(w *WireBlock) error {
	e := make(chan error)
	var wg sync.WaitGroup
	for _, c := range b.conns {
		wg.Add(1)
		go func(c *Conn) {
			defer wg.Done()
			if err := c.Send(w); err != nil {
				e <- err
			}
		}(c)
	}

	wg.Wait()
	close(e)

	for err := range e {
		return err
	}

	return nil
}

type WireBlock struct {
	Head
	Key     []byte // encrypted AES key
	Payload []byte // encrypted encoded payload
}

type Head struct {
	To *Node
}

type Vault struct {
	Parents [][HashSize]byte // Hash of
	Payload []byte
}

type Tail struct {
	From *Node
	Vault
	Signature []byte
}

type Block struct {
	Head
	Tail
}

func (w *WireBlock) Hash() ([HashSize]byte, error) {
	b := [HashSize]byte{}
	h := sha512.New()
	if err := gob.NewEncoder(h).Encode(w); err != nil {
		return b, err
	}
	copy(b[:], h.Sum([]byte{}))
	return b, nil
}

func (b *Block) Encode() (*WireBlock, error) {
	// Generate random key
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}

	// Encrypt key
	ek, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, b.To.PublicKey, k, []byte{})
	if err != nil {
		return nil, err
	}

	// Encrypt payload with AES
	bc, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	bb := &bytes.Buffer{}
	iv := [aes.BlockSize]byte{}
	gob.NewEncoder(cipher.StreamWriter{
		S: cipher.NewOFB(bc, iv[:]),
		W: bb,
	}).Encode(b.Tail)

	w := &WireBlock{
		Head:    b.Head,
		Key:     ek,
		Payload: bb.Bytes(),
	}

	return w, nil
}

func (b *Brk) NewBlock(n *Node, parents [][HashSize]byte, p []byte) (*Block, error) {

	blk := &Block{
		Head: Head{
			To: n,
		},
		Tail: Tail{
			From: &Node{&b.PrivateKey.PublicKey},
			Vault: Vault{
				Parents: parents,
				Payload: p,
			},
		},
	}

	// Generate signature of vault
	bb := &bytes.Buffer{}
	gob.NewEncoder(bb).Encode(blk.Vault)
	h := sha512.Sum512(bb.Bytes())
	s, err := rsa.SignPKCS1v15(rand.Reader, b.PrivateKey, crypto.SHA512, h[:])
	if err != nil {
		return nil, err
	}

	blk.Signature = s

	return blk, nil
}

func (b *Block) Verify() error {
	bb := &bytes.Buffer{}
	gob.NewEncoder(bb).Encode(b.Vault)
	h := sha512.Sum512(bb.Bytes())
	return rsa.VerifyPKCS1v15(b.From.PublicKey, crypto.SHA512, h[:], b.Signature)
}

func (b *Brk) Decode(w *WireBlock) (*Block, error) {
	// Decrypt random key
	k, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, b.PrivateKey, w.Key, []byte{})
	if err != nil {
		return nil, err
	}
	bc, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	iv := [aes.BlockSize]byte{}
	bb := bytes.NewBuffer(w.Payload)
	blk := &Block{
		Head: w.Head,
	}
	if err := gob.NewDecoder(cipher.StreamReader{
		S: cipher.NewOFB(bc, iv[:]),
		R: bb,
	}).Decode(&blk.Tail); err != nil {
		return nil, err
	}
	return blk, nil
}
