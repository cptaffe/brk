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
	"log"
	"sync"

	"github.com/cptaffe/brk/block"
)

// HashSize dictates the standard hash size
const HashSize = 64

// Brk represents a network connection
type Brk struct {
	PrivateKey  *rsa.PrivateKey
	Blocks      chan *block.Block
	writeBlocks chan *block.Wire
	readBlocks  chan *block.Wire
	conns       chan io.Writer
}

// NewBrk creates a new Brk
func NewBrk(pk *rsa.PrivateKey) (*Brk, error) {
	b := &Brk{
		PrivateKey:  pk,
		readBlocks:  make(chan *block.Wire),
		Blocks:      make(chan *block.Block),
		writeBlocks: make(chan *block.Wire),
		conns:       make(chan io.Writer),
	}

	go b.Broadcast()
	go b.Graph()

	return b, nil
}

// Node represents a sender with a distinct public key
type Node struct {
	PublicKey *rsa.PublicKey
}

// ID returns the idnetifiying hash of a node
func (n *Node) ID() ([HashSize]byte, error) {
	b := [HashSize]byte{}
	h := sha512.New()
	if err := gob.NewEncoder(h).Encode(n); err != nil {
		return b, err
	}
	copy(b[:], h.Sum([]byte{}))
	return b, nil
}

// AddConn adds a ReadWriter connection to the list of adjacent node
// connections
func (b *Brk) AddConn(wr io.ReadWriter) error {
	b.conns <- wr
	go b.Listen(wr)
	return nil
}

// Sender is a helper structure which sends a block to a node
type Sender struct {
	*Node
	Brk *Brk
	buf bytes.Buffer
}

// NewSender constructs a new WriteCloser for sending a block to a node
func (b *Brk) NewSender(n *Node) io.WriteCloser {
	s := &Sender{
		Node: n,
		Brk:  b,
	}

	return s
}

// Write writes to a sender until flushing on close
func (s *Sender) Write(p []byte) (int, error) {
	return s.buf.Write(p)
}

// Close writes bytes as a block message
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

	s.Brk.writeBlocks <- w

	return nil
}

// Graph maintains a graph of all messages received
func (b *Brk) Graph() {
	// Build graph and emit chains when they become readable
	var graphLock sync.Mutex
	graph := map[[HashSize]byte]*block.Wire{}

	for {
		select {
		case w := <-b.readBlocks:
			go func(w *block.Wire) {
				h, err := w.Hash()
				if err != nil {
					log.Print(err)
					return
				}
				if graph[h] != nil {
					graphLock.Lock()
					graph[h] = w
					graphLock.Unlock()
					b.writeBlocks <- w // broadcast
				}

				// See if it is addressed to us
				if w.Head.IsTo(&b.PrivateKey.PublicKey) {
					blk, err := b.Decode(w)
					if err != nil {
						log.Print(err)
						return // can't decode
					}
					if err := blk.Verify(); err != nil {
						log.Print(err)
						return // not verifiable
					}
					b.Blocks <- blk
				}
			}(w)
		}
	}

}

// Listen reads new blocks and propogates them to
// adjacent nodes and the graph
func (b *Brk) Listen(r io.Reader) {
	dec := gob.NewDecoder(r)
	for {
		w := &block.Wire{}
		if err := dec.Decode(w); err != nil {
			log.Print(err)
			continue // ignore decoding errors
		}

		go func(w *block.Wire) {
			b.readBlocks <- w
		}(w)
	}
}

// Broadcast propogates blocks to adjacent nodes
func (b *Brk) Broadcast() {
	conns := []io.Writer{}
	enc := gob.NewEncoder(io.MultiWriter(conns...))
	for {
		select {
		case w := <-b.writeBlocks:
			// Write to network in gob format
			if err := enc.Encode(w); err != nil {
				log.Print(err)
				continue
			}
			// Add to graph
			b.readBlocks <- w
		case w := <-b.conns:
			conns = append(conns, w)
			enc = gob.NewEncoder(io.MultiWriter(conns...))
		}
	}
}

// NewBlock returns a new unencrypted block
// which will be routed to n, child of parents, and contain payload p
func (b *Brk) NewBlock(n *Node, parents [][HashSize]byte, p []byte) (*block.Block, error) {
	blk := &block.Block{
		Head: block.Head{
			To: n.PublicKey,
		},
		Tail: block.Tail{
			From: &b.PrivateKey.PublicKey,
			Vault: block.Vault{
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

// Decode decrypts a wire-format block into a block
// NOTE: this will only succeed if this node is the recipient
func (b *Brk) Decode(w *block.Wire) (*block.Block, error) {
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
	blk := &block.Block{
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
