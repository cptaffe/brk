package block

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/gob"
)

// HashSize is the size of hashes in this package
const HashSize = 64

// Wire is the decoded wire format
type Wire struct {
	Head
	Key     []byte // encrypted AES key
	Payload []byte // encrypted encoded payload
}

// Head stores the unencrypted header values used to
// route the block
type Head struct {
	To *rsa.PublicKey
}

// Vault stores the signature-validated portion of the block
// NOTE: One solution to the canonical encoding problem is to
// send vault as an encoded byte slice. The signature check is then
// guaranteed to succeed and the vault could be decoded just fine
type Vault struct {
	Parents [][HashSize]byte // Hash of
	Payload []byte
}

// Tail stores the values encrypted in wire format
type Tail struct {
	From *rsa.PublicKey
	Vault
	Signature []byte
}

// Block represents a decrypted wire format block
type Block struct {
	Head
	Tail
}

// IsTo returns whethor or not a header is addressed to a node
func (h *Head) IsTo(k *rsa.PublicKey) bool {
	// compare public key
	return h.To.N.Cmp(k.N) == 0 && h.To.E == k.E
}

// IsFrom compares a Tail section to a node to determine if it was sent
// by that node
func (t *Tail) IsFrom(k *rsa.PublicKey) bool {
	// compare public key
	return t.From.N.Cmp(k.N) == 0 && t.From.E == k.E
}

// Hash returns the hash value of a wire-format block for use
// when referencing parents
func (w *Wire) Hash() ([HashSize]byte, error) {
	b := [HashSize]byte{}
	h := sha512.New()
	if err := gob.NewEncoder(h).Encode(w); err != nil {
		return b, err
	}
	copy(b[:], h.Sum([]byte{}))
	return b, nil
}

// Verify verifies the signature for Vault data
func (b *Block) Verify() error {
	bb := &bytes.Buffer{}
	gob.NewEncoder(bb).Encode(b.Vault)
	h := sha512.Sum512(bb.Bytes())
	return rsa.VerifyPKCS1v15(b.From, crypto.SHA512, h[:], b.Signature)
}

// Encode yeilds a wire-format block from a decrypted block format
func (b *Block) Encode() (*Wire, error) {
	// Generate random key
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}

	// Encrypt key
	ek, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, b.To, k, []byte{})
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

	w := &Wire{
		Head:    b.Head,
		Key:     ek,
		Payload: bb.Bytes(),
	}

	return w, nil
}
