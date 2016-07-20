package main

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"

	"golang.org/x/crypto/sha3"

	irc "gopkg.in/sorcix/irc.v2"
)

// Message structure
type Message struct {
	Message string `json:"message"`
}

// Encode returns a message from a Message
func (m *Message) Encode() ([]byte, error) {
	b := &bytes.Buffer{}
	if err := json.NewEncoder(b).Encode(m); err != nil {
		return []byte{}, err
	}

	z := &bytes.Buffer{}
	w := zlib.NewWriter(z)
	_, err := w.Write(b.Bytes())
	if err != nil {
		return []byte{}, err
	}
	w.Close()

	b64 := make([]byte, base64.RawStdEncoding.EncodedLen(len(z.Bytes())))
	base64.RawStdEncoding.Encode(b64, z.Bytes())
	return b64, nil
}

// DecodeMessage returns a message from an irc message
func DecodeMessage(b []byte) (*Message, error) {
	b64 := make([]byte, base64.RawStdEncoding.DecodedLen(len(b)))
	base64.RawStdEncoding.Decode(b64, b)
	// Zip
	z, err := zlib.NewReader(bytes.NewBuffer(b64))
	if err != nil {
		return nil, err
	}
	// Decode message
	msg := &Message{}
	if err := json.NewDecoder(z).Decode(msg); err != nil {
		return nil, err
	}
	z.Close()
	return msg, nil
}

// Bot represents the bot
type Bot struct {
	Nick     string
	Chan     string
	Users    map[string][]byte
	Messages <-chan *irc.Message
	conn     *irc.Conn
	key      *rsa.PrivateKey
}

// NewBot returns an initialized bot
func NewBot(conn *irc.Conn) (*Bot, error) {
	mc := make(chan *irc.Message)

	// Channel is a hash of some shared information
	hash := make([]byte, 12)
	sha3.ShakeSum256(hash, []byte("connor+dylan"))
	channel := "#" + base64.RawURLEncoding.EncodeToString(hash)

	// Generate private key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// JSON encoded base64'd public key serves as nick
	jpk, err := json.Marshal(key.Public())
	if err != nil {
		return nil, err
	}
	nick := make([]byte, base64.RawURLEncoding.EncodedLen(len(jpk)))
	base64.RawURLEncoding.Encode(nick, jpk)

	b := &Bot{
		Nick:     string(nick[:16]), // First 16 bytes
		Chan:     channel,
		Messages: mc,
		conn:     conn,
		key:      key,
	}

	go b.Listen(mc)

	go func() {

		if err := b.connect(channel); err != nil {
			log.Fatal(err)
		}

		// Identify with public key
		mb, err := (&Message{
			Message: "hey!",
		}).Encode()
		if err != nil {
			log.Fatal(err)
		}

		// Send initial message
		if _, err := b.Write(mb); err != nil {
			log.Print(err)
		}

		// Churn through write requests
	}()

	return b, nil
}

// Write 128-byte blocks for every IRC message
func (b *Bot) Write(buf []byte) (int, error) {
	// Write in 128-byte chunks in as privmsg's to recipient
	// Write to channel
	const step = 128
	for i := 0; i < len(buf); i += step {
		if err := b.conn.Encode(&irc.Message{
			Command: irc.PRIVMSG,
			Params:  []string{b.Chan, string(buf[i:int(math.Min(float64(i+step), float64(len(buf))))])},
		}); err != nil {
			log.Print(err)
		}
	}

	// End of message marker
	if err := b.conn.Encode(&irc.Message{
		Command: irc.PRIVMSG,
		Params:  []string{b.Chan, "EOM"},
	}); err != nil {
		log.Print(err)
	}

	return 0, nil
}

// Listen listens and responds to messages
func (b *Bot) Listen(c chan<- *irc.Message) error {
	for {
		msg, err := b.conn.Decode()
		if err != nil {
			log.Fatal(err)
		}
		// Handle pings
		if msg.Command == irc.PING {
			if err := b.conn.Encode(&irc.Message{
				Command: irc.PONG,
				Params:  msg.Params,
			}); err != nil {
				log.Fatal(err)
			}
		} else {
			c <- msg
		}
	}
}

// Channel connects a bot to a channel
func (b *Bot) connect(channel string) error {
	// Generate a random password
	in := make([]byte, 64)
	rand.Read(in)
	pass := make([]byte, base32.StdEncoding.EncodedLen(len(in)))
	base32.StdEncoding.Encode(pass, in)

	if err := b.conn.Encode(&irc.Message{
		Command: irc.PASS,
		Params:  []string{string(pass)},
	}); err != nil {
		return err
	}

	if err := b.conn.Encode(&irc.Message{
		Command: irc.NICK,
		Params:  []string{b.Nick},
	}); err != nil {
		return err
	}

	if err := b.conn.Encode(&irc.Message{
		Command: irc.USER,
		Params:  []string{b.Nick, "0", b.Nick, b.Nick},
	}); err != nil {
		return err
	}

	if err := b.conn.Encode(&irc.Message{
		Command: irc.JOIN,
		Params:  []string{channel},
	}); err != nil {
		return err
	}

	return nil
}

func main() {
	conn, err := irc.Dial("irc.freenode.net:6667")
	if err != nil {
		log.Fatal(err)
	}

	b, err := NewBot(conn)
	if err != nil {
		log.Fatal(err)
	}

	for msg := range b.Messages {
		if msg.Command != irc.RPL_MOTD {
			fmt.Println(msg)
		}
		if msg.Command == irc.PRIVMSG {
			m, err := DecodeMessage([]byte(msg.Params[1]))
			if err != nil {
				log.Print(err)
				continue
			}

			if err := b.conn.Encode(&irc.Message{
				Command: irc.PRIVMSG,
				Params:  []string{msg.Prefix.Name, m.Message},
			}); err != nil {
				log.Print(err)
				continue
			}

			fmt.Println(m)
		}
	}

}
