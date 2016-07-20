package main

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	irc "gopkg.in/sorcix/irc.v2"
)

// Message structure
type Message struct {
	Message string `json:"message"`
}

// ToMessage returns a message from a Message
func (m *Message) ToMessage() (string, error) {
	b := &bytes.Buffer{}
	if err := json.NewEncoder(b).Encode(m); err != nil {
		return "", err
	}

	z := &bytes.Buffer{}
	w := zlib.NewWriter(z)
	_, err := w.Write(b.Bytes())
	if err != nil {
		return "", err
	}
	w.Close()

	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(z.Bytes())))
	base64.StdEncoding.Encode(b64, z.Bytes())
	return string(b64), nil
}

// FromMessage returns a message from an irc message
func FromMessage(m *irc.Message) (*Message, error) {
	b64 := make([]byte, base64.StdEncoding.DecodedLen(len([]byte(m.Params[1]))))
	base64.StdEncoding.Decode(b64, []byte(m.Params[1]))
	fmt.Println(m.Params[1], "->", string(b64))
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
	Messages <-chan *irc.Message
	conn     *irc.Conn
}

// NewBot returns an initialized bot
func NewBot(conn *irc.Conn) (*Bot, error) {
	in := make([]byte, 12)
	rand.Read(in)
	nick := make([]byte, base32.StdEncoding.EncodedLen(len(in)))
	base32.StdEncoding.Encode(nick, in)

	mc := make(chan *irc.Message)

	b := &Bot{
		Nick:     string(nick),
		Messages: mc,
		conn:     conn,
	}

	go b.Listen(mc)

	return b, nil
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

// Encode encodes a message on Bot's channel
func (b *Bot) Encode(m *irc.Message) error {
	return b.conn.Encode(m)
}

// Channel connects a bot to a channel
func (b *Bot) Channel(channel string) error {
	// Generate a random password
	in := make([]byte, 64)
	rand.Read(in)
	pass := make([]byte, base32.StdEncoding.EncodedLen(len(in)))
	base32.StdEncoding.Encode(pass, in)

	if err := b.Encode(&irc.Message{
		Command: irc.PASS,
		Params:  []string{string(pass)},
	}); err != nil {
		return err
	}

	if err := b.Encode(&irc.Message{
		Command: irc.NICK,
		Params:  []string{b.Nick},
	}); err != nil {
		return err
	}

	if err := b.Encode(&irc.Message{
		Command: irc.USER,
		Params:  []string{b.Nick, "0", b.Nick, b.Nick},
	}); err != nil {
		return err
	}

	if err := b.Encode(&irc.Message{
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

	sum := sha1.Sum([]byte("connor+dylan"))
	channel := "#" + base64.URLEncoding.EncodeToString(sum[:])

	go func() {
		if err := b.Channel(channel); err != nil {
			log.Fatal(err)
		}

		// Compose message
		s, err := (&Message{
			Message: "hey!",
		}).ToMessage()
		if err != nil {
			log.Fatal(err)
		}

		// Send initial message
		if err := b.conn.Encode(&irc.Message{
			Command: irc.PRIVMSG,
			Params:  []string{channel, s},
		}); err != nil {
			log.Print(err)
		}
	}()

	for msg := range b.Messages {
		fmt.Println(msg)
		if msg.Command == irc.PRIVMSG {
			m, err := FromMessage(msg)
			if err != nil {
				log.Print(err)
				continue
			}

			if err := b.conn.Encode(&irc.Message{
				Command: irc.PRIVMSG,
				Params:  []string{channel, m.Message},
			}); err != nil {
				log.Print(err)
				continue
			}
		}
	}

}
