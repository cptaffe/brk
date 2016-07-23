package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/cptaffe/brk"
)

// Config holds client configuration options
type Config struct {
	PrivateKey *rsa.PrivateKey `json:"private_key"`
	NoServer   bool            `json:"no_server,omitempty"`
	// Peers list of known nodes
	Peers []string `json:"peers,omitempty"`
	// Friends mapping from nickname to public-key
	Friends map[string]*rsa.PublicKey `json:"friends,omitempty"`
	Server  struct {
		Port int `json:"port,omitempty"`
	} `json:"server,omitempty"`
}

func server(b *brk.Brk, conf *Config) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", conf.Server.Port))
	if err != nil {
		return err
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		if err := b.AddConn(conn); err != nil {
			return err
		}
	}
}

func genConfigPath() (string, error) {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		return "", errors.New("HOME not set")
	}
	return homeDir + "/.config/brk.json", nil
}

func readConfig() (*Config, error) {
	confFile, err := genConfigPath()
	if err != nil {
		return nil, err
	}
	conf := &Config{}
	f, err := os.Open(confFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		if err := json.NewDecoder(f).Decode(conf); err != nil {
			return nil, err
		}
	}
	return conf, nil
}

func writeConfig(conf *Config) error {
	confFile, err := genConfigPath()
	if err != nil {
		return err
	}
	f, err := os.Create(confFile)
	if err != nil {
		return err
	}
	b, err := json.Marshal(conf)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "\t"); err != nil {
		return err
	}
	if _, err := io.Copy(f, &out); err != nil {
		return err
	}
	return nil
}

func main() {
	// Try to open .config/brk.json
	conf, err := readConfig()
	if err != nil {
		log.Fatal(err)
	}

	if conf.PrivateKey == nil {
		// Generate RSA key
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatal(err)
		}

		conf.PrivateKey = k
	}

	if conf.Server.Port == 0 {
		conf.Server.Port = 3030
	}

	if len(conf.Friends) == 0 {
		if conf.Friends == nil {
			conf.Friends = make(map[string]*rsa.PublicKey)
		}
		conf.Friends["self"] = &conf.PrivateKey.PublicKey
	}

	// Write parsed conf version
	if err := writeConfig(conf); err != nil {
		log.Fatal(err)
	}

	b, err := brk.NewBrk(conf.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	if !conf.NoServer {
		fmt.Printf("Serving at %d\n", conf.Server.Port)
		go server(b, conf)
	}

	// Connect to some peers?
	for _, peerAddr := range conf.Peers {
		nc, err := net.Dial("tcp", peerAddr)
		if err != nil {
			log.Fatal(err)
		}

		if err := b.AddConn(nc); err != nil {
			log.Fatal(err)
		}
	}

	// List blocks as they are received
	go func() {
		// Listen for blocks
		for blk := range b.Blocks {
			fmt.Println(string(blk.Payload))
		}
	}()

	r := bufio.NewReader(os.Stdin)
	for {
		s, err := r.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		ss := strings.SplitN(s, ":", 2)
		if len(ss) != 2 {
			log.Print("Expected 'nick: message' format")
			continue
		}

		nick := ss[0]
		msg := strings.Trim(ss[1], "\n\r\t ")

		k := conf.Friends[nick]
		if k == nil {
			log.Printf("Unknown friend '%s'", nick)
			continue
		}

		sndr := b.NewSender(&brk.Node{PublicKey: k})
		if _, err := sndr.Write([]byte(msg)); err != nil {
			log.Fatal(err)
		}
		sndr.Close()
	}
}
