package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/cptaffe/brk"
)

// serve on random ports
func server(c chan<- bool, r *rsa.PublicKey) error {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	b, err := brk.NewBrk(k)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := net.Listen("tcp", ":3030")
	if err != nil {
		return err
	}
	c <- true
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			if err := b.AddConn(conn); err != nil {
				panic(err)
			}

			s := b.NewSender(&brk.Node{PublicKey: r})
			if err := gob.NewEncoder(s).Encode("Hey!"); err != nil {
				panic(err)
			}
			s.Close()

			for blk := range b.Blocks {
				var str string
				if err := gob.NewDecoder(bytes.NewBuffer(blk.Payload)).Decode(&str); err != nil {
					log.Fatal(err)
				}

				s := b.NewSender(blk.From)
				if err := gob.NewEncoder(s).Encode(str); err != nil {
					panic(err)
				}
				s.Close()
			}
		}(conn)
	}
}

func main() {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	b, err := brk.NewBrk(k)
	if err != nil {
		log.Fatal(err)
	}

	c := make(chan bool)
	go server(c, &k.PublicKey)
	<-c // server is listening

	nc, err := net.Dial("tcp", "127.0.0.1:3030")
	if err != nil {
		log.Fatal(err)
	}

	if err := b.AddConn(nc); err != nil {
		log.Fatal(err)
	}

	// Listen for messages
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			j := 0
			for blk := range b.Blocks {
				// Decode message
				str := ""
				if err := gob.NewDecoder(bytes.NewBuffer(blk.Payload)).Decode(&str); err != nil {
					log.Fatal(err)
				}

				// Echo client
				s := b.NewSender(blk.From)
				if err := gob.NewEncoder(s).Encode(fmt.Sprint(i, j)); err != nil {
					panic(err)
				}
				s.Close()
				j++
				fmt.Println(str)
			}
		}(i)
	}
	wg.Wait()
}
