package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"sync"
)

func sendThread(conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)
	for {
		in, _ := reader.ReadString('\n')
		conn.Write([]byte(in))
	}
}

func recvThread(conn net.Conn, wg *sync.WaitGroup) {
	buf := make([]byte, 1024)
	for {
		r, err := conn.Read(buf)
		if err != nil {
			break
		}
		fmt.Println(string(buf[:r]))
	}
	wg.Done()
}

func main() {
	sock, _ := net.Dial("tcp", "localhost:3333")
	priv, _ := ecdh.Curve.GenerateKey(ecdh.X25519(), rand.Reader)
	pub := priv.PublicKey()
	sock.Write(pub.Bytes())
	buf := make([]byte, 1024)
	readLen, _ := sock.Read(buf)

	remote, _ := ecdh.X25519().NewPublicKey(buf[:readLen])
	shared, _ := priv.ECDH(remote)

	c, _ := aes.NewCipher(shared)
	gcm, _ := cipher.NewGCM(c)

	pt := []byte("foobar")
	nonce := make([]byte, gcm.NonceSize())
	ct := gcm.Seal(nonce, nonce, pt, nil)

	sock.Write(ct)

	var wg sync.WaitGroup
	wg.Add(1)
	go sendThread(sock)
	go recvThread(sock, &wg)

	wg.Wait()
}
