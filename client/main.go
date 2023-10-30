package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/hkdf"
)

func seal(msg []byte, info []byte, gcm cipher.AEAD, hmacKey []byte) []byte {
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	hm := hmac.New(sha256.New, hmacKey)
	hm.Write(info)
	mac := hm.Sum(nil)
	ct := gcm.Seal(nonce, nonce, msg, mac)
	return ct
}

func open(buf []byte, info []byte, gcm cipher.AEAD, hmacKey []byte) ([]byte, error) {
	nonce := buf[:gcm.NonceSize()]
	ct := buf[gcm.NonceSize():]
	hm := hmac.New(sha256.New, hmacKey)
	hm.Write(info)
	mac := hm.Sum(nil)
	return gcm.Open(nil, nonce, ct, mac)
}

func sendThread(conn net.Conn, gcm cipher.AEAD, hmacKey []byte) {
	reader := bufio.NewReader(os.Stdin)
	for {
		in, _ := reader.ReadString('\n')
		conn.Write([]byte(in))
	}
}

func recvThread(conn net.Conn, gcm cipher.AEAD, hmacKey []byte, wg *sync.WaitGroup) {
	buf := make([]byte, 1052)
	for {
		r, err := conn.Read(buf)
		if err != nil {
			break
		}
		tempBuf := buf[:r]
		info := []byte(conn.RemoteAddr().String() + conn.LocalAddr().String())
		pt, err := open(tempBuf, info, gcm, hmacKey)
		if err != nil {
			fmt.Println("err")
			break
		}
		fmt.Print(string(pt))
	}
	wg.Done()
}

func main() {
	// Begin connection
	conn, _ := net.Dial("tcp", "localhost:3333")

	// Generate private and public keys
	priv, _ := ecdh.Curve.GenerateKey(ecdh.X25519(), rand.Reader)
	pub := priv.PublicKey()

	defer conn.Close()

	// Send the server our public key
	conn.Write(pub.Bytes())

	// Read in the server's public key and derive the shared secret
	buf := make([]byte, 1024)
	readLen, _ := conn.Read(buf)
	remote, _ := ecdh.X25519().NewPublicKey(buf[:readLen])
	shared, _ := priv.ECDH(remote)

	// Derive the AES key and HMAC key
	kdf := hkdf.New(sha256.New, shared, nil, nil)
	var gcmKey [32]byte
	var hmacKey [32]byte
	kdf.Read(gcmKey[:])
	kdf.Read(hmacKey[:])

	// Make the AES cipher
	c, _ := aes.NewCipher(gcmKey[:])
	gcm, _ := cipher.NewGCM(c)

	// Send the magic word, TODO. make it parameterizable
	pt := []byte("foobar")
	info := []byte(conn.RemoteAddr().String() + conn.LocalAddr().String())
	ct := seal(pt, info, gcm, hmacKey[:])
	conn.Write(ct)

	// Read the ack from server
	readLen, _ = conn.Read(buf)
	if string(buf[:readLen]) != "ack" {
		conn.Close()
		return
	}

	// Start threads for handling connection
	var wg sync.WaitGroup
	wg.Add(1)
	go sendThread(conn, gcm, hmacKey[:])
	go recvThread(conn, gcm, hmacKey[:], &wg)
	wg.Wait()
}
