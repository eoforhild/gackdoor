package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"net"
)

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

	pt := []byte("My Super Secret Code Stuf")
	nonce := make([]byte, gcm.NonceSize())
	ct := gcm.Seal(nonce, nonce, pt, nil)
	for _, b := range ct {
		fmt.Print(b, " ")
	}
	sock.Write(ct)
}
