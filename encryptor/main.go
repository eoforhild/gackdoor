package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
)

func main() {
	pt, err := os.ReadFile("gackdoor")
	if err != nil {
		fmt.Println("Cannot find specifed file")
		os.Exit(1)
	}

	key := make([]byte, 32)
	rand.Read(key)

	c, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(c)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	encrypted := gcm.Seal(nonce, nonce, pt, nil)
	println()
	toOutput := append(key, encrypted...)
	os.WriteFile("encGack", toOutput, 0777)
}
