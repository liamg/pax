package pax

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func encrypt(input, key []byte) ([]byte, error) {

	plaintext, err := pkcs7Pad(input, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	xored := xor(iv, plaintext[:aes.BlockSize])
	block.Encrypt(ciphertext[aes.BlockSize:aes.BlockSize*2], xored)

	blockCount := len(plaintext) / aes.BlockSize

	for i := 1; i < blockCount; i++ {
		xored := xor(
			ciphertext[((i)*aes.BlockSize):((i+1)*aes.BlockSize)],
			plaintext[i*aes.BlockSize:((i+1)*aes.BlockSize)],
		)
		block.Encrypt(ciphertext[((i+1)*aes.BlockSize):((i+2)*aes.BlockSize)], xored)
	}

	return ciphertext, nil
}

func decrypt(encrypted, key []byte) ([]byte, error) {

	if len(encrypted) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted data is smaller than block size")
	}

	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted data is not a multiple of block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	output := make([]byte, len(encrypted))

	block.Decrypt(output[0:aes.BlockSize], encrypted[0:aes.BlockSize])
	xored := xor(iv, output[0:aes.BlockSize])
	copy(output[0:aes.BlockSize], xored)

	blockCount := len(encrypted) / aes.BlockSize

	for i := 1; i < blockCount; i++ {
		block.Decrypt(output[i*aes.BlockSize:(i+1)*aes.BlockSize], encrypted[i*aes.BlockSize:(i+1)*aes.BlockSize])
		xored := xor(encrypted[(i-1)*aes.BlockSize:i*aes.BlockSize], output[i*aes.BlockSize:(i+1)*aes.BlockSize])
		copy(output[i*aes.BlockSize:(i+1)*aes.BlockSize], xored)
	}

	return pkcs7Unpad(output[:len(output)], aes.BlockSize)
}

func xor(a, b []byte) []byte {
	output := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		output[i] = a[i] ^ b[i]
	}
	return output
}

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}
