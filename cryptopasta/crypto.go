// Package cryptopasta represents the interface crypto implementation.
package cryptopasta

import (
	"bytes"
	"encoding/base64"
	Cryptopasta "github.com/gtank/cryptopasta"
	"golang.org/x/xerrors"
	"io"
)

// Codec predetermines the consistency of the interfaces crypto implementation.
type Crypto struct {
	key [32]byte
}

// Encrypt - encrypted plain to cipher value.
func (c *Crypto) Encrypt(plain []byte) (cipher []byte, err error) {
	cipher, err = Cryptopasta.Encrypt(plain, &c.key)
	if err != nil {
		return nil, xerrors.Errorf("encrypt plain to cipher error: %w", err)
	}

	return cipher, nil
}

// Decrypt - decrypted cipher to plain value.
func (c *Crypto) Decrypt(cipher []byte) (plain []byte, err error) {
	plain, err = Cryptopasta.Decrypt(cipher, &c.key)
	if err != nil {
		return nil, xerrors.Errorf("decrypt cipher to plain error: %w", err)
	}

	return plain, nil
}

// New is a Crypto constructor.
// Accepts a 256-bit key as a string encoded in standard base64.
func New(key string) (*Crypto, error) {
	srcKey, err := base64.RawStdEncoding.DecodeString(key)
	if err != nil {
		return nil, xerrors.Errorf("base64 decode string error: %w", err)
	}

	dstKey := [32]byte{}
	_, err = io.ReadFull(bytes.NewBuffer(srcKey), dstKey[:])
	if err != nil {
		return nil, xerrors.Errorf("read key value error: %w", err)
	}

	return &Crypto{
		dstKey,
	}, nil
}
