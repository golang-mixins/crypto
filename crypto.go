// Package crypto presents interface (and its implementation sets) of a crypto functions.
package crypto

// Encryptor provides encrypted plain to cipher value.
type Encryptor interface {
	// Encrypt - encrypted plain to cipher value.
	Encrypt(plain []byte) (cipher []byte, err error)
}

// Decryptor provides decrypted cipher to plain value.
type Decryptor interface {
	// Decrypt - decrypted cipher to plain value.
	Decrypt(cipher []byte) (plain []byte, err error)
}
