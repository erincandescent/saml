// Package xmlenc is a partial implementation of the xmlenc standard
// as described in https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/Overview.html.
// The purpose of this implementation is to support encrypted SAML assertions.
package xmlenc

import (
	"crypto/rand"

	"github.com/beevik/etree"
)

// RandReader is a thunk that allows test to replace the source of randomness used by
// this package. By default it is Reader from crypto/rand.
var RandReader = rand.Reader

// Encrypter is an interface that encrypts things. Given a plaintext it returns an
// XML EncryptedData or EncryptedKey element. The required type of `key` varies
// depending on the implementation.
type Encrypter interface {
	Encrypt(key interface{}, plaintext []byte, nonce []byte) (*etree.Element, error)
}

// Decrypter is an interface that decrypts things. The Decrypt() method returns the
// plaintext version of the EncryptedData or EncryptedKey element passed.
type Decrypter interface {
	Algorithm() string
	Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error)
}

// BlockCipher implements a cipher with a fixed size key like AES or 3DES.
type BlockCipher interface {
	Encrypter
	Decrypter
	KeySize() int
}
