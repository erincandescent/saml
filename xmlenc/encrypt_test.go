package xmlenc

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	"gotest.tools/golden"
)

func TestCanEncryptOAEP(t *testing.T) {
	t.Run("CBC", func(t *testing.T) {

		RandReader = rand.New(rand.NewSource(0)) //nolint:gosec // deterministic random numbers for tests

		pemBlock, _ := pem.Decode(golden.Get(t, "cert.pem"))
		certificate, err := x509.ParseCertificate(pemBlock.Bytes)
		assert.Check(t, err)

		e := OAEP()
		e.BlockCipher = AES128CBC
		e.Hash = crypto.SHA1
		e.MGFHash = crypto.SHA1

		el, err := e.Encrypt(certificate, golden.Get(t, "plaintext.xml"), nil)
		assert.Check(t, err)

		doc := etree.NewDocument()
		doc.SetRoot(el)
		doc.IndentTabs()
		ciphertext, _ := doc.WriteToString()

		golden.Assert(t, ciphertext, "ciphertext.xml")
	})

	t.Run("GCM", func(t *testing.T) {
		certBlock, _ := pem.Decode(golden.Get(t, "cert.cert"))
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		assert.Check(t, err)

		keyBlock, _ := pem.Decode(golden.Get(t, "cert.key"))
		assert.Assert(t, keyBlock != nil)
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		assert.Check(t, err)
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		assert.Assert(t, ok)

		e := OAEP()
		e.BlockCipher = AES128GCM
		e.Hash = crypto.SHA1
		e.MGFHash = crypto.SHA1

		decryptor := NewDecryptor(Key{
			Key:         rsaKey,
			Certificate: certificate,
			OAEP:        OAEPParameters{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
			Ciphers:     []BlockCipher{AES128GCM},
		})

		plaintext := golden.Get(t, "plaintext_gcm.xml")

		// A nil nonce is generated and prefixed to the ciphertext, so the
		// result must round-trip.
		el, err := e.Encrypt(certificate, plaintext, nil)
		assert.Check(t, err)
		got, err := decryptor.Decrypt(el)
		assert.Check(t, err)
		assert.DeepEqual(t, got, plaintext)

		// An explicit nonce must round-trip too.
		el, err = e.Encrypt(certificate, plaintext, []byte("1234567890AZ"))
		assert.Check(t, err)
		got, err = decryptor.Decrypt(el)
		assert.Check(t, err)
		assert.DeepEqual(t, got, plaintext)
	})
}
