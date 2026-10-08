package xmlenc

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
)

// RSA key transport algorithm URIs, as used in the Algorithm attribute of an
// xenc:EncryptionMethod element.
const (
	RSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	RSAOAEP      = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	RSA15        = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
)

// RSA implements Encrypter and Decrypter using RSA public key encryption.
//
// Use function like OAEP(), or PKCS1v15() to get an instance of this type ready
// to use.
type RSA struct {
	BlockCipher BlockCipher
	Hash        crypto.Hash // only for OAEP; the zero value means SHA-1
	MGFHash     crypto.Hash // only for OAEP; the zero value means Hash
	Label       []byte      // only for OAEP

	algorithm    string
	keyEncrypter func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error)
	keyDecrypter func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error)
}

// effectiveHash returns the OAEP digest hash, applying the SHA-1 default.
func (e RSA) effectiveHash() crypto.Hash {
	return defaultHash(e.Hash)
}

// effectiveMGF returns the OAEP mask generation function hash, defaulting to
// the effective digest hash.
func (e RSA) effectiveMGF() crypto.Hash {
	if e.MGFHash == 0 {
		return e.effectiveHash()
	}
	return e.MGFHash
}

// oaepOptions returns the crypto/rsa options describing the receiver's OAEP
// parameters.
func (e RSA) oaepOptions() *rsa.OAEPOptions {
	return &rsa.OAEPOptions{
		Hash:    e.effectiveHash(),
		MGFHash: e.effectiveMGF(),
		Label:   e.Label,
	}
}

// defaultHash applies the SHA-1 default used by the XML Encryption OAEP
// profiles when no digest is configured.
func defaultHash(h crypto.Hash) crypto.Hash {
	if h == 0 {
		return crypto.SHA1
	}
	return h
}

// Algorithm returns the name of the algorithm
func (e RSA) Algorithm() string {
	return e.algorithm
}

// Encrypt implements encrypter. certificate must be a []byte containing the ASN.1 bytes
// of certificate containing an RSA public key.
func (e RSA) Encrypt(certificate interface{}, plaintext []byte, nonce []byte) (*etree.Element, error) {
	cert, ok := certificate.(*x509.Certificate)
	if !ok {
		return nil, ErrIncorrectKeyType("*x.509 certificate")
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrIncorrectKeyType("x.509 certificate with an RSA public key")
	}

	// generate a key
	key := make([]byte, e.BlockCipher.KeySize())
	if _, err := RandReader.Read(key); err != nil {
		return nil, err
	}

	keyInfoEl := etree.NewElement("ds:KeyInfo")
	keyInfoEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	encryptedKey := keyInfoEl.CreateElement("xenc:EncryptedKey")
	{
		randBuf := make([]byte, 16)
		if _, err := RandReader.Read(randBuf); err != nil {
			return nil, err
		}
		encryptedKey.CreateAttr("Id", fmt.Sprintf("_%x", randBuf))
	}
	encryptedKey.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")

	encryptionMethodEl := encryptedKey.CreateElement("xenc:EncryptionMethod")
	encryptionMethodEl.CreateAttr("Algorithm", e.algorithm)
	encryptionMethodEl.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	if e.algorithm == RSAOAEPMGF1P || e.algorithm == RSAOAEP {
		digestURI, ok := DigestURI(e.effectiveHash())
		if !ok {
			return nil, ErrAlgorithmNotImplemented(e.effectiveHash().String())
		}
		dm := encryptionMethodEl.CreateElement("ds:DigestMethod")
		dm.CreateAttr("Algorithm", digestURI)
		dm.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

		// The RSA-OAEP (2009) profile carries an explicit MGF, whereas the
		// older rsa-oaep-mgf1p profile fixes MGF1 with SHA-1 and forbids the
		// element.
		if e.algorithm == RSAOAEP {
			mgfURI, ok := MGFURI(e.effectiveMGF())
			if !ok {
				return nil, ErrAlgorithmNotImplemented(e.effectiveMGF().String())
			}
			mgf := encryptionMethodEl.CreateElement("xenc11:MGF")
			mgf.CreateAttr("Algorithm", mgfURI)
			mgf.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
		}

		if len(e.Label) > 0 {
			oaepParamsEl := encryptionMethodEl.CreateElement("xenc:OAEPparams")
			oaepParamsEl.SetText(base64.StdEncoding.EncodeToString(e.Label))
		}
	}
	{
		innerKeyInfoEl := encryptedKey.CreateElement("ds:KeyInfo")
		x509data := innerKeyInfoEl.CreateElement("ds:X509Data")
		x509data.CreateElement("ds:X509Certificate").SetText(
			base64.StdEncoding.EncodeToString(cert.Raw),
		)
	}

	buf, err := e.keyEncrypter(e, pubKey, key)
	if err != nil {
		return nil, err
	}

	cd := encryptedKey.CreateElement("xenc:CipherData")
	cd.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	cd.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(buf))
	encryptedDataEl, err := e.BlockCipher.Encrypt(key, plaintext, nonce)
	if err != nil {
		return nil, err
	}
	encryptedDataEl.InsertChildAt(encryptedDataEl.FindElement("./CipherData").Index(), keyInfoEl)

	return encryptedDataEl, nil
}

// Decrypt implements Decryptor. `key` must be an *rsa.PrivateKey.
func (e RSA) Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error) {
	rsaKey, err := validateRSAKeyIfPresent(key, ciphertextEl)
	if err != nil {
		return nil, err
	}

	ciphertext, err := getCiphertext(ciphertextEl)
	if err != nil {
		return nil, err
	}

	return e.keyDecrypter(e, rsaKey, ciphertext)
}

// OAEP returns a version of RSA that implements RSA in OAEP-MGF1P mode. By default
// the block cipher used is AES-256 CBC and the digest method is SHA-1. You can
// specify other ciphers and parameters by assigning to BlockCipher, Hash,
// MGFHash or Label.
//
// OAEP implements the older RSA-OAEP (2001 spec) for backward compatibility, you might
// perfer OAEP_SHA256 over using this method.
func OAEP() RSA {
	return RSA{
		BlockCipher: AES256CBC,
		Hash:        crypto.SHA1,
		MGFHash:     crypto.SHA1,
		algorithm:   RSAOAEPMGF1P,
		keyEncrypter: func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return rsa.EncryptOAEPWithOptions(RandReader, pubKey, plaintext, e.oaepOptions())
		},
		keyDecrypter: func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return privKey.Decrypt(RandReader, ciphertext, e.oaepOptions())
		},
	}
}

// OAEP_SHA256 returns a version of RSA that implements RSA in OAEP mode. By default
// the block cipher used is AES-256 CBC and the digest method is SHA-256. You can
// specify other ciphers and parameters by assigning to BlockCipher, Hash,
// MGFHash or Label.
func OAEP_SHA256() RSA { //nolint:revive
	return RSA{
		BlockCipher: AES256CBC,
		Hash:        crypto.SHA256,
		MGFHash:     crypto.SHA256,
		algorithm:   RSAOAEP,

		keyEncrypter: func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return rsa.EncryptOAEPWithOptions(RandReader, pubKey, plaintext, e.oaepOptions())
		},
		keyDecrypter: func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return privKey.Decrypt(RandReader, ciphertext, e.oaepOptions())
		},
	}
}

// OAEP_SHA512 returns a version of RSA that implements RSA in OAEP mode. By default
// the block cipher used is AES-256 CBC and the digest method is SHA-512. You can
// specify other ciphers and parameters by assigning to BlockCipher, Hash,
// MGFHash or Label.
func OAEP_SHA512() RSA { //nolint:revive
	return RSA{
		BlockCipher: AES256CBC,
		Hash:        crypto.SHA512,
		MGFHash:     crypto.SHA512,
		algorithm:   RSAOAEP,

		keyEncrypter: func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return rsa.EncryptOAEPWithOptions(RandReader, pubKey, plaintext, e.oaepOptions())
		},
		keyDecrypter: func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return privKey.Decrypt(RandReader, ciphertext, e.oaepOptions())
		},
	}
}

// OAEPWithParameters returns an RSA-OAEP encryptor for the given key
// transport algorithm and parameters. The algorithm must be RSAOAEPMGF1P or
// RSAOAEP; for RSAOAEPMGF1P the mask generation function is fixed to SHA-1 and
// no xenc11:MGF element is emitted. A zero Hash or MGFHash means SHA-1.
func OAEPWithParameters(algorithm string, p OAEPParameters) (RSA, error) {
	var e RSA
	switch algorithm {
	case RSAOAEPMGF1P:
		e = OAEP()
	case RSAOAEP:
		e = OAEP_SHA256()
	default:
		return RSA{}, ErrAlgorithmNotImplemented(algorithm)
	}

	e.Hash = p.Hash
	e.MGFHash = p.MGFHash
	e.Label = p.Label
	return e, nil
}

// PKCS1v15 returns a version of RSA that implements RSA in PKCS1v15 mode. By default
// the block cipher used is AES-256 CBC. The Hash, MGFHash and Label fields are ignored
// because PKCS1v15 does not use them.
func PKCS1v15() RSA {
	return RSA{
		BlockCipher: AES256CBC,
		algorithm:   RSA15,
		keyEncrypter: func(_ RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return rsa.EncryptPKCS1v15(RandReader, pubKey, plaintext)
		},
		keyDecrypter: func(_ RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return rsa.DecryptPKCS1v15(RandReader, privKey, ciphertext)
		},
	}
}
