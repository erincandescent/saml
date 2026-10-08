package xmlenc

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// ErrAlgorithmNotImplemented is returned when encryption used is not
// supported.
type ErrAlgorithmNotImplemented string

func (e ErrAlgorithmNotImplemented) Error() string {
	return "algorithm is not implemented: " + string(e)
}

// ErrCannotFindRequiredElement is returned by Decrypt when a required
// element cannot be found.
type ErrCannotFindRequiredElement string

func (e ErrCannotFindRequiredElement) Error() string {
	return "cannot find required element: " + string(e)
}

// ErrIncorrectTag is returned when Decrypt is passed an element which
// is neither an EncryptedType nor an EncryptedKey
var ErrIncorrectTag = fmt.Errorf("tag must be an EncryptedType or EncryptedKey")

// ErrIncorrectKeyLength is returned when the fixed length key is not
// of the required length.
type ErrIncorrectKeyLength int

func (e ErrIncorrectKeyLength) Error() string {
	return fmt.Sprintf("expected key to be %d bytes", int(e))
}

// ErrIncorrectKeyType is returned when the key is not the correct type
type ErrIncorrectKeyType string

func (e ErrIncorrectKeyType) Error() string {
	return fmt.Sprintf("expected key to be %s", string(e))
}

// ErrParameterMismatch is returned when the parameters declared by a
// ciphertext do not match the parameters the matching key was configured
// with.
var ErrParameterMismatch = errors.New("xmlenc: ciphertext parameters do not match the configured key")

// OAEPParameters describes the RSA-OAEP parameters a key is configured to
// use. A zero Hash means SHA-1; a zero MGFHash means the effective hash.
type OAEPParameters struct {
	Hash    crypto.Hash
	MGFHash crypto.Hash
	Label   []byte
}

// Key describes a key that a Decryptor may use, together with the metadata
// needed to select it for a given ciphertext.
type Key struct {
	// Key is either an *rsa.PrivateKey (to unwrap an EncryptedKey) or a
	// []byte symmetric key (to decrypt an EncryptedData directly).
	Key any

	// Certificate identifies Key in the ds:KeyInfo of an EncryptedKey.
	Certificate *x509.Certificate

	// OAEP holds the RSA-OAEP parameters Key is configured to use.
	OAEP OAEPParameters

	// Ciphers are the block ciphers that may be used with Key.
	Ciphers []BlockCipher
}

// Decryptor decrypts xmlenc elements using a fixed, caller-configured set of
// keys. The parameters used for decryption are never taken from the
// ciphertext; the parameters it declares are only checked against the
// configuration.
type Decryptor struct {
	keys []Key
}

// NewDecryptor returns a Decryptor that will use the given keys.
func NewDecryptor(keys ...Key) *Decryptor {
	return &Decryptor{keys: keys}
}

// Decrypt decrypts an xenc:EncryptedData or xenc:EncryptedKey element.
func (d *Decryptor) Decrypt(el *etree.Element) ([]byte, error) {
	switch el.Tag {
	case "EncryptedData":
		return d.decryptData(el)
	case "EncryptedKey":
		return d.decryptKey(el)
	default:
		return nil, ErrIncorrectTag
	}
}

func (d *Decryptor) decryptData(el *etree.Element) ([]byte, error) {
	var (
		key      Key
		keyBytes []byte
		found    bool
	)

	if encryptedKeyEl := el.FindElement("./KeyInfo/EncryptedKey"); encryptedKeyEl != nil {
		// The symmetric key is wrapped in an EncryptedKey; select the RSA key
		// by the certificate it advertises and unwrap it.
		k, err := d.keyForElement(encryptedKeyEl)
		if err != nil {
			return nil, err
		}
		keyBytes, err = d.decryptKeyWith(encryptedKeyEl, *k)
		if err != nil {
			return nil, err
		}
		key = *k
		found = true
	} else {
		// The data is encrypted directly with a configured symmetric key.
		for i := range d.keys {
			if _, ok := d.keys[i].Key.([]byte); ok {
				key = d.keys[i]
				keyBytes, _ = key.Key.([]byte)
				found = true
				break
			}
		}
	}
	if !found {
		return nil, ErrCannotFindRequiredElement("key")
	}

	encryptionMethodEl := el.FindElement("./EncryptionMethod")
	if encryptionMethodEl == nil {
		return nil, ErrCannotFindRequiredElement("EncryptionMethod")
	}
	algorithm := encryptionMethodEl.SelectAttrValue("Algorithm", "")
	for _, cipher := range key.Ciphers {
		if cipher.Algorithm() == algorithm {
			return cipher.Decrypt(keyBytes, el)
		}
	}
	return nil, ErrAlgorithmNotImplemented(algorithm)
}

func (d *Decryptor) decryptKey(el *etree.Element) ([]byte, error) {
	key, err := d.keyForElement(el)
	if err != nil {
		return nil, err
	}
	return d.decryptKeyWith(el, *key)
}

func (d *Decryptor) decryptKeyWith(el *etree.Element, key Key) ([]byte, error) {
	if err := validateOAEPParameters(el, key.OAEP); err != nil {
		return nil, err
	}

	decrypter := RSA{
		Hash:    key.OAEP.Hash,
		MGFHash: key.OAEP.MGFHash,
		Label:   key.OAEP.Label,
		keyDecrypter: func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return privKey.Decrypt(RandReader, ciphertext, e.oaepOptions())
		},
	}
	return decrypter.Decrypt(key.Key, el)
}

// keyForElement returns the configured key identified by the certificate
// carried in the ds:KeyInfo of el.
func (d *Decryptor) keyForElement(el *etree.Element) (*Key, error) {
	certEl := el.FindElement("./KeyInfo/X509Data/X509Certificate")
	if certEl == nil {
		return nil, ErrCannotFindRequiredElement("KeyInfo/X509Data/X509Certificate")
	}
	raw, err := decodeBase64(certEl.Text())
	if err != nil {
		return nil, ErrCannotFindRequiredElement("KeyInfo/X509Data/X509Certificate")
	}
	for i := range d.keys {
		if d.keys[i].Certificate != nil && bytes.Equal(d.keys[i].Certificate.Raw, raw) {
			return &d.keys[i], nil
		}
	}
	return nil, ErrCannotFindRequiredElement("key")
}

// validateOAEPParameters checks that the RSA-OAEP parameters declared by an
// EncryptedKey match want. The declared parameters are never used to perform
// the decryption.
func validateOAEPParameters(el *etree.Element, want OAEPParameters) error {
	encryptionMethodEl := el.FindElement("./EncryptionMethod")
	if encryptionMethodEl == nil {
		return ErrCannotFindRequiredElement("EncryptionMethod")
	}

	var declaredMGF crypto.Hash
	switch algorithm := encryptionMethodEl.SelectAttrValue("Algorithm", ""); algorithm {
	case RSAOAEPMGF1P:
		// The 2001 profile fixes MGF1 to SHA-1 and does not allow an MGF
		// element.
		if encryptionMethodEl.FindElement("./MGF") != nil {
			return ErrParameterMismatch
		}
		declaredMGF = crypto.SHA1
	case RSAOAEP:
		mgfURI := MGF1SHA1
		if mgfEl := encryptionMethodEl.FindElement("./MGF"); mgfEl != nil {
			mgfURI = mgfEl.SelectAttrValue("Algorithm", "")
		}
		mgfHash, ok := MGFHash(mgfURI)
		if !ok {
			return ErrParameterMismatch
		}
		declaredMGF = mgfHash
	default:
		return ErrAlgorithmNotImplemented(algorithm)
	}

	digestURI := DigestSHA1
	if digestMethodEl := encryptionMethodEl.FindElement("./DigestMethod"); digestMethodEl != nil {
		digestURI = digestMethodEl.SelectAttrValue("Algorithm", "")
	}
	declaredDigest, ok := DigestHash(digestURI)
	if !ok {
		return ErrParameterMismatch
	}

	wantHash := defaultHash(want.Hash)
	wantMGF := want.MGFHash
	if wantMGF == 0 {
		wantMGF = wantHash
	}
	if declaredDigest != wantHash || declaredMGF != wantMGF {
		return ErrParameterMismatch
	}

	var declaredLabel []byte
	if paramsEl := encryptionMethodEl.FindElement("./OAEPparams"); paramsEl != nil {
		label, err := decodeBase64(paramsEl.Text())
		if err != nil {
			return ErrParameterMismatch
		}
		declaredLabel = label
	}
	if !bytes.Equal(declaredLabel, want.Label) {
		return ErrParameterMismatch
	}
	return nil
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
}

func getCiphertext(encryptedKey *etree.Element) ([]byte, error) {
	ciphertextEl := encryptedKey.FindElement("./CipherData/CipherValue")
	if ciphertextEl == nil {
		return nil, fmt.Errorf("cannot find CipherData element containing a CipherValue element")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertextEl.Text()))
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func validateRSAKeyIfPresent(key interface{}, encryptedKey *etree.Element) (*rsa.PrivateKey, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("expected key to be a *rsa.PrivateKey")
	}

	// extract and verify that the public key matches the certificate
	// this section is included to either let the service know up front
	// if the key will work, or let the service provider know which key
	// to use to decrypt the message. Either way, verification is not
	// security-critical.
	//nolint:revive,staticcheck // Keep the later empty branch so that we know to address this at a later date.
	if el := encryptedKey.FindElement("./KeyInfo/X509Data/X509Certificate"); el != nil {
		certPEMbuf := el.Text()
		certPEMbuf = "-----BEGIN CERTIFICATE-----\n" + certPEMbuf + "\n-----END CERTIFICATE-----\n"
		certPEM, _ := pem.Decode([]byte(certPEMbuf))
		if certPEM == nil {
			return nil, fmt.Errorf("invalid certificate")
		}
		cert, err := x509.ParseCertificate(certPEM.Bytes)
		if err != nil {
			return nil, err
		}
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected certificate to be an *rsa.PublicKey")
		}
		if rsaKey.N.Cmp(pubKey.N) != 0 || rsaKey.E != pubKey.E {
			return nil, fmt.Errorf("certificate does not match provided key")
		}
	} else if el = encryptedKey.FindElement("./KeyInfo/X509Data/X509IssuerSerial"); el != nil {
		// TODO: determine how to validate the issuer serial information
	}
	return rsaKey, nil
}
