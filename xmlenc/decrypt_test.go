package xmlenc

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/beevik/etree"
)

func certFromDocument(t *testing.T, doc *etree.Document) *x509.Certificate {
	t.Helper()
	// The certificate that identifies the decryption key lives in the
	// EncryptedKey's KeyInfo. A document may also carry unrelated
	// certificates (e.g. a signing KeyInfo) earlier in the document, so
	// select by the EncryptedKey rather than by document order.
	el := doc.FindElement("//EncryptedKey/KeyInfo/X509Data/X509Certificate")
	assert.Assert(t, el != nil)
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(el.Text()), ""))
	assert.Check(t, err)
	cert, err := x509.ParseCertificate(raw)
	assert.Check(t, err)
	return cert
}

func testCiphers() []BlockCipher {
	return []BlockCipher{AES128CBC, AES192CBC, AES256CBC, TripleDES, AES128GCM}
}

func TestCanDecrypt(t *testing.T) {
	t.Run("CBC", func(t *testing.T) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(golden.Get(t, "input.xml"))
		assert.Check(t, err)

		//nolint:gosec
		keyPEM := "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi\n3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E\nPsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB\nAoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ\nCT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS\nJEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU\nN3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/\nfbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU\n4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM\nRq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA\nyfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr\nvBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6\nhU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==\n-----END RSA PRIVATE KEY-----\n"
		b, _ := pem.Decode([]byte(keyPEM))
		key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
		assert.Check(t, err)

		decryptor := NewDecryptor(Key{
			Key:         key,
			Certificate: certFromDocument(t, doc),
			OAEP:        OAEPParameters{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
			Ciphers:     testCiphers(),
		})

		el := doc.Root().FindElement("//EncryptedKey")
		buf, err := decryptor.Decrypt(el)
		assert.Check(t, err)
		assert.Check(t, is.DeepEqual([]byte{0xc, 0x70, 0xa2, 0xc8, 0x15, 0x74, 0x89, 0x3f, 0x36, 0xd2, 0x7c, 0x14, 0x2a, 0x9b, 0xaa, 0xd9},
			buf))

		el = doc.Root().FindElement("//EncryptedData")
		buf, err = decryptor.Decrypt(el)
		assert.Check(t, err)
		golden.Assert(t, string(buf), "plaintext.xml")
	})

	t.Run("GCM", func(t *testing.T) {
		doc := etree.NewDocument()
		err := doc.ReadFromBytes(golden.Get(t, "input_gcm.xml"))
		assert.Check(t, err)

		keyPEM := golden.Get(t, "cert.key")
		b, _ := pem.Decode(keyPEM)
		key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		assert.Check(t, err)

		decryptor := NewDecryptor(Key{
			Key:         key,
			Certificate: certFromDocument(t, doc),
			OAEP:        OAEPParameters{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
			Ciphers:     testCiphers(),
		})

		el := doc.Root().FindElement("//EncryptedKey")
		_, err = decryptor.Decrypt(el)
		assert.Check(t, err)

		el = doc.Root().FindElement("//EncryptedData")
		_, err = decryptor.Decrypt(el)
		assert.Check(t, err)
	})
}

func TestCannotDecryptWithoutCertificate(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes(golden.Get(t, "input.xml"))
	assert.Check(t, err)

	// Remove the certificate the decryptor needs: the one in the
	// EncryptedKey's KeyInfo (not any other certificate in the document).
	el := doc.FindElement("//EncryptedKey/KeyInfo/X509Data/X509Certificate")
	el.Parent().RemoveChild(el)

	//nolint:gosec
	keyPEM := "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi\n3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E\nPsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB\nAoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ\nCT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS\nJEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU\nN3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/\nfbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU\n4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM\nRq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA\nyfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr\nvBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6\nhU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==\n-----END RSA PRIVATE KEY-----\n"
	b, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	assert.Check(t, err)

	// The Decryptor selects a key by the certificate in the EncryptedKey, so
	// without one it cannot proceed.
	decryptor := NewDecryptor(Key{
		Key:     key,
		OAEP:    OAEPParameters{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
		Ciphers: testCiphers(),
	})

	_, err = decryptor.Decrypt(doc.Root().FindElement("//EncryptedKey"))
	assert.Check(t, is.Error(err, "cannot find required element: KeyInfo/X509Data/X509Certificate"))
}

func newTestRSAEncrypter(algorithm string, hash, mgfHash crypto.Hash, label []byte) RSA {
	var e RSA
	switch algorithm {
	case RSAOAEPMGF1P:
		e = OAEP()
	case RSAOAEP:
		e = OAEP_SHA256()
	}
	e.BlockCipher = AES128CBC
	e.Hash = hash
	e.MGFHash = mgfHash
	e.Label = label
	return e
}

func otherHash(h crypto.Hash) crypto.Hash {
	if h == crypto.SHA256 {
		return crypto.SHA512
	}
	return crypto.SHA256
}

func TestOAEPParameterRoundTrip(t *testing.T) {
	certBlock, _ := pem.Decode(golden.Get(t, "cert.cert"))
	assert.Assert(t, certBlock != nil)
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	assert.Check(t, err)

	keyBlock, _ := pem.Decode(golden.Get(t, "cert.key"))
	assert.Assert(t, keyBlock != nil)
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	assert.Check(t, err)
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	assert.Assert(t, ok)

	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	cases := []struct {
		name       string
		algorithm  string
		hash       crypto.Hash
		mgfHash    crypto.Hash
		label      []byte
		wantDigest string
		wantMGF    string
	}{
		{
			name:       "rsa-oaep-mgf1p-sha1",
			algorithm:  RSAOAEPMGF1P,
			hash:       crypto.SHA1,
			mgfHash:    crypto.SHA1,
			wantDigest: DigestSHA1,
		},
		{
			name:       "rsa-oaep-sha256-mgf1sha1",
			algorithm:  RSAOAEP,
			hash:       crypto.SHA256,
			mgfHash:    crypto.SHA1,
			wantDigest: DigestSHA256,
			wantMGF:    MGF1SHA1,
		},
		{
			name:       "rsa-oaep-sha256-mgf1sha256",
			algorithm:  RSAOAEP,
			hash:       crypto.SHA256,
			mgfHash:    crypto.SHA256,
			wantDigest: DigestSHA256,
			wantMGF:    MGF1SHA256,
		},
		{
			name:       "rsa-oaep-sha384-mgf1sha384",
			algorithm:  RSAOAEP,
			hash:       crypto.SHA384,
			mgfHash:    crypto.SHA384,
			wantDigest: DigestSHA384,
			wantMGF:    MGF1SHA384,
		},
		{
			name:       "rsa-oaep-sha256-mgf1sha256-label",
			algorithm:  RSAOAEP,
			hash:       crypto.SHA256,
			mgfHash:    crypto.SHA256,
			label:      []byte("test label"),
			wantDigest: DigestSHA256,
			wantMGF:    MGF1SHA256,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encrypter := newTestRSAEncrypter(tc.algorithm, tc.hash, tc.mgfHash, tc.label)
			encryptedDataEl, err := encrypter.Encrypt(certificate, plaintext, nil)
			assert.Check(t, err)

			emEl := encryptedDataEl.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod")
			assert.Assert(t, emEl != nil)
			assert.Equal(t, emEl.SelectAttrValue("Algorithm", ""), tc.algorithm)

			dmEl := emEl.FindElement("./DigestMethod")
			assert.Assert(t, dmEl != nil)
			assert.Equal(t, dmEl.SelectAttrValue("Algorithm", ""), tc.wantDigest)

			mgfEl := emEl.FindElement("./MGF")
			if tc.wantMGF == "" {
				assert.Assert(t, mgfEl == nil)
			} else {
				assert.Assert(t, mgfEl != nil)
				assert.Equal(t, mgfEl.SelectAttrValue("Algorithm", ""), tc.wantMGF)
			}

			paramsEl := emEl.FindElement("./OAEPparams")
			if len(tc.label) == 0 {
				assert.Assert(t, paramsEl == nil)
			} else {
				assert.Assert(t, paramsEl != nil)
				assert.Equal(t, strings.TrimSpace(paramsEl.Text()), base64.StdEncoding.EncodeToString(tc.label))
			}

			decryptor := NewDecryptor(Key{
				Key:         rsaKey,
				Certificate: certificate,
				OAEP:        OAEPParameters{Hash: tc.hash, MGFHash: tc.mgfHash, Label: tc.label},
				Ciphers:     []BlockCipher{AES128CBC},
			})
			got, err := decryptor.Decrypt(encryptedDataEl)
			assert.Check(t, err)
			assert.DeepEqual(t, got, plaintext)

			// A Decryptor configured with a different digest must reject the
			// ciphertext rather than fall back to its declared parameters.
			_, err = NewDecryptor(Key{
				Key:         rsaKey,
				Certificate: certificate,
				OAEP:        OAEPParameters{Hash: otherHash(tc.hash), MGFHash: tc.mgfHash, Label: tc.label},
				Ciphers:     []BlockCipher{AES128CBC},
			}).Decrypt(encryptedDataEl)
			assert.Check(t, is.Error(err, ErrParameterMismatch.Error()))

			// A Decryptor configured with a different MGF must reject it too.
			_, err = NewDecryptor(Key{
				Key:         rsaKey,
				Certificate: certificate,
				OAEP:        OAEPParameters{Hash: tc.hash, MGFHash: otherHash(tc.mgfHash), Label: tc.label},
				Ciphers:     []BlockCipher{AES128CBC},
			}).Decrypt(encryptedDataEl)
			assert.Check(t, is.Error(err, ErrParameterMismatch.Error()))

			// A different label must be rejected as well.
			if len(tc.label) > 0 {
				_, err = NewDecryptor(Key{
					Key:         rsaKey,
					Certificate: certificate,
					OAEP:        OAEPParameters{Hash: tc.hash, MGFHash: tc.mgfHash, Label: []byte("other label")},
					Ciphers:     []BlockCipher{AES128CBC},
				}).Decrypt(encryptedDataEl)
				assert.Check(t, is.Error(err, ErrParameterMismatch.Error()))
			}

			// rsa-oaep-mgf1p forbids an explicit MGF element.
			if tc.algorithm == RSAOAEPMGF1P {
				badEl := encryptedDataEl.Copy()
				badEmEl := badEl.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod")
				assert.Assert(t, badEmEl != nil)
				mgf := badEmEl.CreateElement("xenc11:MGF")
				mgf.CreateAttr("Algorithm", MGF1SHA256)

				_, err = NewDecryptor(Key{
					Key:         rsaKey,
					Certificate: certificate,
					OAEP:        OAEPParameters{Hash: tc.hash, MGFHash: tc.mgfHash, Label: tc.label},
					Ciphers:     []BlockCipher{AES128CBC},
				}).Decrypt(badEl)
				assert.Check(t, is.Error(err, ErrParameterMismatch.Error()))
			}
		})
	}
}
