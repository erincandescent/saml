package xmlenc

import (
	"crypto"

	// Register the hash implementations referenced by the tables below so that
	// crypto.Hash.New and crypto.Hash.Available work.
	_ "crypto/sha1" //nolint:gosec // required for protocol support
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Digest method URIs, as used in the Algorithm attribute of a
// ds:DigestMethod element.
const (
	DigestSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// Mask generation function URIs, as used in the Algorithm attribute of an
// xenc11:MGF element.
const (
	MGF1SHA1   = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	MGF1SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	MGF1SHA384 = "http://www.w3.org/2009/xmlenc11#mgf1sha384"
	MGF1SHA512 = "http://www.w3.org/2009/xmlenc11#mgf1sha512"
)

var digestHashes = map[string]crypto.Hash{
	DigestSHA1:   crypto.SHA1,
	DigestSHA256: crypto.SHA256,
	DigestSHA384: crypto.SHA384,
	DigestSHA512: crypto.SHA512,
}

// DigestHash returns the crypto.Hash identified by a ds:DigestMethod URI.
func DigestHash(uri string) (crypto.Hash, bool) {
	h, ok := digestHashes[uri]
	return h, ok
}

// DigestURI returns the ds:DigestMethod URI identified by a crypto.Hash.
func DigestURI(h crypto.Hash) (string, bool) {
	switch h {
	case crypto.SHA1:
		return DigestSHA1, true
	case crypto.SHA256:
		return DigestSHA256, true
	case crypto.SHA384:
		return DigestSHA384, true
	case crypto.SHA512:
		return DigestSHA512, true
	default:
		return "", false
	}
}

var mgfHashes = map[string]crypto.Hash{
	MGF1SHA1:   crypto.SHA1,
	MGF1SHA256: crypto.SHA256,
	MGF1SHA384: crypto.SHA384,
	MGF1SHA512: crypto.SHA512,
}

// MGFHash returns the crypto.Hash identified by an xenc11:MGF URI.
func MGFHash(uri string) (crypto.Hash, bool) {
	h, ok := mgfHashes[uri]
	return h, ok
}

// MGFURI returns the xenc11:MGF URI identified by a crypto.Hash.
func MGFURI(h crypto.Hash) (string, bool) {
	switch h {
	case crypto.SHA1:
		return MGF1SHA1, true
	case crypto.SHA256:
		return MGF1SHA256, true
	case crypto.SHA384:
		return MGF1SHA384, true
	case crypto.SHA512:
		return MGF1SHA512, true
	default:
		return "", false
	}
}
