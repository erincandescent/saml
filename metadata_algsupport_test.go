package saml

import (
	"encoding/xml"
	"testing"

	"gotest.tools/assert"
)

func TestEntityDescriptorExtensions(t *testing.T) {
	const metadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" entityID="https://sp.example.com">
  <md:Extensions>
    <alg:SigningMethod MinKeySize="2048" MaxKeySize="4096" Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  </md:Extensions>
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
    </md:Extensions>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`

	var ed EntityDescriptor
	assert.Check(t, xml.Unmarshal([]byte(metadata), &ed))

	assert.Assert(t, ed.Extensions != nil)
	assert.Equal(t, len(ed.Extensions.SigningMethods), 1)
	assert.Equal(t, ed.Extensions.SigningMethods[0].Algorithm, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	assert.Equal(t, ed.Extensions.SigningMethods[0].MinKeySize, 2048)
	assert.Equal(t, ed.Extensions.SigningMethods[0].MaxKeySize, 4096)
	assert.Equal(t, len(ed.Extensions.DigestMethods), 1)
	assert.Equal(t, ed.Extensions.DigestMethods[0].Algorithm, "http://www.w3.org/2001/04/xmlenc#sha256")

	assert.Equal(t, len(ed.SPSSODescriptors), 1)
	assert.Assert(t, ed.SPSSODescriptors[0].Extensions != nil)
	assert.Equal(t, len(ed.SPSSODescriptors[0].Extensions.SigningMethods), 1)
	assert.Equal(t, ed.SPSSODescriptors[0].Extensions.SigningMethods[0].Algorithm, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")

	// The extensions must survive marshalling, so a producer can emit them.
	out, err := xml.Marshal(ed)
	assert.Check(t, err)

	var back EntityDescriptor
	assert.Check(t, xml.Unmarshal(out, &back))
	assert.Assert(t, back.Extensions != nil)
	assert.Equal(t, back.Extensions.SigningMethods[0].MinKeySize, 2048)
	assert.Assert(t, back.SPSSODescriptors[0].Extensions != nil)
	assert.Equal(t, back.SPSSODescriptors[0].Extensions.SigningMethods[0].Algorithm, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
}
