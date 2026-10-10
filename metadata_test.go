package saml

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

func TestCanParseMetadata(t *testing.T) {
	buf := golden.Get(t, "TestCanParseMetadata_metadata.xml")

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	assert.Check(t, err)

	var False = false
	var True = true

	expected := EntityDescriptor{
		EntityID:      "https://dev.aa.kndr.org/users/auth/saml/metadata",
		ID:            "_af805d1c-c2e3-444e-9cf5-efc664eeace6",
		ValidUntil:    time.Date(2001, time.February, 3, 4, 5, 6, 789000000, time.UTC),
		CacheDuration: time.Hour,
		SPSSODescriptors: []SPSSODescriptor{
			{
				XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:metadata", Local: "SPSSODescriptor"},
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					},
				},
				AuthnRequestsSigned:  &False,
				WantAssertionsSigned: &False,
				AssertionConsumerServices: []IndexedEndpoint{
					{
						Binding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
						Location:  "https://dev.aa.kndr.org/users/auth/saml/callback",
						Index:     0,
						IsDefault: &True,
					},
				},
				AttributeConsumingServices: []AttributeConsumingService{
					{
						Index:        1,
						IsDefault:    &True,
						ServiceNames: []LocalizedName{{Lang: "en", Value: "Required attributes"}},
						RequestedAttributes: []RequestedAttribute{
							{
								Attribute: Attribute{
									FriendlyName: "Email address",
									Name:         "email",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Full name",
									Name:         "name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Given name",
									Name:         "first_name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Family name",
									Name:         "last_name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
						},
					},
				},
			},
		},
	}
	assert.Check(t, is.DeepEqual(expected, metadata))

}

func TestCanProduceSPMetadata(t *testing.T) {
	validUntil, _ := time.Parse("2006-01-02T15:04:05.000000", "2013-03-10T00:32:19.104000")
	AuthnRequestsSigned := true
	WantAssertionsSigned := true
	metadata := EntityDescriptor{
		EntityID:      "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/",
		ValidUntil:    validUntil,
		CacheDuration: time.Hour,
		SPSSODescriptors: []SPSSODescriptor{
			{
				AuthnRequestsSigned:  &AuthnRequestsSigned,
				WantAssertionsSigned: &WantAssertionsSigned,
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{
												Data: `MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX
DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308
kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv
SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf
nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv
TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+
cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==`,
											},
										},
									},
								},
							},
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{
												Data: `MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX
DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308
kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv
SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf
nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv
TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+
cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==`,
											},
										},
									},
								},
							},
						},
					},

					SingleLogoutServices: []Endpoint{{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						Location: "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/",
					}},
				},

				AssertionConsumerServices: []IndexedEndpoint{{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/",
					Index:    1,
				}},
			},
		},
	}

	buf, err := xml.MarshalIndent(metadata, "", "  ")
	assert.Check(t, err)
	golden.Assert(t, string(buf), "TestCanProduceSPMetadata_expected")
}

func TestMetadataValidatesUrlSchemeForProtocolBinding(t *testing.T) {
	buf := golden.Get(t, "TestMetadataValidatesUrlSchemeForProtocolBinding_metadata.xml")

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	assert.Error(t, err, "invalid url scheme \"javascript\" for binding \"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")
}

// TestMetadataKeepsSimpleSignEndpointLocations ensures the HTTP-POST
// SimpleSign binding is recognised. Unrecognised bindings have their location
// discarded (see checkEndpointLocation), which would make endpoints
// advertising it unusable.
func TestMetadataKeepsSimpleSignEndpointLocations(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
	}{
		{
			name: "assertion consumer service",
			metadata: `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
				<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://sp.example.com/acs" index="0"/>
				</SPSSODescriptor>
			</EntityDescriptor>`,
		},
		{
			name: "single sign on service",
			metadata: `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
				<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
					<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://idp.example.com/saml/sso"/>
				</IDPSSODescriptor>
			</EntityDescriptor>`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			metadata := EntityDescriptor{}
			assert.Check(t, xml.Unmarshal([]byte(test.metadata), &metadata))

			var endpoints []Endpoint
			for _, sp := range metadata.SPSSODescriptors {
				for _, acs := range sp.AssertionConsumerServices {
					endpoints = append(endpoints, Endpoint{Binding: acs.Binding, Location: acs.Location})
				}
			}
			for _, idp := range metadata.IDPSSODescriptors {
				endpoints = append(endpoints, idp.SingleSignOnServices...)
			}

			if len(endpoints) != 1 {
				t.Fatalf("expected exactly one endpoint, got %d", len(endpoints))
			}
			assert.Equal(t, HTTPPostSimpleSignBinding, endpoints[0].Binding)
			assert.Assert(t, strings.HasPrefix(endpoints[0].Location, "https://"), "location was discarded: %q", endpoints[0].Location)
		})
	}
}
