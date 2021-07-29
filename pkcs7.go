package timestamp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

var ErrMissingAttribute = errors.New("missing signer attribute")

// ContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   content [0] EXPLICIT ANY DEFINED BY contentType }
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithms DigestAlgorithmIdentifiers,
//   encapContentInfo EncapsulatedContentInfo,
//   certificates [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
//   signerInfos SignerInfos }
type SignedData struct {
	Version                    int
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapsulatedContentInfo    EncapsulatedContentInfo
	Certificates               asn1.RawValue          `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []SignerInfo           `asn1:"set"`
}

// EncapsulatedContentInfo ::= SEQUENCE {
//   eContentType ContentType,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
type EncapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,optional,tag:0"`
}

// SignerInfo ::= SEQUENCE {
//   version CMSVersion,
//   sid SignerIdentifier,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature SignatureValue,
//   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
type SignerInfo struct {
	Version            int
	SignerIdentifier   IssuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []Attribute `asn1:"optional,tag:1"`
}

// IssuerAndSerialNumber ::= SEQUENCE {
//   issuer Name,
//   serialNumber CertificateSerialNumber }
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute ::= SEQUENCE {
//   attrType OBJECT IDENTIFIER,
//   attrValues SET OF AttributeValue }
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// ParsedSignedData is ready to be read and verified.
type ParsedSignedData struct {
	Content      []byte
	ContentType  asn1.ObjectIdentifier
	Certificates []*x509.Certificate
	CRLs         []pkix.CertificateList

	signers []SignerInfo
}

func ParseSignedData(data []byte) (*ParsedSignedData, error) {
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, err
	}
	if !OIDSignedData.Equal(contentInfo.ContentType) {
		return nil, errors.New("not signed data type")
	}

	var signedData SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(signedData.Certificates.Bytes)
	if err != nil {
		return nil, err
	}

	return &ParsedSignedData{
		Content:      signedData.EncapsulatedContentInfo.Content,
		ContentType:  signedData.EncapsulatedContentInfo.ContentType,
		Certificates: certs,
		CRLs:         signedData.CRLs,
		signers:      signedData.SignerInfos,
	}, nil
}

func (d *ParsedSignedData) Verify(roots *x509.CertPool) error {
	if len(d.signers) == 0 {
		return errors.New("no signer found")
	}
	if len(d.Certificates) == 0 {
		return errors.New("no certs found")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range d.Certificates {
		intermediates.AddCert(cert)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   time.Now().UTC(),
	}
	for _, signer := range d.signers {
		if err := d.verify(signer, verifyOpts); err != nil {
			return err
		}
	}
	return nil
}

// verify verifies the trust in a top-down manner
func (d *ParsedSignedData) verify(signer SignerInfo, opts x509.VerifyOptions) error {
	// Fetch cert
	cert := findCertificate(d.Certificates, signer.SignerIdentifier)
	if cert == nil {
		return errors.New("signer cert not found")
	}

	// Verify cert chain
	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	// Verify signature
	algorithm := ConvertToSignatureAlgorithm(signer.DigestAlgorithm.Algorithm, signer.SignatureAlgorithm.Algorithm)
	if algorithm == x509.UnknownSignatureAlgorithm {
		return errors.New("unknown signature algorithm")
	}
	signed := d.Content
	if len(signer.SignedAttributes) > 0 {
		encoded, err := asn1.MarshalWithParams(signer.SignedAttributes, "set")
		if err != nil {
			return err
		}
		signed = encoded
	}
	if err := cert.CheckSignature(algorithm, signed, signer.Signature); err != nil {
		return err
	}

	// Verify attributes
	if len(signer.SignedAttributes) == 0 {
		return nil
	}

	var contentType asn1.ObjectIdentifier
	if err := findAttribute(signer.SignedAttributes, OIDAttributeContentType, &contentType); err != nil {
		return err
	}
	if !d.ContentType.Equal(contentType) {
		return errors.New("mismatch content type")
	}

	var expectedDigest []byte
	if err := findAttribute(signer.SignedAttributes, OIDAttributeMessageDigest, &expectedDigest); err != nil {
		return err
	}
	hash, ok := ConvertToHash(signer.DigestAlgorithm.Algorithm)
	if !ok {
		return errors.New("unsupported digest algorithm")
	}
	actualDigest, err := ComputeHash(hash, d.Content)
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedDigest, actualDigest) {
		return errors.New("mismatch digest")
	}

	var signingTime time.Time
	if err := findAttribute(signer.SignedAttributes, OIDAttributeSigningTime, &signingTime); err != nil {
		if err == ErrMissingAttribute {
			return nil
		}
		return err
	}
	// sanity check on signing time
	if signingTime.Before(cert.NotBefore) || signingTime.After(cert.NotAfter) {
		return errors.New("signature signed when cert is inactive")
	}

	return nil
}

func findCertificate(certs []*x509.Certificate, signerID IssuerAndSerialNumber) *x509.Certificate {
	for _, cert := range certs {
		if bytes.Equal(cert.RawIssuer, signerID.Issuer.FullBytes) && cert.SerialNumber.Cmp(signerID.SerialNumber) == 0 {
			return cert
		}
	}
	return nil
}

func findAttribute(attributes []Attribute, identifier asn1.ObjectIdentifier, attributeOut interface{}) error {
	for _, attribute := range attributes {
		if identifier.Equal(attribute.Type) {
			_, err := asn1.Unmarshal(attribute.Values.Bytes, attributeOut)
			return err
		}
	}
	return ErrMissingAttribute
}

func ComputeHash(hash crypto.Hash, message []byte) ([]byte, error) {
	h := hash.New()
	_, err := h.Write(message)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
