package timestamp

import (
	"crypto/x509"
	"encoding/asn1"

	"github.com/opencontainers/go-digest"
)

var (
	OIDDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

var DigestAlgorithmOIDs = map[digest.Algorithm]asn1.ObjectIdentifier{
	digest.SHA256: OIDDigestAlgorithmSHA256,
	digest.SHA384: OIDDigestAlgorithmSHA384,
	digest.SHA512: OIDDigestAlgorithmSHA512,
}

var ()

var (
	OIDSignatureAlgorithmRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDSignatureAlgorithmRSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDSignatureAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSignatureAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSignatureAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	OIDSignatureAlgorithmECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDSignatureAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSignatureAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSignatureAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var (
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDCTTSTInfo  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

// ConvertToSignatureAlgorithm converts algorithms encoded in ASN.1 to golang signature algorithm.
func ConvertToSignatureAlgorithm(digestAlgorithm, signatureAlgorithm asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case OIDSignatureAlgorithmRSA.Equal(signatureAlgorithm):
		switch {
		case OIDDigestAlgorithmSHA1.Equal(digestAlgorithm):
			return x509.SHA1WithRSA
		case OIDDigestAlgorithmSHA256.Equal(digestAlgorithm):
			return x509.SHA256WithRSA
		case OIDDigestAlgorithmSHA384.Equal(digestAlgorithm):
			return x509.SHA384WithRSA
		case OIDDigestAlgorithmSHA512.Equal(digestAlgorithm):
			return x509.SHA512WithRSA
		}
	case OIDSignatureAlgorithmRSASHA1.Equal(signatureAlgorithm):
		return x509.SHA1WithRSA
	case OIDSignatureAlgorithmRSASHA256.Equal(signatureAlgorithm):
		return x509.SHA256WithRSA
	case OIDSignatureAlgorithmRSASHA384.Equal(signatureAlgorithm):
		return x509.SHA384WithRSA
	case OIDSignatureAlgorithmRSASHA512.Equal(signatureAlgorithm):
		return x509.SHA512WithRSA
	case OIDSignatureAlgorithmECDSASHA1.Equal(signatureAlgorithm):
		return x509.ECDSAWithSHA1
	case OIDSignatureAlgorithmECDSASHA256.Equal(signatureAlgorithm):
		return x509.ECDSAWithSHA256
	case OIDSignatureAlgorithmECDSASHA384.Equal(signatureAlgorithm):
		return x509.ECDSAWithSHA384
	case OIDSignatureAlgorithmECDSASHA512.Equal(signatureAlgorithm):
		return x509.ECDSAWithSHA512
	}
	return x509.UnknownSignatureAlgorithm
}
