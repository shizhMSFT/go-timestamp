package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Response is a time-stamping response.
// TimeStampResp ::= SEQUENCE  {
//     status                  PKIStatusInfo,
//     timeStampToken          TimeStampToken     OPTIONAL  }
type Response struct {
	Status         PKIStatusInfo
	TimeStampToken TimeStampToken `asn1:"optional"`
}

func (r *Response) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

// PKIStatusInfo contains status codes and failure information for PKI messages.
// PKIStatusInfo ::= SEQUENCE {
//     status        PKIStatus,
//     statusString  PKIFreeText     OPTIONAL,
//     failInfo      PKIFailureInfo  OPTIONAL  }
type PKIStatusInfo struct {
	Status       PKIStatus
	StatusString string         `asn1:"optional"`
	FailInfo     PKIFailureInfo `asn1:"optional"`
}

// TimeStampToken is of ContentInfo type
type TimeStampToken struct {
	ContentType asn1.ObjectIdentifier
	Content     SignedData `asn1:"explicit,tag:0"`
}

// SignedData ::= SEQUENCE {
//     version CMSVersion,
//     digestAlgorithms DigestAlgorithmIdentifiers,
//     encapContentInfo EncapsulatedContentInfo,
//     certificates [0] IMPLICIT CertificateSet OPTIONAL,
//     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//     signerInfos SignerInfos }
type SignedData struct {
	Version                 int
	DigestAlgorithms        []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapsulatedContentInfo EncapsulatedContentInfo
	Certificates            []asn1.RawValue `asn1:"optional,set,tag:0"`
	CRLs                    []asn1.RawValue `asn1:"optional,set,tag:1"`
	SignerInfos             []SignerInfo    `asn1:"set"`
}

// EncapsulatedContentInfo ::= SEQUENCE {
//     eContentType ContentType,
//     eContent [0] EXPLICIT OCTET STRING OPTIONAL }
type EncapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     TSTInfo `asn1:"optional,explicit,tag:0"`
}

// SignerInfo ::= SEQUENCE {
//     version CMSVersion,
//     sid SignerIdentifier,
//     digestAlgorithm DigestAlgorithmIdentifier,
//     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//     signatureAlgorithm SignatureAlgorithmIdentifier,
//     signature SignatureValue,
//     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
type SignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []Attribute `asn1:"optional,set,tag:1"`
}

// Attribute ::= SEQUENCE {
//     attrType OBJECT IDENTIFIER,
//     attrValues SET OF AttributeValue }
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// TSTInfo ::= SEQUENCE  {
//     version                      INTEGER  { v1(1) },
//     policy                       TSAPolicyId,
//     messageImprint               MessageImprint,
//       -- MUST have the same value as the similar field in
//       -- TimeStampReq
//     serialNumber                 INTEGER,
//      -- Time-Stamping users MUST be ready to accommodate integers
//      -- up to 160 bits.
//     genTime                      GeneralizedTime,
//     accuracy                     Accuracy                 OPTIONAL,
//     ordering                     BOOLEAN             DEFAULT FALSE,
//     nonce                        INTEGER                  OPTIONAL,
//       -- MUST be present if the similar field was present
//       -- in TimeStampReq.  In that case it MUST have the same value.
//     tsa                          [0] GeneralName          OPTIONAL,
//     extensions                   [1] IMPLICIT Extensions  OPTIONAL   }
type TSTInfo struct {
	Version        int
	Policy         TSAPolicyID
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// Accuracy ::= SEQUENCE {
//     seconds        INTEGER              OPTIONAL,
//     millis     [0] INTEGER  (1..999)    OPTIONAL,
//     micros     [1] INTEGER  (1..999)    OPTIONAL  }
type Accuracy struct {
	Seconds      int `asn1:"optional"`
	Milliseconds int `asn1:"optional,tag:0"`
	Microseconds int `asn1:"optional,tag:1"`
}
