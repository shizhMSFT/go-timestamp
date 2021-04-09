package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// Request is a time-stamping request.
// TimeStampReq ::= SEQUENCE  {
//     version                      INTEGER  { v1(1) },
//     messageImprint               MessageImprint,
//       --a hash algorithm OID and the hash value of the data to be
//       --time-stamped
//     reqPolicy             TSAPolicyID              OPTIONAL,
//     nonce                 INTEGER                  OPTIONAL,
//     certReq               BOOLEAN                  DEFAULT FALSE,
//     extensions            [0] IMPLICIT Extensions  OPTIONAL  }
type Request struct {
	Version        int // currently v1
	MessageImprint MessageImprint
	ReqPolicy      TSAPolicyID      `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	CertReq        bool             `asn1:"optional,default:false"`
	Extensions     []pkix.Extension `asn1:"optional,tag:0"`
}

func (r Request) MarshalBinary() ([]byte, error) {
	return asn1.Marshal(r)
}

// MessageImprint contains the hash of the datum to be time-stamped.
// MessageImprint ::= SEQUENCE  {
//     hashAlgorithm                AlgorithmIdentifier,
//     hashedMessage                OCTET STRING  }
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// TSAPolicyID indicates the TSA policy.
type TSAPolicyID asn1.ObjectIdentifier
