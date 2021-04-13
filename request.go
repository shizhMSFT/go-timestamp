package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"

	digest "github.com/opencontainers/go-digest"
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

// NewRequest creates a request based on the given digest.
func NewRequest(digest digest.Digest) (*Request, error) {
	hashAlgorithm, found := DigestAlgorithmOIDs[digest.Algorithm()]
	if !found {
		return nil, errors.New("unsupported algorithm")
	}
	hashedMessage, err := hex.DecodeString(digest.Encoded())
	if err != nil {
		return nil, err
	}

	return &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: hashAlgorithm,
			},
			HashedMessage: hashedMessage,
		},
	}, nil
}

func (r *Request) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("null request")
	}
	return asn1.Marshal(*r)
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
