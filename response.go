package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"go.mozilla.org/pkcs7"
)

// Response is a time-stamping response.
// TimeStampResp ::= SEQUENCE  {
//     status                  PKIStatusInfo,
//     timeStampToken          TimeStampToken     OPTIONAL  }
type Response struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

func (r *Response) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("null response")
	}
	return asn1.Marshal(*r)
}

func (r *Response) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

func (r *Response) SignedData() (*pkcs7.PKCS7, error) {
	return pkcs7.Parse(r.TimeStampToken.FullBytes)
}

func (r *Response) TimeStampTokenInfo() (*TSTInfo, error) {
	signed, err := r.SignedData()
	if err != nil {
		return nil, err
	}

	info := &TSTInfo{}
	if _, err := asn1.Unmarshal(signed.Content, info); err != nil {
		return nil, err
	}

	return info, nil
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
