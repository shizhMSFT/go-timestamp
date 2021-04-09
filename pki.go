package timestamp

import "encoding/asn1"

// Status contains the PKI status code.
type PKIStatus int

const (
	PKIStatusGranted PKIStatus = iota
	PKIStatusGrantedWithMods
	PKIStatusRejection
	PKIStatusWaiting
	PKIStatusRevocationWarning
	PKIStatusRevocationNotification
)

// PKIFailureInfo contains error messages
type PKIFailureInfo asn1.BitString

const (
	PKIFailureInfoBadAlg              = 0  // unrecognized or unsupported Algorithm Identifier
	PKIFailureInfoBadRequest          = 2  // transaction not permitted or supported
	PKIFailureInfoBadDataFormat       = 5  // the data submitted has the wrong format
	PKIFailureInfoTimeNotAvailable    = 14 // the TSA's time source is not available
	PKIFailureInfoUnacceptedPolicy    = 15 // the requested TSA policy is not supported by the TSA.
	PKIFailureInfoUnacceptedExtension = 16 // the requested extension is not supported by the TSA.
	PKIFailureInfoAddInfoNotAvailable = 17 // the additional information requested could not be understood or is not available
	PKIFailureInfoSystemFailure       = 25 // the request cannot be handled due to system failure
)
