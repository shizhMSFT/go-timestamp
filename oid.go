package timestamp

import (
	"encoding/asn1"

	"github.com/opencontainers/go-digest"
)

var DigestAlgorithmOIDs = map[digest.Algorithm]asn1.ObjectIdentifier{
	digest.SHA256: {2, 16, 840, 1, 101, 3, 4, 2, 1},
	digest.SHA384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
	digest.SHA512: {2, 16, 840, 1, 101, 3, 4, 2, 3},
}

var (
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDCTTSTInfo  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)
