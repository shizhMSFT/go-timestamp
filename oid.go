package timestamp

import (
	"encoding/asn1"

	"github.com/opencontainers/go-digest"
)

var DigestAlgorithmOIDs = map[digest.Algorithm]asn1.ObjectIdentifier{
	digest.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	digest.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	digest.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}
