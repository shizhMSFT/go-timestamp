package asn1

import "bytes"

func ConvertToDER(ber []byte) ([]byte, error) {
	v, err := Decode(bytes.NewReader(ber))
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, v.EncodedLen()))
	v.Encode(buf)
	return buf.Bytes(), nil
}
