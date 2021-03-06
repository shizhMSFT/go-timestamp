package asn1

import "io"

type PrimitiveValue struct {
	identifier []byte
	content    []byte
}

func (v *PrimitiveValue) Encode(w ValueWriter) error {
	_, err := w.Write(v.identifier)
	if err != nil {
		return err
	}
	if err = encodeLength(w, len(v.content)); err != nil {
		return err
	}
	_, err = w.Write(v.content)
	return err
}

func (v *PrimitiveValue) EncodedLen() int {
	return len(v.identifier) + encodedLengthSize(len(v.content)) + len(v.content)
}

func DecodePrimitive(r ValueReader) (*PrimitiveValue, error) {
	identifier, err := decodeIdentifier(r)
	if err != nil {
		return nil, err
	}
	if !isPrimitive(identifier[0]) {
		return nil, ErrConstructed
	}
	length, err := decodeLength(r)
	if err != nil {
		return nil, err
	}
	content := make([]byte, length)
	_, err = io.ReadFull(r, content)
	if err != nil {
		if err == io.EOF {
			return nil, ErrEarlyEOF
		}
		return nil, err
	}

	return &PrimitiveValue{
		identifier: identifier,
		content:    content,
	}, nil
}
