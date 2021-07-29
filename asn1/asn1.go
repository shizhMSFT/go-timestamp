package asn1

import (
	"encoding/asn1"
	"io"
)

var (
	ErrEarlyEOF          = asn1.SyntaxError{Msg: "early EOF"}
	ErrConstructed       = asn1.SyntaxError{Msg: "constructed value"}
	ErrPrimitive         = asn1.SyntaxError{Msg: "primitive value"}
	ErrUnsupportedLength = asn1.StructuralError{Msg: "length method not supported"}
)

type Value interface {
	Encode(ValueWriter) error
	EncodedLen() int
}

func Decode(r ValueReader) (Value, error) {
	peekIdentifier, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	err = r.UnreadByte()
	if err != nil {
		return nil, err
	}
	if isPrimitive(peekIdentifier) {
		return DecodePrimitive(r)
	}
	return DecodeConstructed(r)
}

func isPrimitive(identifier byte) bool {
	return identifier&0x20 == 0
}

func encodedLengthSize(length int) int {
	if length < 128 {
		return 1
	}

	lengthSize := 1
	for ; length > 0; lengthSize++ {
		length >>= 8
	}
	return lengthSize
}

func encodeLength(w io.ByteWriter, length int) error {
	if length < 128 {
		return w.WriteByte(byte(length))
	}

	lengthSize := encodedLengthSize(length)
	err := w.WriteByte(0x80 | byte(lengthSize-1))
	if err != nil {
		return err
	}
	for i := lengthSize - 1; i > 0; i-- {
		if err = w.WriteByte(byte(length >> (8 * (i - 1)))); err != nil {
			return err
		}
	}
	return nil
}

func decodeIdentifier(r io.ByteReader) ([]byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	identifier := []byte{b}
	if b&0x1f == 0x1f {
		for {
			b, err = r.ReadByte()
			if err != nil {
				if err == io.EOF {
					return nil, ErrEarlyEOF
				}
				return nil, err
			}
			identifier = append(identifier, b)
			if b&0x80 != 0 {
				break
			}
		}
	}
	return identifier, nil
}

func decodeLength(r io.ByteReader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return 0, ErrEarlyEOF
		}
		return 0, err
	}
	switch {
	case b < 0x80:
		return int(b), nil
	case b == 0x80:
		return 0, ErrUnsupportedLength
	}

	n := int(b & 0x7f)
	if n > 4 {
		return 0, ErrUnsupportedLength
	}
	var length int
	for i := 0; i < n; i++ {
		b, err = r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0, ErrEarlyEOF
			}
			return 0, err
		}
		length = (length << 8) | int(b)
	}
	if length < 0 {
		return 0, ErrUnsupportedLength
	}
	return length, nil
}
