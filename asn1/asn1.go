package asn1

import (
	"bytes"
	"errors"
	"io"
)

var (
	ErrUnsupportedLength = errors.New("asn1: length methond not supported")
)

type Value struct {
	identifier []byte
	content    []byte
}

func NewValue(identifier, content []byte) *Value {
	return &Value{
		identifier: identifier,
		content:    content,
	}
}

func (v *Value) IsPrimitive() bool {
	return v.identifier[0]&0x20 == 0
}

func (v *Value) Members() ([]*Value, error) {
	if v.IsPrimitive() {
		return nil, nil
	}

	var result []*Value
	reader := bytes.NewReader(v.content)
	for reader.Len() > 0 {
		value, err := parseValue(reader)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func (v *Value) MarshalBinary() ([]byte, error) {
	// Calculate the size of length
	length := len(v.content)
	lengthSize := 1
	if length > 127 {
		for l := length; l > 0; lengthSize++ {
			l >>= 8
		}
	}

	// Allocate buffer
	offset := len(v.identifier)
	buf := make([]byte, offset+lengthSize+len(v.content))

	// Fill in buffer
	copy(buf, v.identifier)
	if length > 127 {
		buf[offset] = byte(0x80 | byte(lengthSize-1))
		offset++
		for i := 1; i < lengthSize; i++ {
			buf[offset] = byte(length >> (8 * (4 - i)))
			offset++
		}
	} else {
		buf[offset] = byte(length)
		offset++
	}
	copy(buf[offset:], v.content)

	return buf, nil
}

func (v *Value) UnmarshalBinary(data []byte) error {
	r, err := parseValue(bytes.NewReader(data))
	if err != nil {
		return err
	}

	*v = *r
	return nil
}

type valueReader interface {
	io.Reader
	io.ByteReader
}

func parseValue(r valueReader) (*Value, error) {
	identifier, err := parseIdentifier(r)
	if err != nil {
		return nil, err
	}
	length, err := parseLength(r)
	if err != nil {
		return nil, err
	}

	content := make([]byte, length)
	_, err = io.ReadFull(r, content)
	if err != nil {
		return nil, err
	}

	return &Value{
		identifier: identifier,
		content:    content,
	}, nil
}

func parseIdentifier(r io.ByteReader) ([]byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	identifier := []byte{b}
	if b&0x1f == 0x1f {
		for {
			b, err = r.ReadByte()
			if err != nil {
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

func parseLength(r io.ByteReader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
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
			return 0, err
		}
		length = (length << 8) | int(b)
	}
	if length < 0 {
		return 0, ErrUnsupportedLength
	}
	return length, nil
}
