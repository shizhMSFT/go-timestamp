package asn1

import "io"

type ValueReader interface {
	io.Reader
	io.ByteScanner
}

type ValueWriter interface {
	io.Writer
	io.ByteWriter
}

type LimitedValueReader struct {
	io.LimitedReader
	S io.ByteScanner
}

func LimitValueReader(r ValueReader, n int64) ValueReader {
	return &LimitedValueReader{
		LimitedReader: io.LimitedReader{
			R: r,
			N: n,
		},
		S: r,
	}
}

func (l *LimitedValueReader) ReadByte() (c byte, err error) {
	if l.N <= 0 {
		return 0, io.EOF
	}
	c, err = l.S.ReadByte()
	if err == nil {
		l.N--
	}
	return
}

func (l *LimitedValueReader) UnreadByte() (err error) {
	err = l.S.UnreadByte()
	if err == nil {
		l.N++
	}
	return
}
