package bech32

import (
	"fmt"
)

type ErrMixedCase struct{}

func (e ErrMixedCase) Error() string {
	return "string not all lowercase or all uppercase"
}

type ErrInvalidBitGroups struct{}

func (e ErrInvalidBitGroups) Error() string {
	return "only bit groups between 1 and 8 allowed"
}

type ErrInvalidIncompleteGroup struct{}

func (e ErrInvalidIncompleteGroup) Error() string {
	return "invalid incomplete group"
}

type ErrInvalidLength int

func (e ErrInvalidLength) Error() string {
	return fmt.Sprintf("invalid bech32 string length %d", int(e))
}

type ErrInvalidCharacter rune

func (e ErrInvalidCharacter) Error() string {
	return fmt.Sprintf("invalid character in string: '%c'", rune(e))
}

type ErrInvalidSeparatorIndex int

func (e ErrInvalidSeparatorIndex) Error() string {
	return fmt.Sprintf("invalid separator index %d", int(e))
}

type ErrNonCharsetChar rune

func (e ErrNonCharsetChar) Error() string {
	return fmt.Sprintf("invalid character not part of charset: %v", int(e))
}

type ErrInvalidChecksum struct {
	Expected  string
	ExpectedM string
	Actual    string
}

func (e ErrInvalidChecksum) Error() string {
	return fmt.Sprintf("invalid checksum (expected (bech32=%v, "+
		"bech32m=%v), got %v)", e.Expected, e.ExpectedM, e.Actual)
}

type ErrInvalidDataByte byte

func (e ErrInvalidDataByte) Error() string {
	return fmt.Sprintf("invalid data byte: %v", byte(e))
}
