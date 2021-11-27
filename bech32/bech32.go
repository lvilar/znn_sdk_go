package bech32

import (
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var gen = []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func toBytes(chars string) ([]byte, error) {
	decoded := make([]byte, 0, len(chars))
	for i := 0; i < len(chars); i++ {
		index := strings.IndexByte(charset, chars[i])
		if index < 0 {
			return nil, ErrNonCharsetChar(chars[i])
		}
		decoded = append(decoded, byte(index))
	}
	return decoded, nil
}

func bech32Polymod(hrp string, values, checksum []byte) int {
	chk := 1

	for i := 0; i < len(hrp); i++ {
		b := chk >> 25
		hiBits := int(hrp[i]) >> 5
		chk = (chk&0x1ffffff)<<5 ^ hiBits
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}

	b := chk >> 25
	chk = (chk & 0x1ffffff) << 5
	for i := 0; i < 5; i++ {
		if (b>>uint(i))&1 == 1 {
			chk ^= gen[i]
		}
	}

	for i := 0; i < len(hrp); i++ {
		b := chk >> 25
		loBits := int(hrp[i]) & 31
		chk = (chk&0x1ffffff)<<5 ^ loBits
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}

	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ int(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}

	if checksum == nil {
		for v := 0; v < 6; v++ {
			b := chk >> 25
			chk = (chk & 0x1ffffff) << 5
			for i := 0; i < 5; i++ {
				if (b>>uint(i))&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
	} else {
		for _, v := range checksum {
			b := chk >> 25
			chk = (chk&0x1ffffff)<<5 ^ int(v)
			for i := 0; i < 5; i++ {
				if (b>>uint(i))&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
	}

	return chk
}

func writeBech32Checksum(hrp string, data []byte, bldr *strings.Builder,
	version Version) {

	bech32Const := int(VersionToConsts[version])
	polymod := bech32Polymod(hrp, data, nil) ^ bech32Const
	for i := 0; i < 6; i++ {
		b := byte((polymod >> uint(5*(5-i))) & 31)

		c := charset[b]
		bldr.WriteByte(c)
	}
}

func bech32VerifyChecksum(hrp string, data []byte) (Version, bool) {
	checksum := data[len(data)-6:]
	values := data[:len(data)-6]
	polymod := bech32Polymod(hrp, values, checksum)

	bech32Version, ok := ConstsToVersion[ChecksumConst(polymod)]
	if ok {
		return bech32Version, true
	}

	return VersionUnknown, false
}

func decodeNoLimit(bech string) (string, []byte, Version, error) {
	if len(bech) < 8 {
		return "", nil, VersionUnknown, ErrInvalidLength(len(bech))
	}

	var hasLower, hasUpper bool
	for i := 0; i < len(bech); i++ {
		if bech[i] < 33 || bech[i] > 126 {
			return "", nil, VersionUnknown, ErrInvalidCharacter(bech[i])
		}

		hasLower = hasLower || (bech[i] >= 97 && bech[i] <= 122)
		hasUpper = hasUpper || (bech[i] >= 65 && bech[i] <= 90)
		if hasLower && hasUpper {
			return "", nil, VersionUnknown, ErrMixedCase{}
		}
	}

	if hasUpper {
		bech = strings.ToLower(bech)
	}

	one := strings.LastIndexByte(bech, '1')
	if one < 1 || one+7 > len(bech) {
		return "", nil, VersionUnknown, ErrInvalidSeparatorIndex(one)
	}

	hrp := bech[:one]
	data := bech[one+1:]

	decoded, err := toBytes(data)
	if err != nil {
		return "", nil, VersionUnknown, err
	}

	bech32Version, ok := bech32VerifyChecksum(hrp, decoded)
	if !ok {

		actual := bech[len(bech)-6:]
		payload := decoded[:len(decoded)-6]

		var expectedBldr strings.Builder
		expectedBldr.Grow(6)
		writeBech32Checksum(hrp, payload, &expectedBldr, Version0)
		expectedVersion0 := expectedBldr.String()

		var b strings.Builder
		b.Grow(6)
		writeBech32Checksum(hrp, payload, &expectedBldr, VersionM)
		expectedVersionM := expectedBldr.String()

		err = ErrInvalidChecksum{
			Expected:  expectedVersion0,
			ExpectedM: expectedVersionM,
			Actual:    actual,
		}
		return "", nil, VersionUnknown, err
	}

	return hrp, decoded[:len(decoded)-6], bech32Version, nil
}

func DecodeNoLimit(bech string) (string, []byte, error) {
	hrp, data, _, err := decodeNoLimit(bech)
	return hrp, data, err
}

func Decode(bech string) (string, []byte, error) {
	if len(bech) > 90 {
		return "", nil, ErrInvalidLength(len(bech))
	}

	hrp, data, _, err := decodeNoLimit(bech)
	return hrp, data, err
}

func DecodeGeneric(bech string) (string, []byte, Version, error) {
	if len(bech) > 90 {
		return "", nil, VersionUnknown, ErrInvalidLength(len(bech))
	}

	return decodeNoLimit(bech)
}

func encodeGeneric(hrp string, data []byte,
	version Version) (string, error) {

	hrp = strings.ToLower(hrp)
	var bldr strings.Builder
	bldr.Grow(len(hrp) + 1 + len(data) + 6)
	bldr.WriteString(hrp)
	bldr.WriteString("1")

	for _, b := range data {
		if int(b) >= len(charset) {
			return "", ErrInvalidDataByte(b)
		}
		bldr.WriteByte(charset[b])
	}

	writeBech32Checksum(hrp, data, &bldr, version)

	return bldr.String(), nil
}

func Encode(hrp string, data []byte) (string, error) {
	return encodeGeneric(hrp, data, Version0)
}

func EncodeM(hrp string, data []byte) (string, error) {
	return encodeGeneric(hrp, data, VersionM)
}

func ConvertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	if fromBits < 1 || fromBits > 8 || toBits < 1 || toBits > 8 {
		return nil, ErrInvalidBitGroups{}
	}

	maxSize := len(data)*int(fromBits)/int(toBits) + 1

	regrouped := make([]byte, 0, maxSize)

	nextByte := byte(0)
	filledBits := uint8(0)

	for _, b := range data {

		b = b << (8 - fromBits)

		remFromBits := fromBits
		for remFromBits > 0 {
			remToBits := toBits - filledBits

			toExtract := remFromBits
			if remToBits < toExtract {
				toExtract = remToBits
			}

			nextByte = (nextByte << toExtract) | (b >> (8 - toExtract))

			b = b << toExtract
			remFromBits -= toExtract
			filledBits += toExtract

			if filledBits == toBits {
				regrouped = append(regrouped, nextByte)
				filledBits = 0
				nextByte = 0
			}
		}
	}

	if pad && filledBits > 0 {
		nextByte = nextByte << (toBits - filledBits)
		regrouped = append(regrouped, nextByte)
		filledBits = 0
		nextByte = 0
	}

	if filledBits > 0 && (filledBits > 4 || nextByte != 0) {
		return nil, ErrInvalidIncompleteGroup{}
	}

	return regrouped, nil
}

func EncodeFromBase256(hrp string, data []byte) (string, error) {
	converted, err := ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	return Encode(hrp, converted)
}

func DecodeToBase256(bech string) (string, []byte, error) {
	hrp, data, err := Decode(bech)
	if err != nil {
		return "", nil, err
	}
	converted, err := ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, converted, nil
}
