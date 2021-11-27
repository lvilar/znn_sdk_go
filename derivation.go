package zenon

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

const (
	FirstHardenedIndex = uint32(0x80000000)
	seedModifier       = "ed25519 seed"
)

var (
	ErrInvalidPath        = errors.New("Invalid derivation path")
	ErrNoPublicDerivation = errors.New("No public derivation for ed25519")
	pathRegex             = regexp.MustCompile(`^m(\/[0-9]+')+$`)
)

type Key struct {
	Key       []byte
	ChainCode []byte
}

func DeriveForPath(path string, seed []byte) (*Key, error) {
	if !isValidPath(path) {
		return nil, ErrInvalidPath
	}

	key, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	segments := strings.Split(path, "/")
	for _, segment := range segments[1:] {
		i64, err := strconv.ParseUint(strings.TrimRight(segment, "'"), 10, 32)
		if err != nil {
			return nil, err
		}
		i := uint32(i64) + FirstHardenedIndex
		key, err = key.Derive(i)
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}

func NewMasterKey(seed []byte) (*Key, error) {
	hmac := hmac.New(sha512.New, []byte(seedModifier))
	_, err := hmac.Write(seed)
	if err != nil {
		return nil, err
	}
	sum := hmac.Sum(nil)
	key := &Key{
		Key:       sum[:32],
		ChainCode: sum[32:],
	}
	return key, nil
}

func (k *Key) Derive(i uint32) (*Key, error) {
	if i < FirstHardenedIndex {
		return nil, ErrNoPublicDerivation
	}

	iBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iBytes, i)
	key := append([]byte{0x0}, k.Key...)
	data := append(key, iBytes...)

	hmac := hmac.New(sha512.New, k.ChainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	sum := hmac.Sum(nil)
	newKey := &Key{
		Key:       sum[:32],
		ChainCode: sum[32:],
	}
	return newKey, nil
}

func (k *Key) PublicKey() ([]byte, error) {
	reader := bytes.NewReader(k.Key)
	pub, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, err
	}
	return pub[:], nil
}

func isValidPath(path string) bool {
	if !pathRegex.MatchString(path) {
		return false
	}

	segments := strings.Split(path, "/")
	for _, segment := range segments[1:] {
		_, err := strconv.ParseUint(strings.TrimRight(segment, "'"), 10, 32)
		if err != nil {
			return false
		}
	}

	return true
}
