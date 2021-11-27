package zenon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/lvilar/znn_sdk_go/bech32"

	bip39 "github.com/lvilar/znn_sdk_go/go-bip39"

	"golang.org/x/crypto/sha3"
)

type KeyStore struct {
	Mnemonic   string `json:"mnemonic"`
	Entropy    string `json:"entropy"`
	Seed       string `json:"seed"`
	PrivateKey string `json:"privatekey"`
	PublicKey  string `json:"publickey"`
	Address    string `json:"address"`
	CoreBytes  string `json:"corebytes"`
}

func FromMnemonic(mnemonic string, account int) string {
	if !bip39.IsMnemonicValid(mnemonic) {
		return "Error Mnemonic: " + mnemonic
	}
	e, _ := bip39.EntropyFromMnemonic(mnemonic)
	entropy := hex.EncodeToString(e)
	seed := bip39.NewSeed(mnemonic, "")

	pathVal := "m/44'/73404'/" + fmt.Sprintf("%d", account) + "'"
	privatekey, _ := DeriveForPath(pathVal, seed)
	publickey, _ := privatekey.PublicKey()

	arr0 := make([]byte, 1)
	arr0[0] = 0x00
	arr1 := sha3.Sum256(publickey)

	corebyte := append(arr0[:], arr1[:19]...)
	conv, _ := bech32.ConvertBits(corebyte, 8, 5, true)
	address, _ := bech32.Encode("z", conv)

	ks := &KeyStore{
		Mnemonic:   mnemonic,
		Entropy:    entropy,
		Seed:       hex.EncodeToString(seed),
		PrivateKey: hex.EncodeToString(privatekey.Key),
		PublicKey:  hex.EncodeToString(publickey),
		Address:    address,
		CoreBytes:  hex.EncodeToString(corebyte),
	}
	jsonKS, err := json.Marshal(ks)
	if err != nil {
		fmt.Println(err)
		return err.Error()
	}
	return string(jsonKS)
}
