package main

import (
	"encoding/hex"
	"fmt"

	"github.com/okx/go-wallet-sdk/crypto/bip32"
	"github.com/tyler-smith/go-bip39"

	"github.com/okx/go-wallet-sdk/coins/tron"

	btcec2 "github.com/btcsuite/btcd/btcec/v2"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type ChainType int

const (
	ChainTypeEvm ChainType = iota
	ChainTypeTron
)

func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	return mnemonic, err
}

func GetDerivedPath(index int, chainType ChainType) string {
	switch chainType {
	case ChainTypeEvm:
		{
			return fmt.Sprintf(`m/44'/60'/0'/0/%d`, index)
		}
	case ChainTypeTron:
		{
			return fmt.Sprintf(`m/44'/195'/0'/0/%d`, index)
		}
	default:
		{
			return ""
		}
	}
}

func GetDerivedPrivateKey(mnemonic string, hdPath string) (string, error) {
	seed := bip39.NewSeed(mnemonic, "") // 由助记词生成种子
	rp, err := bip32.NewMasterKey(seed)
	if err != nil {
		return "", err
	}
	c, err := rp.NewChildKeyByPathString(hdPath)
	if err != nil {
		return "", err
	}
	childPrivateKey := hex.EncodeToString(c.Key.Key)
	return childPrivateKey, nil
}

func create(chainType ChainType, mnemonic string) {
	hdPath := GetDerivedPath(0, chainType)
	derivePrivateKey, err := GetDerivedPrivateKey(mnemonic, hdPath)
	if err != nil {
		return
	}
	fmt.Println("generate derived private key:", derivePrivateKey, ",derived path: ", hdPath)
	pubKeyHex := derivePrivateKey
	privateKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return
	}
	privateKey, publicKey := btcec2.PrivKeyFromBytes(privateKeyBytes)
	if privateKey == nil {
		return
	}
	switch chainType {
	case ChainTypeEvm:
		{
			// 将secp256k1.PublicKey转换为ecdsa.PublicKey
			ecdsaPublicKey := publicKey.ToECDSA()

			// 1. 将公钥序列化为字节格式
			pubBytes := crypto.FromECDSAPub(ecdsaPublicKey)

			// 2. 对序列化后的公钥进行Keccak256哈希运算
			hash := crypto.Keccak256(pubBytes[1:]) // 注意：我们只对公钥的x,y坐标进行哈希，所以需要去掉第一个字节

			// 3. 取哈希值的最后20个字节作为地址
			address := common.BytesToAddress(hash[12:])

			fmt.Println(address.Hex()) // 输出地址
			break
		}
	case ChainTypeTron:
		{
			addr := tron.GetAddress(publicKey)
			fmt.Println(addr)
			break
		}
	}
}

func main() {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		return
	}
	fmt.Println(mnemonic)
	create(ChainTypeTron, mnemonic)
	create(ChainTypeEvm, mnemonic)
}
