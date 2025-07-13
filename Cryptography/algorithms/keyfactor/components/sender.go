package components

import (
	"compsci/keyfactor/crypto"
	"fmt"
	"math/big"
)

type sender struct {
	publicKey *crypto.Key
}

func NewSender(publicKey *crypto.Key) *sender {
	return &sender{
		publicKey: publicKey,
	}
}

func (sender *sender) SendMessage(message string) []*big.Int {
	fmt.Println("Modulus = ", sender.publicKey.Modulus)
	fmt.Println("RSA Key size = ", sender.publicKey.Modulus.BitLen())
	fmt.Println("Sender is sending message ", message)
	rsa := crypto.NewRSA()
	return rsa.EncryptMessage(message, sender.publicKey)
}
