package components

import (
	"compsci/keyfactor/crypto"
	"fmt"
	"math/big"
)

type sender struct {
	exponent int
}

func NewSender(exponent int) *sender {
	return &sender{
		exponent: exponent,
	}
}

func (sender *sender) SendMessage(message string) []*big.Int {
	rsa := crypto.NewRSA(sender.exponent)
	fmt.Println("Modulus = ", rsa.Modulus)
	fmt.Println("RSA Key size = ", bitLength(rsa.Modulus))
	fmt.Println("Sender is sending message ", message)
	return rsa.EncryptMessage(message)
}

func bitLength(n int) int {
	length := 0
	for n > 0 {
		length++
		n >>= 1
	}
	return length
}
