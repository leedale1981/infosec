package components

import (
	"compsci/keyfactor/crypto"
	"fmt"
	"math/big"
)

type sender struct {
	exponent int
	Modulus  *big.Int
}

func NewSender(exponent int) *sender {
	return &sender{
		exponent: exponent,
	}
}

func (sender *sender) SendMessage(message string) []*big.Int {
	// Generate primes used to calculate the modulus
	p := new(big.Int)
	p.SetString("18446744073709551557", 10)
	q := new(big.Int)
	q.SetString("18446744073709551533", 10)
	sender.Modulus = new(big.Int).Mul(p, q)

	rsa := crypto.NewRSA(sender.exponent, p, q)
	fmt.Println("Modulus = ", rsa.Modulus)
	fmt.Println("RSA Key size = ", rsa.Modulus.BitLen())
	fmt.Println("Sender is sending message ", message)
	return rsa.EncryptMessage(message)
}
