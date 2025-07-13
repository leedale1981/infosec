package components

import (
	"compsci/keyfactor/crackers"
	"compsci/keyfactor/crypto"
	"fmt"
	"math/big"
	"time"
)

type attacker struct {
	exponent int
}

func NewAttacker(exponent int) *attacker {
	return &attacker{exponent: exponent}
}

func (attacker *attacker) DecodeInterceptedMessage(cipher []*big.Int) string {
	// Decrypt the cipher by brute force by facorizing n to find the prime factors.
	fmt.Println("Attacker is attempting to decode intercepted cipher")
	rsa := crypto.NewRSA(attacker.exponent)
	start := time.Now()
	computedP, computedQ := crackers.NewRSACracker().Factorize(rsa.Modulus)
	elapsed := time.Since(start)
	fmt.Println("Factorizing n took = ", elapsed)

	phi := (computedP - 1) * (computedQ - 1)
	privateExponent := new(big.Int).ModInverse(big.NewInt(int64(attacker.exponent)), big.NewInt(int64(phi)))

	return rsa.DecryptMessage(cipher, privateExponent, big.NewInt(int64(rsa.Modulus)))
}
