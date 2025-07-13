package components

import (
	"compsci/keyfactor/crackers"
	"compsci/keyfactor/crypto"
	"fmt"
	"math/big"
	"time"
)

type attacker struct {
	publicKey *crypto.Key
}

func NewAttacker(publicKey *crypto.Key) *attacker {
	return &attacker{publicKey: publicKey}
}

func (attacker *attacker) DecodeInterceptedMessage(cipher []*big.Int) string {
	// Decrypt the cipher by brute force by facorizing n to find the prime factors.
	fmt.Println("Attacker is attempting to decode intercepted cipher")
	start := time.Now()
	//computedP, computedQ := crackers.NewRSACracker().Factorize(attacker.modulus)
	computedP, computedQ := crackers.NewRSACracker().PollardsRho(attacker.publicKey.Modulus)
	elapsed := time.Since(start)
	fmt.Println("Factorizing n took = ", elapsed)

	// This forms the private key used to decrypt the message.
	newP := new(big.Int).Sub(computedP, big.NewInt(1))
	newQ := new(big.Int).Sub(computedQ, big.NewInt(1))
	phi := new(big.Int).Mul(newP, newQ)
	privateExponent := new(big.Int).ModInverse(attacker.publicKey.Exponent, phi)
	rsa := crypto.NewRSA()
	crackedKey := &crypto.Key{Modulus: attacker.publicKey.Modulus, Exponent: privateExponent}
	return rsa.DecryptMessage(cipher, crackedKey)
}
