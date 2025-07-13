package crypto

import (
	"math/big"
)

type rsa struct{}

type Key struct {
	Modulus  *big.Int
	Exponent *big.Int
}

func NewRSA() *rsa {
	return &rsa{}
}

func (rsa *rsa) GenerateKeyPair() (public *Key, private *Key) {
	// Generate primes used to calculate the modulus
	p := new(big.Int)
	p.SetString("4294967311", 10)
	q := new(big.Int)
	q.SetString("4294967357", 10)
	modulus := new(big.Int).Mul(p, q)
	publicExponent := 65537 // known publically
	newP := new(big.Int).Sub(p, big.NewInt(1))
	newQ := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(newP, newQ)
	privateExponent := new(big.Int).ModInverse(big.NewInt(int64(publicExponent)), phi)

	public = &Key{Modulus: modulus, Exponent: big.NewInt(int64(publicExponent))}
	private = &Key{Modulus: modulus, Exponent: privateExponent}
	return public, private
}

func (rsa *rsa) EncryptMessage(message string, publicKey *Key) []*big.Int {
	cipher := make([]*big.Int, len(message))

	for i, char := range message {
		cipher[i] = new(big.Int).Exp(big.NewInt(int64(char)), publicKey.Exponent, publicKey.Modulus)
	}

	return cipher
}

func (rsa *rsa) DecryptMessage(cipher []*big.Int, privateKey *Key) string {
	plaintext := make([]rune, len(cipher))
	for i, c := range cipher {
		plaintext[i] = rune(new(big.Int).Exp(c, privateKey.Exponent, privateKey.Modulus).Uint64())
	}
	return string(plaintext)
}
