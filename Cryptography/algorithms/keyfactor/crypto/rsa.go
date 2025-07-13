package crypto

import (
	"math/big"
)

type rsa struct {
	exponent int
	Modulus  *big.Int
}

func NewRSA(exponent int, p *big.Int, q *big.Int) *rsa {
	return &rsa{
		exponent: exponent,
		Modulus:  new(big.Int).Mul(p, q),
	}
}

func (rsa *rsa) EncryptMessage(message string) []*big.Int {
	cipher := make([]*big.Int, len(message))

	for i, char := range message {
		cipher[i] = new(big.Int).Exp(big.NewInt(int64(char)), big.NewInt(int64(rsa.exponent)), rsa.Modulus)
	}

	return cipher
}

func (rsa *rsa) DecryptMessage(cipher []*big.Int, d, n *big.Int) string {
	plaintext := make([]rune, len(cipher))
	for i, c := range cipher {
		plaintext[i] = rune(new(big.Int).Exp(c, d, n).Uint64())
	}
	return string(plaintext)
}
