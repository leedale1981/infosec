package components

import (
	"compsci/keyfactor/crypto"
	"math/big"
)

type receiver struct {
	privateKey *crypto.Key
}

func NewReceiver(privateKey *crypto.Key) *receiver {
	return &receiver{
		privateKey: privateKey,
	}
}

func (receiver *receiver) ReceiveMessage(cipher []*big.Int) string {
	rsa := crypto.NewRSA()
	return rsa.DecryptMessage(cipher, receiver.privateKey)
}
