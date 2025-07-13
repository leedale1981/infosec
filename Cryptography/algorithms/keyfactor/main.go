package main

import (
	"compsci/keyfactor/components"
	"compsci/keyfactor/crypto"
	"fmt"
)

func main() {
	// Generate keys used for message exchange
	rsa := crypto.NewRSA()
	publicKey, privateKey := rsa.GenerateKeyPair()

	// Some component is sending a message across a network using the public key to encrypt.
	originalMessage := "Hello"
	sender := components.NewSender(publicKey)
	cipher := sender.SendMessage(originalMessage)

	// Some component is receiving the message and has access to the privateKey
	receiver := components.NewReceiver(privateKey)
	decodedMessage := receiver.ReceiveMessage(cipher)

	// Some attacker has intercepted the message cipher and wants to decode it by factorizing the modulus.
	attacker := components.NewAttacker(publicKey)
	crackedDecodedMessage := attacker.DecodeInterceptedMessage(cipher)

	fmt.Println("Original message = ", originalMessage)
	fmt.Println("Receiver decrypted message = ", decodedMessage)
	fmt.Println("Attacker decrypted message = ", crackedDecodedMessage)
}
