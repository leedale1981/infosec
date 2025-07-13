package main

import (
	"compsci/keyfactor/components"
	"fmt"
)

func main() {
	// Some component is sending a message across a network.
	originalMessage := "Hello"
	publicExponent := 65537 // known publically
	sender := components.NewSender(publicExponent)
	cipher := sender.SendMessage(originalMessage)

	// Some attacker has intercepted the message cipher and wants to decode it by factorizing the modulus.
	attacker := components.NewAttacker(publicExponent, sender.Modulus)
	decodedMessage := attacker.DecodeInterceptedMessage(cipher)

	fmt.Println("Original message = ", originalMessage)
	fmt.Println("Decrypted message= ", decodedMessage)
}
