package main

import (
	"compsci/keyfactor/components"
	"fmt"
)

func main() {
	// Some component is sending a message across a network.
	originalMessage := "Hello"
	publicExponent := 65537 // known publically
	cipher := components.NewSender(publicExponent).SendMessage(originalMessage)

	// Some attacker has intercepted the message cipher and wants to decode it by factorizing the modulus.
	attacker := components.NewAttacker(publicExponent)
	decodedMessage := attacker.DecodeInterceptedMessage(cipher)

	fmt.Println("Original message = ", originalMessage)
	fmt.Println("Decrypted message= ", decodedMessage)
}
