package main

import (
	"fmt"
	"time"
)

func main() {
	originalMessage := "Hello"
	publicExponent := 17 // known publically
	p := 65521           // private
	q := 65519           // private
	n := p * q           // known publically and its size defines the encryption space.
	fmt.Println("Modulus = ", n)
	fmt.Println("RSA Key size = ", bitLength(n))
	cipher := encrypt(originalMessage, publicExponent, n)

	// Decrypt the cipher by brute force by facorizing n to find the prime factors.
	start := time.Now()
	computedP, computedQ := factorize(n)
	elapsed := time.Since(start)
	fmt.Println("Factorizing n took = ", elapsed)

	phi := (computedP - 1) * (computedQ - 1)           // private
	privateExponent := modInverse(publicExponent, phi) // private

	decodedMessage := decrypt(cipher, privateExponent, n)

	fmt.Println("Original = ", originalMessage)
	fmt.Println("Decrypted = ", decodedMessage)
}

func bitLength(n int) int {
	length := 0
	for n > 0 {
		length++
		n >>= 1
	}
	return length
}

func factorize(n int) (int, int) {
	for i := 2; i*i <= n; i++ {
		if n%i == 0 {
			return i, n / i
		}
	}
	return -1, -1 // Not found
}

func decrypt(cipher []int, d, n int) string {
	plaintext := make([]rune, len(cipher))
	for i, c := range cipher {
		plaintext[i] = rune(modExp(c, d, n) % 128)
	}
	return string(plaintext)
}

func encrypt(message string, e, n int) []int {
	cipher := make([]int, len(message))

	for i, char := range message {
		cipher[i] = modExp(int(char), e, n)
	}
	return cipher
}

func extendedEuclidean(a, b int) (gcd, x, y int) {
	if b == 0 {
		return a, 1, 0
	}
	gcd, x1, y1 := extendedEuclidean(b, a%b)
	x = y1
	y = x1 - (a/b)*y1
	return
}

// Modular exponentiation (m^e mod n)
func modExp(base, exp, mod int) int {
	result := 1
	base %= mod

	for exp > 0 {
		if exp%2 == 1 {
			result = (result * base) % mod
		}
		exp >>= 1
		base = (base * base) % mod
	}
	return result
}

// modInverse finds modular inverse of e mod phi
func modInverse(e, phi int) int {
	gcd, x, _ := extendedEuclidean(e, phi)
	if gcd != 1 {
		return -1 // inverse doesn't exist
	}
	// Ensure positive result
	return (x%phi + phi) % phi
}
