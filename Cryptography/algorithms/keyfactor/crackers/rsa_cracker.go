package crackers

type rsaCracker struct{}

func NewRSACracker() *rsaCracker {
	return &rsaCracker{}
}

func (cracker *rsaCracker) Factorize(modulus int) (int, int) {
	for i := 2; i*i <= modulus; i++ {
		if modulus%i == 0 {
			return i, modulus / i
		}
	}
	return -1, -1
}
