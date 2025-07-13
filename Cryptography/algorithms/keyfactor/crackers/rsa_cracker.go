package crackers

import "math/big"

type rsaCracker struct{}

func NewRSACracker() *rsaCracker {
	return &rsaCracker{}
}

func (cracker *rsaCracker) Factorize(modulus *big.Int) (p, q *big.Int) {
	one := big.NewInt(1)
	i := big.NewInt(2)
	sqrtN := new(big.Int).Sqrt(modulus) // Upper bound: √n

	for i.Cmp(sqrtN) <= 0 {
		if new(big.Int).Mod(modulus, i).Cmp(big.NewInt(0)) == 0 {
			p = new(big.Int).Set(i)
			q = new(big.Int).Div(modulus, i)
			return
		}
		i.Add(i, one)
	}
	return nil, nil // Not found
}

func (cracker *rsaCracker) PollardsRho(n *big.Int) (p, q *big.Int) {
	one := big.NewInt(1)
	x := big.NewInt(2)
	y := big.NewInt(2)
	d := big.NewInt(1)
	f := func(x *big.Int) *big.Int {
		// f(x) = x² + 1 mod n
		x2 := new(big.Int).Mul(x, x)
		x2.Add(x2, one)
		x2.Mod(x2, n)
		return x2
	}

	for d.Cmp(one) == 0 {
		x = f(x)
		y = f(f(y))
		diff := new(big.Int).Sub(x, y)
		d.GCD(nil, nil, diff.Abs(diff), n)
	}

	if d.Cmp(n) == 0 {
		return nil, nil // Failed
	}
	p = d // Found a factor
	q = new(big.Int).Div(n, d)
	return p, q
}
