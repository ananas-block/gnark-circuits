package emfield

import "math/big"

func quarticColumns(columns nativeMatrix, height int) nativeMatrix {
	rows := newMatrix(height, len(columns))
	for i := range rows {
		for j, column := range columns {
			if i < len(column) {
				rows[i][j].Set(column[i])
			}
		}
	}
	return rows
}

func linearCombination(q *big.Int, rows [][]*big.Int, coefs ...*big.Int) []*big.Int {
	out := make([]*big.Int, len(rows[0]))
	for j := range out {
		out[j] = new(big.Int)
		for i, c := range coefs {
			out[j].Add(out[j], new(big.Int).Mul(c, rows[i][j]))
		}
		out[j].Mod(out[j], q)
	}
	return out
}

func quarticCenteredTower(g poly, q *big.Int) (nativeMatrix, nativeMatrix, *big.Int, poly) {
	if polyDeg(g) != 4 {
		panic("quartic tower needs a degree-four factor")
	}
	half := new(big.Int).ModInverse(big.NewInt(2), q)
	scale := func(p poly, c *big.Int) poly { return polyMul(p, poly{c}, q) }
	var beta, gamma poly
	q2 := new(big.Int).Mul(q, q)
	for i := 1; i < 4 && (beta == nil || gamma == nil); i++ {
		z := make(poly, i+1)
		for j := range z {
			z[j] = new(big.Int)
		}
		z[i].SetInt64(1)
		conj := polyPowMod(z, q2, g, q)
		trace := polySub(z, scale(conj, big.NewInt(-1)), q)
		if beta == nil && polyDeg(trace) > 0 {
			beta = scale(trace, half)
		}
		anti := polySub(z, conj, q)
		if gamma == nil && len(anti) > 0 {
			gamma = scale(anti, half)
		}
	}
	if beta == nil || gamma == nil {
		panic("missing quadratic tower generators")
	}
	trace := polySub(beta, scale(polyPowMod(beta, q, g, q), big.NewInt(-1)), q)
	if polyDeg(trace) > 0 {
		panic("quadratic trace is not constant")
	}
	if len(trace) > 0 {
		beta = polySub(beta, scale(trace, half), q)
	}
	beta2 := polyMod(polyMul(beta, beta, q), g, q)
	if polyDeg(beta2) != 0 {
		panic("centered quadratic generator does not square to a scalar")
	}
	basis := nativeMatrix{{big.NewInt(1)}, beta, gamma, polyMod(polyMul(beta, gamma, q), g, q)}
	inverse := matrixInverse(quarticColumns(basis, 4), q)
	if inverse == nil {
		panic("singular extension basis")
	}
	gamma2 := polyMod(polyMul(gamma, gamma, q), g, q)
	coords := matrixMultiply(inverse, quarticColumns(nativeMatrix{gamma2}, 4), q)
	if coords[2][0].Sign() != 0 || coords[3][0].Sign() != 0 {
		panic("outer generator square is not in the quadratic subfield")
	}
	return basis, inverse, beta2[0], gamma2
}

func (b *crtBasis) appendQuarticKaraSquare(f, g, idem poly, n int, q *big.Int) {
	basis, inverse, d, gamma2 := quarticCenteredTower(g, q)
	forms := matrixMultiply(inverse, quarticColumns(residueColumns(n, g, q), 4), q)
	one, zero := big.NewInt(1), new(big.Int)
	ab0 := linearCombination(q, forms, one, zero, one, zero)
	ab1 := linearCombination(q, forms, zero, one, zero, one)
	var left, right nativeMatrix
	for _, pair := range []nativeMatrix{forms[:2], forms[2:], {ab0, ab1}} {
		left = append(left, pair[0], linearCombination(q, pair, one, one))
		right = append(right, pair[1], linearCombination(q, pair, one, d))
	}

	beta, gamma := basis[1], basis[2]
	h := polySub(polyMul(beta, poly{big.NewInt(2)}, q), poly{new(big.Int).Add(one, d)}, q)
	var lifted nativeMatrix
	for _, weight := range []poly{polySub(poly{one}, gamma, q), polySub(gamma2, gamma, q), gamma} {
		lifted = append(lifted,
			polyMod(polyMul(idem, polyMul(h, weight, q), q), f, q),
			polyMod(polyMul(idem, weight, q), f, q))
	}
	combine := quarticColumns(lifted, n)
	checkQuarticSquareTensor(f, idem, left, right, combine, q)
	b.squareLeft = append(b.squareLeft, left...)
	b.squareRight = append(b.squareRight, right...)
	for j := range b.squareCombine {
		b.squareCombine[j] = append(b.squareCombine[j], combine[j]...)
	}
}

func checkQuarticSquareTensor(f, idem poly, left, right, combine nativeMatrix, q *big.Int) {
	n := len(combine)
	powers := residueColumns(2*n-1, f, q)
	for i := 0; i < n; i++ {
		for l := i; l < n; l++ {
			products := make(nativeMatrix, len(left))
			for k := range products {
				v := new(big.Int).Mul(left[k][i], right[k][l])
				if i != l {
					v.Add(v, new(big.Int).Mul(left[k][l], right[k][i]))
				}
				products[k] = []*big.Int{v}
			}
			want := polyMod(polyMul(idem, powers[i+l], q), f, q)
			if i != l {
				want = polyMul(want, poly{big.NewInt(2)}, q)
			}
			actual := matrixMultiply(combine, products, q)
			got := make(poly, n)
			for j := range got {
				got[j] = actual[j][0]
			}
			if len(polySub(got, want, q)) != 0 {
				panic("quartic Karatsuba square tensor mismatch")
			}
		}
	}
}
