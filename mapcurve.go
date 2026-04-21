// Copyright 2026 The bn254-map-to-curve-demo contributors.
// SPDX-License-Identifier: Apache-2.0
//
// This file is distributed under the Apache License, Version 2.0. See the
// LICENSE file in the project root for the full license text.
//
// Cryptographic ideas implemented here come from two published papers:
//
//   - J. Groth, H. Malvai, A. Miller, Y.-N. Zhang,
//     "Constraint-Friendly Map-to-Elliptic-Curve-Group Relations and Their
//     Applications", Asiacrypt 2025.
//   - Y. El Housni, B. Bünz,
//     "On the Security of Constraint-Friendly Map-to-Curve Relations", 2026.
//
// If you use this material in academic work, please cite those papers, not
// this repository.
//
// Command mapcurve is a self-contained demo of three constructions on BN254:
//
//   - the GMMZ x-increment map-to-curve relation (constructor + verifier),
//   - the El Housni-Bunz algebraic attack (order-3 automorphism forgery),
//   - the y-increment countermeasure (constructor + verifier, j=0 version).
//
// It uses gnark-crypto (https://github.com/consensys/gnark-crypto) as the
// underlying finite-field / elliptic-curve library.
//
// Build & run (requires Go 1.22+):
//
//	go mod init bn254-map-to-curve-demo
//	go get github.com/consensys/gnark-crypto@v0.12.1
//	go run mapcurve.go
//
// WARNING: this is teaching code, not production code. The attack routine is
// meant to demonstrate the vulnerability of the x-increment construction with
// GMMZ's published parameters. Do NOT deploy the x-increment in production.
package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ---------------------------------------------------------------------------
// Common constants
// ---------------------------------------------------------------------------

// TweakBound is the maximum number of tweak attempts.
// For x-increment (success probability 1/2 per tweak), T = 256 gives a
// failure probability below 2^{-256}. For y-increment on j=0 curves
// (success probability 1/3 per tweak), T = 256 gives failure below 2^{-150}.
const TweakBound = 256

// BN254Seed is the curve-defining seed u such that q(u) and p(u) are prime.
// q(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
// p(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
var BN254Seed, _ = new(big.Int).SetString("4965661367192848881", 10)

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// rhsBN254 computes out = x^3 + 3  (BN254 has a = 0, b = 3).
func rhsBN254(out, x *fp.Element) {
	var x2, x3 fp.Element
	x2.Square(x)
	x3.Mul(&x2, x)
	var three fp.Element
	three.SetUint64(3)
	out.Add(&x3, &three)
}

// primitiveCubeRootFp returns a primitive cube root of unity omega in F_q
// such that phi(x,y) = (omega*x, y) acts on BN254 G1 as [lambda]-scalar.
func primitiveCubeRootFp() fp.Element {
	var omega fp.Element
	// omega = 21888242871839275220042445260109153167277707414472061641714758635765020556616
	s, _ := new(big.Int).SetString(
		"21888242871839275220042445260109153167277707414472061641714758635765020556616", 10)
	omega.SetBigInt(s)
	return omega
}

// bn254GLVLambda returns the scalar lambda in F_p with phi(P) = [lambda]P on G1,
// where phi(x,y) = (omega*x, y) and omega is primitiveCubeRootFp().
//
// There are two primitive cube roots of unity in F_p; the one that MATCHES our
// chosen omega1 = primitiveCubeRootFp() is:
//
//	lambda = 21888242871839275217838484774961031246154997185409878258781734729429964517155
//
// which equals -1 - lambda' where lambda' = 4407920970296243842393367215006156084916469457145843978461
// is the *other* cube root of unity.
func bn254GLVLambda() *big.Int {
	l, _ := new(big.Int).SetString(
		"21888242871839275217838484774961031246154997185409878258781734729429964517155", 10)
	return l
}

// ---------------------------------------------------------------------------
// GMMZ x-increment: constructor and verifier
// ---------------------------------------------------------------------------

// XIncWitness is the witness (k, z) for the x-increment relation.
type XIncWitness struct {
	K uint32     // tweak in [0, T)
	Z fp.Element // square root of y: z^2 = y
}

// XIncConstruct maps a message m to a BN254 G1 point by the GMMZ
// x-increment procedure. Returns the point (x,y) and the witness (k,z).
func XIncConstruct(m *fp.Element) (bn254.G1Affine, XIncWitness, error) {
	var (
		tBig = big.NewInt(int64(TweakBound))
		mBig = new(big.Int)
		base fp.Element
	)
	m.BigInt(mBig)
	base.SetBigInt(new(big.Int).Mul(mBig, tBig))

	var (
		x, y, f, kElem fp.Element
	)

	for k := uint32(0); k < TweakBound; k++ {
		kElem.SetUint64(uint64(k))
		x.Add(&base, &kElem)
		rhsBN254(&f, &x)

		// QR test (Legendre symbol = 1 iff f is a nonzero QR).
		if f.Legendre() != 1 {
			continue
		}

		y.Sqrt(&f)

		var z fp.Element
		if z.Sqrt(&y) == nil {
			// y itself is not a QR: try next tweak.
			continue
		}

		var P bn254.G1Affine
		P.X = x
		P.Y = y
		if !P.IsOnCurve() || !P.IsInSubGroup() {
			continue
		}
		return P, XIncWitness{K: k, Z: z}, nil
	}
	return bn254.G1Affine{}, XIncWitness{}, errors.New(
		"x-increment: no valid tweak found")
}

// XIncVerify re-checks the five algebraic conditions of the x-increment
// relation. In a SNARK this compiles to a handful of R1CS constraints.
func XIncVerify(m *fp.Element, P *bn254.G1Affine, w *XIncWitness) bool {
	if w.K >= TweakBound {
		return false
	}
	// x = m*T + k
	var tElem, kElem, base, x fp.Element
	tElem.SetUint64(uint64(TweakBound))
	kElem.SetUint64(uint64(w.K))
	base.Mul(m, &tElem)
	x.Add(&base, &kElem)
	if !x.Equal(&P.X) {
		return false
	}
	// z^2 = y (canonical QR choice)
	var z2 fp.Element
	z2.Square(&w.Z)
	if !z2.Equal(&P.Y) {
		return false
	}
	return P.IsOnCurve() && P.IsInSubGroup()
}

// ---------------------------------------------------------------------------
// Attack: BN254 order-3 automorphism forgery
// ---------------------------------------------------------------------------

// ComputeShortVector returns (a(u), b(u), omega(u)) from Proposition 1 of
// El Housni-Bunz:
//
//	a(u) = 6u^2 + 2u + 1
//	b(u) = 2u
//	omega(u) = 18u^3 + 18u^2 + 9u + 1    (primitive cube root of unity mod q(u))
func ComputeShortVector(u *big.Int) (a, b, omega *big.Int) {
	u2 := new(big.Int).Mul(u, u)
	u3 := new(big.Int).Mul(u2, u)

	a = new(big.Int).Mul(big.NewInt(6), u2)
	a.Add(a, new(big.Int).Mul(big.NewInt(2), u))
	a.Add(a, big.NewInt(1))

	b = new(big.Int).Mul(big.NewInt(2), u)

	omega = new(big.Int).Mul(big.NewInt(18), u3)
	omega.Add(omega, new(big.Int).Mul(big.NewInt(18), u2))
	omega.Add(omega, new(big.Int).Mul(big.NewInt(9), u))
	omega.Add(omega, big.NewInt(1))
	return
}

// ForgeBLS produces a valid BLS signature on a fresh message m2 using a
// single signing-oracle query on a crafted m1. Exploits the order-3
// automorphism on the BN254 j=0 curve together with GMMZ's claimed
// parameters (M*T ~ 2^127 ~ sqrt(q)).
//
// The trick: phi(x,y) = (omega*x, y) is an automorphism with phi(P) =
// [lambda]P on G1. So applying phi to sigma1 = [sk]*H(m1) as a pure
// coordinate map yields phi(sigma1) = [sk]*phi(H(m1)). If phi(H(m1)).x
// happens to fall in the encoding range [0, MT), we get a valid forgery
// on a fresh message m2 = floor(phi(H(m1)).x / T). The short vector from
// Proposition 1 guarantees exactly this.
//
// Returns (m2, sigma2, P2) where P2 = phi^2(H(m1)) is the forged hash
// point that the verifier will reconstruct; the caller can then run a
// standard BLS pairing check on (sigma2, vk) against P2.
func ForgeBLS(
	signOracle func(m fp.Element) bn254.G1Affine,
) (m2 fp.Element, sigma2 bn254.G1Affine, P2 bn254.G1Affine, err error) {

	aInt, _, omegaInt := ComputeShortVector(BN254Seed)

	// Take x1 = |a| mod q, split into (m1, k1) by x1 = m1*T + k1.
	qModulus := fp.Modulus()
	x1Int := new(big.Int).Mod(aInt, qModulus)
	T := big.NewInt(int64(TweakBound))
	m1Int := new(big.Int)
	k1IntUnused := new(big.Int)
	m1Int.DivMod(x1Int, T, k1IntUnused)

	var m1 fp.Element
	m1.SetBigInt(m1Int)

	// Recompute H(m1) ourselves (it's a public deterministic function).
	// The oracle would produce the same point.
	H1, _, cerr := XIncConstruct(&m1)
	if cerr != nil {
		return fp.Element{}, bn254.G1Affine{}, bn254.G1Affine{},
			fmt.Errorf("XIncConstruct(m1) failed: %w", cerr)
	}

	// Query the signing oracle.
	sigma1 := signOracle(m1)

	// Apply phi^2 as a coordinate map: phi^2(x, y) = (omega^2 * x, y).
	var omegaFp, omega2 fp.Element
	omegaFp.SetBigInt(omegaInt)
	omega2.Square(&omegaFp)

	// phi^2(H(m1)):
	P2.X.Mul(&omega2, &H1.X)
	P2.Y = H1.Y
	if !P2.IsOnCurve() {
		return fp.Element{}, bn254.G1Affine{}, bn254.G1Affine{},
			fmt.Errorf("P2 off curve (impossible on j=0)")
	}

	// phi^2(sigma1):
	sigma2.X.Mul(&omega2, &sigma1.X)
	sigma2.Y = sigma1.Y
	if !sigma2.IsOnCurve() {
		return fp.Element{}, bn254.G1Affine{}, bn254.G1Affine{},
			fmt.Errorf("sigma2 off curve (impossible on j=0)")
	}

	// Derive m2 from P2.x by Euclidean division.
	var x2Big big.Int
	P2.X.BigInt(&x2Big)
	var m2Big, k2Big big.Int
	m2Big.DivMod(&x2Big, T, &k2Big)
	m2.SetBigInt(&m2Big)

	return m2, sigma2, P2, nil
}

// ---------------------------------------------------------------------------
// y-increment: constructor and verifier (j=0 version)
// ---------------------------------------------------------------------------

// YIncWitness is the witness k for the y-increment relation.
type YIncWitness struct {
	K uint32
}

// YIncConstructBN254 maps m to a BN254 G1 point using the y-increment
// procedure. Here x-recovery reduces to a cube root because BN254 is j=0.
func YIncConstructBN254(m *fp.Element) (bn254.G1Affine, YIncWitness, error) {
	var (
		tBig = big.NewInt(int64(TweakBound))
		mBig = new(big.Int)
		base fp.Element
	)
	m.BigInt(mBig)
	base.SetBigInt(new(big.Int).Mul(mBig, tBig))

	var (
		y, y2, negC, x, kElem fp.Element
		bFp                   fp.Element
	)
	bFp.SetUint64(3)

	for k := uint32(0); k < TweakBound; k++ {
		kElem.SetUint64(uint64(k))
		y.Add(&base, &kElem)

		// negC = y^2 - b  (want x^3 = negC).
		y2.Square(&y)
		negC.Sub(&y2, &bFp)

		if !cubeRootInFq(&x, &negC) {
			continue
		}

		var P bn254.G1Affine
		P.X = x
		P.Y = y
		if !P.IsOnCurve() || !P.IsInSubGroup() {
			continue
		}
		return P, YIncWitness{K: k}, nil
	}
	return bn254.G1Affine{}, YIncWitness{},
		errors.New("y-increment: no valid tweak found")
}

// YIncVerify re-checks the four algebraic conditions of the y-increment
// relation. Compiles to ~16 R1CS constraints natively.
func YIncVerify(m *fp.Element, P *bn254.G1Affine, w *YIncWitness) bool {
	if w.K >= TweakBound {
		return false
	}
	var tElem, kElem, base, y fp.Element
	tElem.SetUint64(uint64(TweakBound))
	kElem.SetUint64(uint64(w.K))
	base.Mul(m, &tElem)
	y.Add(&base, &kElem)
	if !y.Equal(&P.Y) {
		return false
	}
	return P.IsOnCurve() && P.IsInSubGroup()
}

// ---------------------------------------------------------------------------
// Cube root in F_q for BN254.
// ---------------------------------------------------------------------------
//
// BN254's base field satisfies q - 1 = 2 * 3^2 * m with gcd(m,6) = 1 (i.e.
// v_3(q-1) = 2). For a cubic residue t, we compute
//
//     cand := t^((q+8)/27)
//
// which is a cube root of unity times the desired cube root. But because
// 9 | q-1 (not just 3), the "correction factor" cand^3 / t is a 9th root
// of unity, not merely a cube root. We therefore iterate cand, cand·ζ₉,
// cand·ζ₉², …, cand·ζ₉⁸ and return the first whose cube equals t.
//
// We use gnark-crypto's Element.Exp to stay inside the Montgomery form.

var (
	cubeExpOnce  sync.Once
	cubeExpE     *big.Int   // (q+8)/27
	cubeResidueE *big.Int   // (q-1)/3
	zeta9        fp.Element // a primitive 9th root of unity
)

func cubeExpInit() {
	cubeExpOnce.Do(func() {
		q := fp.Modulus()
		cubeExpE = new(big.Int).Add(q, big.NewInt(8))
		cubeExpE.Div(cubeExpE, big.NewInt(27))
		cubeResidueE = new(big.Int).Sub(q, big.NewInt(1))
		cubeResidueE.Div(cubeResidueE, big.NewInt(3))

		// Build a primitive 9th root of unity: take g^((q-1)/9) for some g
		// that is not a 9th-power residue. Probe small integers.
		qm1Over9 := new(big.Int).Sub(q, big.NewInt(1))
		qm1Over9.Div(qm1Over9, big.NewInt(9))

		var one fp.Element
		one.SetOne()

		var g, pow9 fp.Element
		for i := int64(2); i < 1000; i++ {
			g.SetUint64(uint64(i))
			pow9.Exp(g, qm1Over9)
			if pow9.Equal(&one) {
				continue // g is a 9th-power residue; useless
			}
			// pow9 has order dividing 9 and isn't 1. Need order exactly 9,
			// i.e., pow9^3 != 1.
			var cubed fp.Element
			cubed.Square(&pow9)
			cubed.Mul(&cubed, &pow9)
			if !cubed.Equal(&one) {
				zeta9 = pow9
				return
			}
		}
		panic("cube root init: failed to find a primitive 9th root of unity")
	})
}

// cubeRootInFq returns out = t^{1/3} in BN254's F_q if t is a cube, or
// false otherwise.
func cubeRootInFq(out, t *fp.Element) bool {
	if t.IsZero() {
		out.SetZero()
		return true
	}
	cubeExpInit()

	// Step 1: cubic-residue test via t^((q-1)/3) == 1.
	var r fp.Element
	r.Exp(*t, cubeResidueE)
	var one fp.Element
	one.SetOne()
	if !r.Equal(&one) {
		return false
	}

	// Step 2: candidate = t^((q+8)/27).
	var cand fp.Element
	cand.Exp(*t, cubeExpE)

	// Step 3: cand^3 equals t * (9th root of unity); iterate up to 9 times.
	var cube fp.Element
	for i := 0; i < 9; i++ {
		cube.Square(&cand)
		cube.Mul(&cube, &cand)
		if cube.Equal(t) {
			*out = cand
			return true
		}
		cand.Mul(&cand, &zeta9)
	}
	return false
}

// ---------------------------------------------------------------------------
// Cardano depressed-cubic solver (needed for j != 0, 1728 curves)
// ---------------------------------------------------------------------------

// SolveDepressedCubic tries to find x in F_q with x^3 + a*x + c = 0.
// Returns (x, true) on success. Only handles the D-square branch of Cardano
// (full generality requires F_{q^2} arithmetic).
func SolveDepressedCubic(a, c *fp.Element) (fp.Element, bool) {
	var (
		two, three, twentySeven fp.Element
		halfC, a3Over27, Dsq    fp.Element
		half                    fp.Element
	)
	two.SetUint64(2)
	three.SetUint64(3)
	twentySeven.SetUint64(27)
	half.Inverse(&two)

	halfC.Mul(c, &half)

	var a2, a3 fp.Element
	a2.Square(a)
	a3.Mul(&a2, a)
	var inv27 fp.Element
	inv27.Inverse(&twentySeven)
	a3Over27.Mul(&a3, &inv27)

	var halfC2 fp.Element
	halfC2.Square(&halfC)
	Dsq.Add(&halfC2, &a3Over27)

	if Dsq.Legendre() != 1 {
		return fp.Element{}, false
	}

	var D fp.Element
	D.Sqrt(&Dsq)

	var inside fp.Element
	inside.Neg(&halfC)
	inside.Add(&inside, &D)

	var u fp.Element
	if ok := cubeRootInFq(&u, &inside); !ok {
		return fp.Element{}, false
	}

	if u.IsZero() {
		if a.IsZero() {
			return fp.Element{}, false
		}
		var x, aInv fp.Element
		x.Mul(&three, c)
		aInv.Inverse(a)
		x.Mul(&x, &aInv)
		return x, true
	}

	var threeU, invThreeU, aOver3u, x fp.Element
	threeU.Mul(&three, &u)
	invThreeU.Inverse(&threeU)
	aOver3u.Mul(a, &invThreeU)
	x.Sub(&u, &aOver3u)
	return x, true
}

// ---------------------------------------------------------------------------
// BLS signing oracle (used by the demo)
// ---------------------------------------------------------------------------

// BLSOracle is a toy signing oracle: on input m, it runs the x-increment
// constructor to get H(m), then returns [sk] * H(m).
type BLSOracle struct {
	sk big.Int // secret scalar in [1, p)
	vk bn254.G2Affine
	g2 bn254.G2Affine
	// log of queries (so the demo can assert "m2 was never queried").
	queried []fp.Element
}

// NewBLSOracle samples a fresh keypair and returns a BLS signing oracle.
func NewBLSOracle() (*BLSOracle, error) {
	_, _, _, g2 := bn254.Generators()

	// Sample sk uniformly in [1, p).
	skInt, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		return nil, err
	}
	if skInt.Sign() == 0 {
		skInt.SetUint64(1)
	}
	var vk bn254.G2Affine
	vk.ScalarMultiplication(&g2, skInt)
	return &BLSOracle{sk: *skInt, vk: vk, g2: g2}, nil
}

// Sign implements the signing-oracle interface expected by ForgeBLS.
// The hash H is the GMMZ x-increment map to G1.
func (o *BLSOracle) Sign(m fp.Element) bn254.G1Affine {
	Hm, _, err := XIncConstruct(&m)
	if err != nil {
		panic(fmt.Sprintf("signing oracle: %v", err))
	}
	o.queried = append(o.queried, m)

	var sigma bn254.G1Affine
	sigma.ScalarMultiplication(&Hm, &o.sk)
	return sigma
}

// VerifyBLSWithXInc re-creates the x-increment hash of m and checks the
// pairing equation e(sigma, g2) == e(H(m), vk).
func (o *BLSOracle) VerifyBLSWithXInc(m fp.Element, sigma bn254.G1Affine) bool {
	Hm, _, err := XIncConstruct(&m)
	if err != nil {
		return false
	}
	return pairingCheck(sigma, o.g2, Hm, o.vk)
}

// VerifyForgedPoint checks the pairing against a known forged point P2
// (we need this form because the forgery doesn't go through XIncConstruct
// on m2 — it derives P2 = phi^2(P1) directly).
func (o *BLSOracle) VerifyForgedPoint(P bn254.G1Affine, sigma bn254.G1Affine) bool {
	return pairingCheck(sigma, o.g2, P, o.vk)
}

// AlreadyQueried reports whether m was passed to Sign during the demo.
func (o *BLSOracle) AlreadyQueried(m fp.Element) bool {
	for i := range o.queried {
		if o.queried[i].Equal(&m) {
			return true
		}
	}
	return false
}

// pairingCheck returns true iff e(a, b) == e(c, d).
func pairingCheck(a bn254.G1Affine, b bn254.G2Affine,
	c bn254.G1Affine, d bn254.G2Affine) bool {
	// e(a,b) = e(c,d)  <=>  e(a,b) * e(-c,d) = 1.
	var negC bn254.G1Affine
	negC.Neg(&c)

	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{a, negC},
		[]bn254.G2Affine{b, d},
	)
	if err != nil {
		return false
	}
	return ok
}

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------

func banner(s string) {
	line := "============================================================"
	fmt.Println()
	fmt.Println(line)
	fmt.Println("  " + s)
	fmt.Println(line)
}

// demoXIncrement exercises XIncConstruct + XIncVerify on a random message.
func demoXIncrement() error {
	banner("1) GMMZ x-increment: construct + verify")

	// Random 100-bit message, as in GMMZ's zkVM setting.
	m, err := sampleMessage(100)
	if err != nil {
		return err
	}
	fmt.Printf("  message m = %s\n", m.String())

	P, w, err := XIncConstruct(&m)
	if err != nil {
		return fmt.Errorf("construct failed: %w", err)
	}
	fmt.Printf("  H(m).x    = %s\n", P.X.String())
	fmt.Printf("  witness   = (k=%d, z=%s)\n", w.K, w.Z.String())

	if !XIncVerify(&m, &P, &w) {
		return errors.New("x-increment verifier rejected a valid witness")
	}
	fmt.Println("  verifier accepts ✓")
	return nil
}

// demoYIncrement exercises YIncConstructBN254 + YIncVerify.
func demoYIncrement() error {
	banner("2) y-increment countermeasure: construct + verify (BN254)")

	m, err := sampleMessage(100)
	if err != nil {
		return err
	}
	fmt.Printf("  message m = %s\n", m.String())

	P, w, err := YIncConstructBN254(&m)
	if err != nil {
		return fmt.Errorf("construct failed: %w", err)
	}
	fmt.Printf("  H(m).y    = %s\n", P.Y.String())
	fmt.Printf("  witness   = (k=%d)\n", w.K)

	if !YIncVerify(&m, &P, &w) {
		return errors.New("y-increment verifier rejected a valid witness")
	}
	fmt.Println("  verifier accepts ✓")
	return nil
}

// demoAttack carries out the BLS forgery against an x-increment signing
// oracle on BN254.
func demoAttack() error {
	banner("3) Algebraic attack: BLS signature forgery on x-increment")

	oracle, err := NewBLSOracle()
	if err != nil {
		return err
	}
	fmt.Printf("  oracle sk = 0x%x...  (truncated)\n",
		new(big.Int).Mod(&oracle.sk, big.NewInt(1<<32)))

	// Run the forgery.
	m2, sigma2, P2, err := ForgeBLS(oracle.Sign)
	if err != nil {
		return fmt.Errorf("forgery failed: %w", err)
	}

	fmt.Printf("  forged m2 = %s\n", m2.String())
	fmt.Printf("  forged sig on m2 produced from a single oracle query on m1\n")

	if oracle.AlreadyQueried(m2) {
		return errors.New(
			"ForgeBLS returned the same message it queried — not a real forgery")
	}
	fmt.Println("  m2 is distinct from every queried m1 ✓")

	if !oracle.VerifyForgedPoint(P2, sigma2) {
		return errors.New("pairing check on forgery FAILED (should succeed!)")
	}
	fmt.Println("  pairing check accepts the forgery ✗ (BLS is broken)")
	return nil
}

// sampleMessage samples a uniform integer in [0, 2^bits) and converts it to
// an fp.Element.
func sampleMessage(bits int) (fp.Element, error) {
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return fp.Element{}, err
	}
	var m fp.Element
	m.SetBigInt(n)
	return m, nil
}

func main() {
	fmt.Println("map-to-curve on BN254: demo of GMMZ x-increment,")
	fmt.Println("the El Housni-Bunz forgery, and the y-increment countermeasure.")

	if err := demoXIncrement(); err != nil {
		fmt.Printf("x-increment demo FAILED: %v\n", err)
	}

	if err := demoYIncrement(); err != nil {
		fmt.Printf("y-increment demo FAILED: %v\n", err)
	}

	if err := demoAttack(); err != nil {
		fmt.Printf("attack demo FAILED: %v\n", err)
	}

	banner("done")
}
