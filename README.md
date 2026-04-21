# bn254-map-to-curve-demo

A self-contained Go demonstration of three constructions on the BN254
elliptic curve, covering two recent academic papers:

1. **GMMZ x-increment** — a constraint-friendly map-to-curve relation
   (Groth, Malvai, Miller, Zhang; Asiacrypt 2025)
2. **Order-3 automorphism forgery** — a concrete BLS signature forgery
   that breaks the x-increment when M·T ≳ √q
   (El Housni, Bünz; 2026)
3. **y-increment countermeasure** — the same authors' fix, which
   neutralises the automorphism by encoding into the y-coordinate

The program runs all three end-to-end on BN254 and prints the result of
each. The third section is the main pedagogical point: the BLS verifier
accepts a signature on a message the signing oracle was **never queried
on** — an existential forgery, the definitional failure of EUF-CMA
security.

---

## ⚠️ Disclaimer

This is **teaching code** that reproduces a cryptographic weakness
published in peer-reviewed academic work. It is **not a zero-day**:

- The attack was publicly disclosed by El Housni & Bünz in 2026.
- The GMMZ authors acknowledged the gap and committed to tightening
  their parameter constraints in a revised version.
- To the best of the original authors' knowledge, **no production
  system currently deploys the vulnerable x-increment construction**.

Do **not** ship the x-increment in any real system. The y-increment
fix in this repo is provably secure in the standard EC-GGM and should
be preferred wherever a constraint-friendly map-to-curve is needed.

This repo is provided **for education and reproducibility only**, with
no warranty of any kind. The author accepts no responsibility for
misuse.

---

## 📚 Attribution

All the cryptographic ideas in this repo come from the following two
papers. If you use this material in academic work, **cite the papers,
not this repo**.

### Primary references

- **Jens Groth, Harjasleen Malvai, Andrew Miller, Yi-Nuo Zhang.**
  *Constraint-Friendly Map-to-Elliptic-Curve-Group Relations and Their
  Applications.* Asiacrypt 2025.
- **Youssef El Housni, Benedikt Bünz.**
  *On the Security of Constraint-Friendly Map-to-Curve Relations.* 2026.

### Reference implementations by the original authors

- [Jasleen1/map-to-curve](https://github.com/Jasleen1/map-to-curve) —
  GMMZ's own Noir circuits.
- [yelhousni/map-to-curve](https://github.com/yelhousni/map-to-curve) —
  El Housni–Bünz's artifact: SageMath attack simulation, gnark circuits
  for both constructions, constraint-count benchmarks.

This repo is an **independent Go re-implementation written for
pedagogy**. It does not claim to be faithful to either paper's exact
engineering choices; it sacrifices performance for clarity, and omits
the BLS12-377 / P-256 / emulated-field variants that appear in the
official artifacts.

---

## 🚀 Quick start

### Requirements

- Go 1.22 or newer
- An internet connection (one-time, to fetch `gnark-crypto`)

### Build and run

```bash
git clone https://github.com/umitaygul/bn254-map-to-curve-demo.git
cd bn254-map-to-curve-demo
GOSUMDB=off go build -o mapcurve .
./mapcurve          # Linux/macOS
.\mapcurve.exe      # Windows
```

`GOSUMDB=off` is only needed because the bundled `go.mod` uses `replace`
directives to redirect `golang.org/x/sys` and `rsc.io/tmplfunc` to
their GitHub mirrors (useful for sandboxed/firewalled environments). On
a normal developer machine you can delete the `replace` block and use:

```bash
go mod init bn254-map-to-curve-demo
go get github.com/consensys/gnark-crypto@v0.12.1
go build .
```

### Expected output

```
map-to-curve on BN254: demo of GMMZ x-increment,
the El Housni-Bunz forgery, and the y-increment countermeasure.

============================================================
  1) GMMZ x-increment: construct + verify
============================================================
  ...
  verifier accepts ✓

============================================================
  2) y-increment countermeasure: construct + verify (BN254)
============================================================
  ...
  verifier accepts ✓

============================================================
  3) Algebraic attack: BLS signature forgery on x-increment
============================================================
  ...
  m2 is distinct from every queried m1 ✓
  pairing check accepts the forgery ✗ (BLS is broken)

============================================================
  done
============================================================
```

Numeric values differ each run because of fresh randomness (new secret
key, new sampled 100-bit messages). A sample full run is recorded in
`demo_output.txt` for reproducibility.

---

## 📄 What's in this repo

| File                | What it is                                                     |
|---------------------|----------------------------------------------------------------|
| `mapcurve.go`       | Single-file Go implementation: constructors, verifiers, attack |
| `go.mod`            | Go module pinning gnark-crypto v0.12.1 + mirror redirects      |
| `README.md`         | This file                                                      |
| `LICENSE`           | Apache 2.0 (matching gnark-crypto's license)                   |
| `demo_output.txt`   | Sample captured output of a clean run                          |
| `map_to_curve.pdf`  | 19-page technical companion document (LaTeX)                   |
| `map_to_curve.tex`  | LaTeX source of the companion                                  |

### The companion PDF

`map_to_curve.pdf` walks through the mathematics of both papers in
unified notation: the EC-GGM threat model, the x-increment relation
and why each of its five algebraic constraints matters, the Minkowski
lattice argument behind the attack, the short-vector form for BN curves,
and the y-increment fix with its security proof sketch. It reproduces
key code listings inline alongside the math, so the document and the
Go source are strictly consistent.

---

## 🧪 Verifying the mathematics yourself

If you don't trust my implementation (which you shouldn't — I'm not an
auditor), here are three independent ways to check things:

1. **Run the demo.** If all three sections print ✓, the x-increment
   round-trips, the y-increment round-trips, and the forgery's pairing
   equation holds against a fresh random key. That's a stronger check
   than any static review.
2. **Read the SageMath version.** El Housni–Bünz publish a self-contained
   SageMath attack script in [their artifact](https://github.com/yelhousni/map-to-curve).
   It's more concise than the Go version and closer to paper notation.
3. **Compile the gnark circuits.** Their artifact also contains actual
   gnark circuits for R1CS/PLONK constraint counts on BN254,
   BLS12-377, and P-256 — that's the real production-style reference.

---

## 🤝 Contributing

This repo is primarily for documentation and self-education. If you
spot a mathematical error, a stale API call, or an unclear explanation,
issues and PRs are welcome. For substantive questions about the
underlying cryptography, please engage with the **original authors**
(links in the Attribution section above) — they wrote the papers and
know their construction far better than I do.

---

## 📬 License

Apache License 2.0 — see `LICENSE`. Chosen to match gnark-crypto, so
the two can be composed without license-compatibility questions.
