package findings

// testRand is a small deterministic generator (SplitMix64) for reproducible
// test data. Tests use it instead of math/rand so that no pseudo-random
// package is linked anywhere in the module; it is never security material.
type testRand struct{ state uint64 }

func newTestRand(seed uint64) *testRand { return &testRand{state: seed} }

func (r *testRand) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// Intn returns a value in [0, n) and panics when n <= 0, like math/rand.
func (r *testRand) Intn(n int) int {
	if n <= 0 {
		panic("testRand: n must be positive")
	}
	return int(r.next() % uint64(n)) //nolint:gosec // the remainder is below n, a positive int
}
