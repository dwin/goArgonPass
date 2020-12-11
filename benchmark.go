package argonpass

import "time"

// Benchmark takes ArgonParams and returns the number of seconds elapsed as a float64 and error.
func Benchmark(params *ArgonParams) (elapsed float64, err error) {
	pass := "benchmarkpass"
	start := time.Now()

	salt, err := generateSalt(params.SaltSize)
	if err != nil {
		return elapsed, err
	}

	_, err = generateHash([]byte(pass), salt, params)

	t := time.Now()
	dur := t.Sub(start)

	return dur.Seconds(), err
}
