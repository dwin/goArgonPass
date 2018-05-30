package argonpass

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	algo            = "argon2i"
	currentVersion  = argon2.Version
	defaultSaltSize = 16
	minPassLength   = 8
)

var (
	defaultParams = ArgonParams{Time: 10, Memory: 64 * 1024, Threads: 4, OutputSize: 32, Function: "argon2id"}
	functions     = []string{"argon2i", "argon2id"}
)

// ArgonParams control how the Argon2 function creates the digest output
type ArgonParams struct {
	Time       uint32
	Memory     uint32
	Threads    uint8
	OutputSize uint32
	Function   string
}

// Hash generates a argon2id hash of the input pass string with default settings
// and returns the output in the specified string format and error value
func Hash(pass string, customParams ...ArgonParams) (string, error) {
	// Check input pass length
	if len(pass) < minPassLength {
		return "", ErrPassphraseInputTooShort
	}
	// Check for custom params, if not use default
	var params ArgonParams
	switch len(customParams) {
	case 0:
		params = defaultParams
	case 1:
		params = customParams[0]
	default:
		return "", ErrCustomParameters
	}

	// Generate random salt
	salt, err := generateSalt(defaultSaltSize)
	if err != nil {
		return "", err
	}

	// Generate hash
	passHash, err := generateHash([]byte(pass), salt, params)
	if err != nil {
		return "", err
	}

	// Encode hash to base64
	encodedHash := base64.StdEncoding.EncodeToString(passHash)
	// Encode salt to base64
	encodedSalt := base64.StdEncoding.EncodeToString(salt)

	// Format output string
	// $argon2{function}$v={version}$m={memory},t={time},p={parallelism}${salt(base64)}${digest(base64)}
	// example: $argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
	return fmt.Sprintf("$%s$v=%v$m=%v,t=%v,p=%v$%s$%s", params.Function, currentVersion, params.Memory, params.Time, params.Threads, encodedSalt, encodedHash), nil
}

// Verify regenerates the hash using the supplied pass and compares the value returning an error if the password
// is invalid or another error occurs. Any error should be considered a validation failure.
func Verify(pass, hash string) error {
	// Check valid input
	valid := regexp.MustCompile(`[$]argon2(?:id|i)[$]v=\d\d[$]m=\d{3,12},t=\d{1,4},p=\d{1,2}[$][^$]{1,64}[$][^$]{1,128}`)
	if !valid.MatchString(hash) {
		return ErrInvalidHashFormat
	}

	// Split hash into parts
	part := strings.Split(hash, "$")

	// Get Parameters
	hashParams, err := parseParams(part[3])
	if err != nil {
		return err
	}

	// Check hash function
	switch part[1] {
	case "argon2i":
		hashParams.Function = "argon2i"
	case "argon2id":
		hashParams.Function = "argon2id"
	default:
		return ErrFunctionMismatch
	}

	// Get & Check Version
	hashVersion, err := strconv.Atoi(strings.Trim(part[2], "v="))
	if err != nil {
		return ErrVersion
	}
	// Verify version is not greater than current version or less than 0
	if hashVersion > currentVersion || hashVersion < 0 {
		return ErrVersion
	}

	// Get salt
	salt, err := base64.StdEncoding.DecodeString(part[4])
	if err != nil {
		return ErrDecodingSalt
	}

	// Get argon digest
	decodedHash, err := base64.StdEncoding.DecodeString(part[5])
	if err != nil {
		return ErrDecodingHash
	}

	// Get size of existing hash
	hashParams.OutputSize = uint32(len(decodedHash))

	// Generate hash for comparison using user input with stored parameters
	comparisonHash, err := generateHash([]byte(pass), salt, hashParams)
	if err != nil {
		return err
	}

	// Compare given hash input to generated hash
	for i := range decodedHash {
		if decodedHash[i] != comparisonHash[i] {
			return ErrHashMismatch
		}
		// return nil only if supplied hash and computed hash from passphrase match
		return nil
	}

	return ErrHashMismatch

}

// generateSalt uses int input to return a random a salt for use in crypto operations
func generateSalt(saltLen int) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return salt, ErrSaltGen
	}
	return salt, nil
}

// generateHash takes passphrase and salt as bytes with parameters to provide Argon2 digest output
func generateHash(pass, salt []byte, params ArgonParams) ([]byte, error) {
	switch params.Function {
	case "argon2i":
		return argon2.Key(pass, salt, params.Time, params.Memory, params.Threads, params.OutputSize), nil
	case "argon2id":
		return argon2.IDKey(pass, salt, params.Time, params.Memory, params.Threads, params.OutputSize), nil
	default:
		return nil, ErrFunctionMismatch
	}
}

// parseParams takes parameters from a slice of hash string and returns ArgonParams
func parseParams(inputParams string) (out ArgonParams, err error) {
	// expected format: m=65536,t=2,p=4
	part := strings.Split(inputParams, ",")

	mem, err := strconv.Atoi(strings.TrimPrefix(part[0], "m="))
	if err != nil {
		return out, ErrParseMemory
	}
	timeCost, err := strconv.Atoi(strings.TrimPrefix(part[1], "t="))
	if err != nil {
		return out, ErrParseTime
	}
	threads, err := strconv.Atoi(strings.TrimPrefix(part[2], "p="))
	if err != nil {
		return out, ErrParseParallelism
	}
	out.Memory = uint32(mem)
	out.Time = uint32(timeCost)
	out.Threads = uint8(threads)

	return out, err
}

// Benchmark takes ArgonParams and returns the number of seconds elapsed as a float64 and error
func Benchmark(params ArgonParams) (elapsed float64, err error) {
	pass := "benchmarkpass"
	start := time.Now()
	salt, err := generateSalt(defaultSaltSize)
	if err != nil {
		return 0, err
	}
	_, err = generateHash([]byte(pass), salt, params)
	if err != nil {
		return 0, err
	}
	t := time.Now()
	dur := t.Sub(start)
	return dur.Seconds(), err

}
