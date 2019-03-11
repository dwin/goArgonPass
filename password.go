// Package argonpass provides passphrase hashing and hash verification using the Argon2
// password hashing method.
//
// The default Argon2 function is ```Argon2id```, which is a hybrid version of Argon2 combining
// Argon2i and Argon2d. Argon2id is side-channel resistant and provides better brute- force cost
// savings due to time-memory tradeoffs than Argon2i, but Argon2i is still plenty secure.
//
// The string input/output format was designed to be compatible with
// [Passlib for Python](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html) and
// [Argon2 PHP](https://wiki.php.net/rfc/argon2_password_hash), and you should have full compatibility
// using the ```argon2i``` function, but will not be able to use ```argon2id```, which is the default
// for this package until those libraries are updated to support it. I encourage you to find the parameters
// that work best for your application, but the defaults are resonable for an interactive use
// such as a web application login.
package argonpass

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// ArgonVariant describes an Argon2 hashing variant.
type ArgonVariant string

const (
	// ArgonVariant2i describe the Argon2i variant.
	ArgonVariant2i ArgonVariant = "argon2i"
	// ArgonVariant2id describe the Argon2id variant.
	ArgonVariant2id ArgonVariant = "argon2id"
)

const (
	currentVersion = argon2.Version
	minPassLength  = 8
	minSaltSize    = 8
	maxSaltSize    = 64
	minTime        = 1
	minMemory      = 1 << 10
	minParallelism = 1
	minOutputSize  = 16 // minimum Argon2 digest output size only
	maxOutputSize  = 512
	maxParallelism = 64
)

const (
	// DefaultMemory ...
	DefaultMemory = 64 * 1024
	// DefaultParallelism ...
	DefaultParallelism = 4
	// DefaultOutputSize ...
	DefaultOutputSize = 32
	// DefaultFunction ...
	DefaultFunction = ArgonVariant2id
	// DefaultSaltSize ...
	DefaultSaltSize = 8
	// DefaultTime ...
	DefaultTime = 1
)

// defaultParams are the parameters used if none are provided to Hash function
var defaultParams = ArgonParams{
	Time:        DefaultTime,
	Memory:      DefaultMemory,
	Parallelism: DefaultParallelism,
	OutputSize:  DefaultOutputSize,
	Function:    DefaultFunction,
	SaltSize:    DefaultSaltSize,
}

// hashFormatRegExpCompiled is used to verify hash string format
var hashFormatRegExpCompiled = regexp.MustCompile(`[$]argon2(?:id|i)[$]v=\d{1,3}[$]m=\d{3,20},t=\d{1,4},p=\d{1,2}[$][^$]{1,100}[$][^$]{1,768}`)

// ArgonParams control how the Argon2 function creates the digest output
type ArgonParams struct {
	Time        uint32
	Memory      uint32
	Parallelism uint8
	OutputSize  uint32
	Function    ArgonVariant
	SaltSize    uint8
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
		params = checkParams(customParams[0])
	default:
		return "", ErrCustomParameters
	}

	// Generate random salt
	salt, err := generateSalt(params.SaltSize)
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
	// $argon2{function(i or id)}$v={version}$m={memory},t={time},p={parallelism}${salt(base64)}${digest(base64)}
	// example: $argon2id$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
	hashOut := generateOutputString(params.Function, currentVersion, params.Memory, params.Time, params.Parallelism, encodedSalt, encodedHash)

	return hashOut, nil
}

// Verify regenerates the hash using the supplied pass and compares the value returning an error if the password
// is invalid or another error occurs. Any error should be considered a validation failure.
func Verify(pass, hash string) error {
	// Get Parameters
	hashParams, err := GetParams(hash)
	if err != nil {
		return err
	}

	// Split hash into parts
	part := strings.Split(hash, "$")

	// Get & Check Version
	hashVersion, err := strconv.Atoi(strings.Trim(part[2], "v="))
	if err != nil {
		return err
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
		return ErrDecodingDigest
	}

	// Generate hash for comparison using user input with stored parameters
	comparisonHash, err := generateHash([]byte(pass), salt, hashParams)
	if err != nil {
		return fmt.Errorf("Unable to generate hash for comparison using inputs, error: %s", err)
	}

	// Compare given hash input to generated hash
	if res := subtle.ConstantTimeCompare(decodedHash, comparisonHash); res == 1 {
		// return nil only if supplied hash and computed hash from passphrase match
		return nil
	}
	return ErrHashMismatch
}

// GetParams takes hash sting as input and returns parameters as ArgonParams along with error
func GetParams(hash string) (hashParams ArgonParams, err error) {
	// Check valid input
	if err = checkHashFormat(hash); err != nil {
		return
	}

	// Split hash into parts
	part := strings.Split(hash, "$")

	// Get Parameters
	hashParams, err = parseParams(part[3])
	if err != nil {
		return
	}

	// Get hash function
	hashParams.Function = ArgonVariant(part[1])

	// Get salt size
	salt, err := base64.StdEncoding.DecodeString(part[4])
	if err != nil {
		return hashParams, ErrDecodingSalt
	}
	hashParams.SaltSize = uint8(len(salt))

	// Get argon digest size
	decodedHash, err := base64.StdEncoding.DecodeString(part[5])
	if err != nil {
		return hashParams, ErrDecodingDigest
	}
	hashParams.OutputSize = uint32(len(decodedHash))

	return
}

// checkHashFormat uses regex to validate hash string pattern and returns error
func checkHashFormat(hash string) error {
	// Check valid input
	if !hashFormatRegExpCompiled.MatchString(hash) {
		return ErrInvalidHashFormat
	}
	return nil
}

// generateSalt uses int input to return a random a salt for use in crypto operations
func generateSalt(saltLen uint8) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// generateHash takes passphrase and salt as bytes with parameters to provide Argon2 digest output
func generateHash(pass, salt []byte, params ArgonParams) ([]byte, error) {
	switch params.Function {
	case ArgonVariant2i:
		return argon2.Key(pass, salt, params.Time, params.Memory, params.Parallelism, params.OutputSize), nil
	case ArgonVariant2id:
		return argon2.IDKey(pass, salt, params.Time, params.Memory, params.Parallelism, params.OutputSize), nil
	default:
		return nil, ErrFunctionMismatch
	}
}

func generateOutputString(argonVariant ArgonVariant, version int, memory, time uint32, parallelism uint8, salt, hash string) string {
	return fmt.Sprintf("$%s$v=%v$m=%v,t=%v,p=%v$%s$%s", argonVariant, version, memory, time, parallelism, salt, hash)
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
	parallelism, err := strconv.Atoi(strings.TrimPrefix(part[2], "p="))
	if err != nil {
		return out, ErrParseParallelism
	}
	out.Memory = uint32(mem)
	out.Time = uint32(timeCost)
	out.Parallelism = uint8(parallelism)

	return out, err
}

// checkParams verifies that parameters fall within min and max allowed values
func checkParams(params ArgonParams) ArgonParams {
	// Enforce Minimum Params
	if params.SaltSize < minSaltSize {
		params.SaltSize = minSaltSize
	}
	if params.Time < minTime {
		params.Time = minTime
	}
	if params.Memory < minMemory {
		params.Memory = minMemory
	}
	if params.Parallelism < minParallelism {
		params.Parallelism = minParallelism
	}
	if params.OutputSize < minOutputSize {
		params.OutputSize = minOutputSize
	}
	// Enforce Max Params
	if params.SaltSize > maxSaltSize {
		params.SaltSize = maxSaltSize
	}
	if params.OutputSize > maxOutputSize {
		params.OutputSize = maxOutputSize
	}
	if params.Parallelism > maxParallelism {
		params.Parallelism = maxParallelism
	}

	return params
}

// Benchmark takes ArgonParams and returns the number of seconds elapsed as a float64 and error
func Benchmark(params ArgonParams) (elapsed float64, err error) {
	pass := "benchmarkpass"
	start := time.Now()

	salt, err := generateSalt(params.SaltSize)
	_, err = generateHash([]byte(pass), salt, params)

	t := time.Now()
	dur := t.Sub(start)
	return dur.Seconds(), err
}
