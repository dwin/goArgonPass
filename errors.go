package argonpass

import "errors"

var (
	// ErrCustomParameters indicates the parameters passed to hash function are invalid.
	// see minimum constants in password.go
	ErrCustomParameters = errors.New("Parameters passed to hash are invalid")

	// ErrPassphraseInputTooShort indicates the passphrase was less than 8 characters
	ErrPassphraseInputTooShort = errors.New("Passphrase Input too short, must be >= 8 characters")

	// ErrVersion indicates the version could not be found in hash string or version of hash is
	// greater than current package version and is incompatible
	ErrVersion = errors.New("Unable to parse version or incorrect version")

	// ErrFunctionMismatch indicates the function does not match a supported Argon2 function of 'i' or 'id'
	ErrFunctionMismatch = errors.New("Function of hash is invalid, must be 'argon2i' or 'argon2id'")

	// ErrDecodingSalt indicates there was an issue converting the expected base64 salt to bytes
	ErrDecodingSalt = errors.New("Unable to decode salt base64 to byte")

	// ErrDecodingDigest indicates there was an issue converting the expected base64 hash digest to bytes
	ErrDecodingDigest = errors.New("Unable to decode passhash digest base64 to byte")

	// ErrParseTime indicates there was an issue parsing the time parameter from the hash
	// input string, possibly was not expected integer value
	ErrParseTime = errors.New("Unable to parse time parameter")

	// ErrParseMemory indicates there was an issue parsing the memory parameter from the hash
	// input string, possibly was not expected integer value
	ErrParseMemory = errors.New("Unable to parse memory parameter")

	// ErrParseParallelism indicates there was an issue parsing the parallelism parameter from the hash
	// input string, possibly was not expected integer value
	ErrParseParallelism = errors.New("Unable to parse parallelism/threads parameter")

	// ErrHashMismatch indicates the Argon2 digest regenerated using the hash input string salt
	// and user password input did not produce a matching value. Passphrase input does not match
	// hash string input.
	ErrHashMismatch = errors.New("Unable to verify passphrase input with given hash value")

	// ErrInvalidHashFormat indicates the hash string input does not match specified format,
	// example: '$argon2{function(i/id)}$v={version}$m={memory},t={time},p={parallelism}${salt(base64)}${digest(base64)}'
	ErrInvalidHashFormat = errors.New("Invalid hash input string format")
)
