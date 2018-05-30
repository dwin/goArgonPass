package argonpass

import "errors"

var (
	ErrCustomParameters = errors.New("Parameters passed to hash are invalid")

	ErrPassphraseInputTooShort = errors.New("Passphrase Input too short, must be > 0 characters")
	// ErrVersion indicates the version could not be found in hash string or version of hash is
	// greater than current package version and is incompatible
	ErrVersion = errors.New("Unable to parse version or incorrect version")

	ErrFunctionMismatch = errors.New("Function of hash is invalid, must be 'argon2i' or 'argon2id'")

	ErrDecodingSalt = errors.New("Unable to decode salt base64 to byte")

	ErrDecodingHash = errors.New("Unable to decode passhash base64 to byte")

	ErrParseTime = errors.New("Unable to parse time parameter")

	ErrParseMemory = errors.New("Unable to parse memory parameter")

	ErrParseParallelism = errors.New("Unable to parse parallelism/threads parameter")

	ErrHashMismatch = errors.New("Unable to verify passphrase input with given hash value")

	ErrInvalidHashFormat = errors.New("Invalid hash format, hash should be in form of '$argon2{function(i or id)}$v={version}$m={memory},t={time},p={parallelism}${salt(base64)}${digest(base64)}'")
)
