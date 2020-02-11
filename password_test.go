package argonpass

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/icrowley/fake"
	"golang.org/x/crypto/argon2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testdata = map[string]string{
		"testpass":             "$argon2id$v=19$m=65536,t=10,p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=",
		"pEVDROhl8ksT1FiZB1Nc": "$argon2id$v=19$m=65536,t=10,p=4$C75eQEesF0BbHL3wBsaaAg==$VwNdvHdQn1QMYpedCZ0o/4JX07Sh5LrfTBzTQhSXfc0=",
		"8koJ3haNVVV47JWg8zQRKLtImCUgmVFg8dCS7IYtCjhLnFFfHTNXXpbZoSUEIimH": "$argon2id$v=19$m=65536,t=10,p=4$smp4HSblqVHGu1wNvPMkYA==$FCjpCngTwRefH3BT//hyLd0/q6hgbMjiBtPdqnsjL4k=",
		"OEQRVj1O":                 "$argon2id$v=19$m=65536,t=10,p=4$rKWlclAZ1feliEaKUVe9Aw==$96ByjSgZFdvvCpJhoLxtnjTRYbAF6cyNgdnl2LdZ0gI=",
		"o2s5M7gttWtX4hr6":         "$argon2i$v=19$m=65536,t=5,p=4$KG6py4HoITzyOP0sOJvAAA==$ZY2gclySeV9LDcAnfU6pjbYdbw652jZVxqNBEQFWpyk=",
		"7Hjxel7CkclL":             "$argon2i$v=19$m=65536,t=5,p=4$BHQg8klpY8/sWcCjemdy6Q==$xHf/mMqMjsUybImONEpvGs/cOLjpd24wseATlM/woJs=",
		"4mW1lMYmG2OaEmfGm2NFpRmh": "$argon2i$v=19$m=65536,t=5,p=4$MrcQyTq/if2OH2G5+YPKig==$m6zc3AIQbGZOSv3grFtlquTUXXKdyfmCvrmKJ4cQf7E=",
	}
)

func TestHash(t *testing.T) {
	// Test Short Pass
	_, err := Hash("1234567", nil)
	assert.EqualError(t, err, ErrPassphraseInputTooShort.Error())

	// Test below min custom params
	out, err := Hash("password", &ArgonParams{Function: ArgonVariant2i})
	assert.NoError(t, err)
	assert.Contains(t, out, "$argon2i$v=19$m=1024,t=1,p=1")

	// Test above max params, should be forced to max
	out, err = Hash("password", &ArgonParams{SaltSize: 100, OutputSize: 600, Function: ArgonVariant2i})
	assert.NoError(t, err)
	if err != nil {
		t.FailNow()
	}
	part := strings.Split(out, "$")
	// Get salt, check was set to max Salt Size
	salt, err := base64.StdEncoding.DecodeString(part[4])
	assert.NoError(t, err)
	assert.Len(t, salt, maxSaltSize)
	// Get argon digest, check was set to max Output Size
	decodedHash, err := base64.StdEncoding.DecodeString(part[5])
	assert.NoError(t, err)
	assert.Len(t, decodedHash, maxOutputSize)

	// Test invalid function choice
	hash, err := Hash("password", &ArgonParams{Time: 1, Memory: 16 * 1024, Parallelism: 4, OutputSize: 32, Function: "argon2b"})
	assert.EqualError(t, err, ErrFunctionMismatch.Error())
	assert.Empty(t, hash)

	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestVerify(t *testing.T) {
	// Test Verify using testdata
	for pass, hash := range testdata {
		err := Verify(pass, hash)
		require.NoError(t, err)
		if err != nil {
			fmt.Printf("Verification failed for pass: %s with hash: %s\n", pass, hash)
		}
	}

	// Test Verify using testdata hashes and invalid passphrases
	for _, hash := range testdata {
		err := Verify("invalid_pass", hash)
		require.EqualError(t, err, ErrHashMismatch.Error())
	}

	// Test Verify with bad salt
	err := Verify("password", "$argon2i$v=19$m=65536,t=5,p=4$=$m6zc3AIQbGZOSv3grFtlquTUXXKdyfmCvrmKJ4cQf7E=")
	require.EqualError(t, err, ErrDecodingSalt.Error())
	require.NotNil(t, err)

	// Test Verify with bad digest
	err = Verify("password", "$argon2i$v=19$m=65536,t=5,p=4$MrcQyTq/if2OH2G5+YPKig==$=")
	require.EqualError(t, err, ErrDecodingDigest.Error())
	require.NotNil(t, err)

	// Test Verify with bad hash string input
	err = Verify("password", "$argon2id$v=19$m=65536,t=10$p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	require.EqualError(t, err, ErrInvalidHashFormat.Error())
	require.NotNil(t, err)

	// Test Verify with Invalid hash function
	err = Verify("password", "$argon2bi$v=19$m=65536,t=10,p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	require.EqualError(t, err, ErrInvalidHashFormat.Error())
	require.NotNil(t, err)

	// Test Verify with Invalid version
	err = Verify("password", "$argon2i$v=99$m=65536,t=10,p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	require.EqualError(t, err, ErrVersion.Error())
	require.NotNil(t, err)

	// Test Verify with malformed/invalid salt
	err = Verify("password", "$argon2i$v=19$m=65536,t=10,p=4$wusfaUEXf@hsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	require.EqualError(t, err, ErrDecodingSalt.Error())
	require.NotNil(t, err)

	// Test Verify with malformed/invalid salt
	err = Verify("password", "$argon2i$v=19$m=65536,t=5,p=4$ $m6zc3AIQbGZOSv3grFtlquTUXXKdyfmCvrmKJ4cQf7E=")
	require.EqualError(t, err, ErrDecodingSalt.Error())
	require.NotNil(t, err)

	// Test Verify with malformed/invalid salt
	err = Verify("password", "$argon2i$v=19$m=65536,t=5,p=4$MrcQyTq/if?OH2G5+YPKig==$m6zc3AIQbGZOSv3grFtlquTUXXKdyfmCvrmKJ4cQf7E=")
	require.EqualError(t, err, ErrDecodingSalt.Error())
	require.NotNil(t, err)

	// Test Verify with malformed/invalid digest
	err = Verify("password", "$argon2i$v=19$m=65536,t=10,p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb53#IcyP5CGpEvsO1agp2aZQ=")
	require.EqualError(t, err, ErrDecodingDigest.Error())
	require.NotNil(t, err)

	// Test Verify with malformed/invalid digest
	err = Verify("password", "$argon2i$v=19$m=65536,t=5,p=4$MrcQyTq/ifOH2G5+YPKig==$m6zc3AIQbGZOSv3grFtlquTUX*XKdyfmCvrmKJ4cQf7E=")
	require.EqualError(t, err, ErrDecodingSalt.Error())
	require.NotNil(t, err)

	// Test Verify with malformed/invalid digest
	err = Verify("password", "$argon2i$v=19$m=65536,t=5,p=4$MrcQyTq/ifOH2G5+YPKig==$ ")
	require.EqualError(t, err, ErrDecodingSalt.Error())
	require.NotNil(t, err)

	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestGetParams(t *testing.T) {
	// Test GetParams using testdata hashes
	for _, hash := range testdata {
		params, err := GetParams(hash)
		assert.NoError(t, err)
		assert.NotZero(t, params.Memory)
		assert.NotZero(t, params.Parallelism)
		assert.NotZero(t, params.Time)
		assert.NotZero(t, params.OutputSize)
		assert.NotZero(t, params.SaltSize)
	}

	fmt.Println(" - " + t.Name() + " complete - ")
}
func TestCheckParams(t *testing.T) {
	params := checkParams(&ArgonParams{SaltSize: 100, OutputSize: 600})
	assert.EqualValues(t, maxSaltSize, params.SaltSize)
	assert.EqualValues(t, maxOutputSize, params.OutputSize)
	assert.EqualValues(t, minMemory, params.Memory)
	assert.EqualValues(t, minTime, params.Time)
	assert.EqualValues(t, minParallelism, params.Parallelism)
	assert.Empty(t, params.Function)
	// Check Max Parameters
	params = checkParams(&ArgonParams{Parallelism: 100})
	assert.EqualValues(t, maxParallelism, params.Parallelism)
}
func TestCheckHashFormat(t *testing.T) {
	// Check bad hash format
	err := checkHashFormat("$argon2id$v=19$m=65536,t=10$p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	assert.EqualError(t, err, ErrInvalidHashFormat.Error())
	// Check valid hash format
	err = checkHashFormat("$argon2id$v=19$m=65536,t=1,p=4$in2Oi1x57p0=$FopwSR12aLJ9OGPw1rKU5K5osAOGxOJzxC/shk+i850=")
	assert.NoError(t, err)

	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestGenerateOutputString(t *testing.T) {
	// Test Data
	salt, err := generateSalt(8)
	require.NoError(t, err)
	saltEncoded := base64.StdEncoding.EncodeToString(salt)
	testpass := []byte(fake.Password(8, 256, true, true, true))

	t.Run("Generate ArgonVariant2i output string", func(t *testing.T) {
		variant := ArgonVariant2i
		hash, err := generateHash(testpass, salt, &ArgonParams{Time: 2, Memory: 64 * 1024, Parallelism: 4, OutputSize: 32, Function: variant})
		assert.NoError(t, err)
		hashEncoded := base64.StdEncoding.EncodeToString(hash)
		output := generateOutputString(variant, argon2.Version, 64*1024, 2, 4, saltEncoded, hashEncoded)
		require.NotEmpty(t, output)
		assert.NoError(t, checkHashFormat(output))
	})

	t.Run("Generate ArgonVariant2id output string", func(t *testing.T) {
		variant := ArgonVariant2id
		hash, err := generateHash(testpass, salt, &ArgonParams{Time: 2, Memory: 64 * 1024, Parallelism: 4, OutputSize: 32, Function: variant})
		assert.NoError(t, err)
		hashEncoded := base64.StdEncoding.EncodeToString(hash)
		output := generateOutputString(variant, argon2.Version, 64*1024, 2, 4, saltEncoded, hashEncoded)
		require.NotEmpty(t, output)
		assert.NoError(t, checkHashFormat(output))
	})

}
func TestGenerateHash(t *testing.T) {
	// Test regeneration with expected output
	salt, _ := base64.StdEncoding.DecodeString("AXLonWF8MSgG515yMlIRSw==")
	testpass := []byte("testpass")
	out, err := generateHash(testpass, salt, &ArgonParams{Time: 12, Memory: 64 * 1024, Parallelism: 4, OutputSize: 32, Function: ArgonVariant2id})
	assert.NoError(t, err)
	assert.EqualValues(t, "+iExTQDCJnO4fErO61zMAeC24R3utWMk8tW85saXOBU=", base64.StdEncoding.EncodeToString(out))

	// Test invalid function choice
	hash, err := generateHash(testpass, salt, &ArgonParams{Time: 1, Memory: 16 * 1024, Parallelism: 4, OutputSize: 32, Function: "argon2b"})
	assert.EqualError(t, err, ErrFunctionMismatch.Error())
	assert.Empty(t, hash)

	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestGenerateSalt(t *testing.T) {
	// Generate random salts from minSaltSize to maxSaltSize
	for i := minSaltSize; i < maxSaltSize; i++ {
		expectedLen := i
		salt, err := generateSalt(uint8(expectedLen))
		assert.NoError(t, err)
		assert.Len(t, salt, expectedLen)
	}
}

func TestHashAndVerify(t *testing.T) {
	// Hash & Verify various lengths from 8 chars up to 256 chars with default params
	for i := 8; i < 256; i *= 8 {
		pass := fake.Password(8, 256, true, true, true)
		out, err := Hash(pass, nil)
		assert.NoError(t, err)
		assert.NotEmpty(t, out)
		err = Verify(pass, out)
		assert.NoError(t, err)
	}

	// Hash & Verify with Custom Params
	for i := 8; i < 256; i *= 8 {
		pass := fake.Password(8, 256, true, true, true)
		out, err := Hash(pass, &ArgonParams{Time: 12, Memory: 64 * 1024, Parallelism: 4, OutputSize: 32, Function: "argon2id"})
		assert.NoError(t, err)
		assert.NotEmpty(t, out)
		err = Verify(pass, out)
		assert.NoError(t, err)
	}
	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestParseParams(t *testing.T) {
	expected := &ArgonParams{
		Time:        2,
		Memory:      65536,
		Parallelism: 4,
	}
	params, err := parseParams("m=65536,t=2,p=4")
	assert.NoError(t, err)
	assert.Equal(t, expected, params)

	// Test with bad params, these should not happen in regular use since these would fail regex
	_, err = parseParams("m=65.536,t=2,p=4")
	assert.EqualError(t, err, ErrParseMemory.Error())
	_, err = parseParams("m=65536,t=2b,p=4")
	assert.EqualError(t, err, ErrParseTime.Error())
	_, err = parseParams("m=65536,t=2,p=4h")
	assert.EqualError(t, err, ErrParseParallelism.Error())

	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestBenchmark(t *testing.T) {
	var count int
	var totalDuration float64
	for totalDuration < 3 {
		singleDuration, err := Benchmark(defaultParams)
		assert.NoError(t, err)
		totalDuration += singleDuration
		count++
	}
	assert.NotZero(t, count)
	assert.NotZero(t, totalDuration)
	fmt.Printf("%v runs in %.2f seconds, or %.2f/second\n", count, totalDuration, float64(count)/totalDuration)
	fmt.Println(" - " + t.Name() + " complete - ")
}

func BenchmarkHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Hash("testpass", nil)
	}
}
