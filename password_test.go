package argonpass

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	testdata = map[string]string{
		"testpass":                                                         "$argon2id$v=19$m=65536,t=10,p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=",
		"pEVDROhl8ksT1FiZB1Nc":                                             "$argon2id$v=19$m=65536,t=10,p=4$C75eQEesF0BbHL3wBsaaAg==$VwNdvHdQn1QMYpedCZ0o/4JX07Sh5LrfTBzTQhSXfc0=",
		"8koJ3haNVVV47JWg8zQRKLtImCUgmVFg8dCS7IYtCjhLnFFfHTNXXpbZoSUEIimH": "$argon2id$v=19$m=65536,t=10,p=4$smp4HSblqVHGu1wNvPMkYA==$FCjpCngTwRefH3BT//hyLd0/q6hgbMjiBtPdqnsjL4k=",
		"OEQRVj1O":                 "$argon2id$v=19$m=65536,t=10,p=4$rKWlclAZ1feliEaKUVe9Aw==$96ByjSgZFdvvCpJhoLxtnjTRYbAF6cyNgdnl2LdZ0gI=",
		"o2s5M7gttWtX4hr6":         "$argon2i$v=19$m=65536,t=5,p=4$KG6py4HoITzyOP0sOJvAAA==$ZY2gclySeV9LDcAnfU6pjbYdbw652jZVxqNBEQFWpyk=",
		"7Hjxel7CkclL":             "$argon2i$v=19$m=65536,t=5,p=4$BHQg8klpY8/sWcCjemdy6Q==$xHf/mMqMjsUybImONEpvGs/cOLjpd24wseATlM/woJs=",
		"4mW1lMYmG2OaEmfGm2NFpRmh": "$argon2i$v=19$m=65536,t=5,p=4$MrcQyTq/if2OH2G5+YPKig==$m6zc3AIQbGZOSv3grFtlquTUXXKdyfmCvrmKJ4cQf7E=",
	}
)

// Generate random password
func randSeq(n int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*(){}.<>|\\/~`+-[]\"1234567890-_,")
	b := make([]rune, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
func TestHash(t *testing.T) {
	// Test Short Pass
	_, err := Hash("1234567")
	assert.EqualError(t, err, ErrPassphraseInputTooShort.Error())

	// Test Too Many Custom Params
	_, err = Hash("password", ArgonParams{Time: 0}, ArgonParams{Memory: 0})
	assert.EqualError(t, err, ErrCustomParameters.Error())

	// Test below min custom params
	out, err := Hash("password", ArgonParams{})
	assert.NoError(t, err)
	assert.Contains(t, out, "$argon2id$v=19$m=1024,t=1,p=1")

	// Test above max params, should be forced to max
	out, err = Hash("password", ArgonParams{SaltSize: 100, OutputSize: 600})
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

	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestRandSeq(t *testing.T) {
	s := randSeq(12)
	assert.Len(t, s, 12)
	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestVerify(t *testing.T) {
	// Test Verify using testdata
	for pass, hash := range testdata {
		err := Verify(pass, hash)
		assert.NoError(t, err)
		if err != nil {
			fmt.Printf("Verification failed for pass: %s with hash: %s\n", pass, hash)
		}
	}

	// Test Verify using testdata hashes and invalid passphrases
	for _, hash := range testdata {
		err := Verify("invalid_pass", hash)
		assert.EqualError(t, err, ErrHashMismatch.Error())
	}

	// Test Verify with bad hash string input
	err := Verify("password", "$argon2id$v=19$m=65536,t=10$p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	assert.EqualError(t, err, ErrInvalidHashFormat.Error())

	// Test Verify with Invalid hash function
	err = Verify("password", "$argon2bi$v=19$m=65536,t=10,p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	assert.EqualError(t, err, ErrInvalidHashFormat.Error())

	// Test Verify with Invalid version
	err = Verify("password", "$argon2i$v=99$m=65536,t=10,p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	assert.EqualError(t, err, ErrVersion.Error())

	// Test Verify with malformed/invalid salt
	err = Verify("password", "$argon2i$v=19$m=65536,t=10,p=4$wusfaUEXf@hsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb536IcyP5CGpEvsO1agp2aZQ=")
	assert.EqualError(t, err, ErrDecodingSalt.Error())

	// Test Verify with malformed/invalid digest
	err = Verify("password", "$argon2i$v=19$m=65536,t=10,p=4$wusfaUEXfbhsz9R3+PI9nQ==$54an1yiYbCEfTtUzE0Lb53#IcyP5CGpEvsO1agp2aZQ=")
	assert.EqualError(t, err, ErrDecodingHash.Error())

	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestCheckParams(t *testing.T) {
	params := checkParams(ArgonParams{SaltSize: 100, OutputSize: 600})
	assert.EqualValues(t, maxSaltSize, params.SaltSize)
	assert.EqualValues(t, maxOutputSize, params.OutputSize)
	assert.EqualValues(t, minMemory, params.Memory)
	assert.EqualValues(t, minTime, params.Time)
	assert.EqualValues(t, argon2id, params.Function)
	assert.EqualValues(t, minParallelism, params.Parallelism)
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
func TestGenerateHash(t *testing.T) {
	// Test regeneration with expected output
	salt, _ := base64.StdEncoding.DecodeString("AXLonWF8MSgG515yMlIRSw==")
	testpass := []byte("testpass")
	out, err := generateHash(testpass, salt, ArgonParams{Time: 12, Memory: 64 * 1024, Parallelism: 4, OutputSize: 32, Function: "argon2id"})
	assert.NoError(t, err)
	assert.EqualValues(t, "+iExTQDCJnO4fErO61zMAeC24R3utWMk8tW85saXOBU=", base64.StdEncoding.EncodeToString(out))

	// Test invalid function choice
	_, err = generateHash(testpass, salt, ArgonParams{Time: 12, Memory: 64 * 1024, Parallelism: 4, OutputSize: 32, Function: "argon2b"})
	assert.EqualError(t, err, ErrFunctionMismatch.Error())

	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestGenerateSalt(t *testing.T) {
	expectedLen := 20
	salt, err := generateSalt(uint8(expectedLen))
	assert.NoError(t, err)
	assert.Len(t, salt, expectedLen)
}

func TestHashAndVerify(t *testing.T) {
	// Hash & Verify various lengths from 8 chars up to 256 chars with default params
	for i := 8; i < 256; i *= 3 {
		pass := randSeq(i)
		out, err := Hash(pass)
		assert.NoError(t, err)
		assert.NotEmpty(t, out)
		err = Verify(pass, out)
		assert.NoError(t, err)
	}

	// Hash & Verify with Custom Params
	for i := 8; i < 256; i *= 3 {
		pass := randSeq(i)
		out, err := Hash(pass, ArgonParams{Time: 12, Memory: 64 * 1024, Parallelism: 4, OutputSize: 32, Function: "argon2id"})
		assert.NoError(t, err)
		assert.NotEmpty(t, out)
		err = Verify(pass, out)
		assert.NoError(t, err)
	}
	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestParseParams(t *testing.T) {
	expected := ArgonParams{
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
	for totalDuration < 5 {
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
		_, _ = Hash("testpass")
	}
}
