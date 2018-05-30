package argonpass

import (
	"encoding/base64"
	"fmt"
	"math/rand"
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
func TestHashShortPass(t *testing.T) {
	// Test Short Pass
	_, err := Hash("1234567")
	assert.EqualError(t, err, ErrPassphraseInputTooShort.Error())
	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestRandSeq(t *testing.T) {
	s := randSeq(12)
	assert.Len(t, s, 12)
	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestVerify(t *testing.T) {
	for pass, hash := range testdata {
		err := Verify(pass, hash)
		assert.Nil(t, err)
		if err != nil {
			fmt.Printf("Verification failed for pass: %s with hash: %s\n", pass, hash)
		}
	}
	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestGenerateHash(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString("AXLonWF8MSgG515yMlIRSw==")
	out, err := generateHash([]byte("testpass"), salt, ArgonParams{Time: 12, Memory: 64 * 1024, Threads: 4, OutputSize: 32, Function: "argon2id"})
	assert.Nil(t, err)
	assert.EqualValues(t, "+iExTQDCJnO4fErO61zMAeC24R3utWMk8tW85saXOBU=", base64.StdEncoding.EncodeToString(out))
	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestHashAndVerify(t *testing.T) {
	// Hash & Verify various lengths from 8 chars up to 256 chars with default params
	for i := 8; i < 256; i *= 3 {
		pass := randSeq(i)
		out, err := Hash(pass)
		assert.Nil(t, err)
		assert.NotEmpty(t, out)
		err = Verify(pass, out)
		assert.Nil(t, err)
	}

	// Hash & Verify with Custom Params
	for i := 8; i < 256; i *= 3 {
		pass := randSeq(i)
		out, err := Hash(pass, ArgonParams{Time: 12, Memory: 64 * 1024, Threads: 4, OutputSize: 32, Function: "argon2id"})
		assert.Nil(t, err)
		assert.NotEmpty(t, out)
		err = Verify(pass, out)
		assert.Nil(t, err)
	}
	fmt.Println(" - " + t.Name() + " complete - ")
}

func TestBenchmark(t *testing.T) {
	var count int
	var totalDuration float64
	for totalDuration < 5 {
		singleDuration, err := Benchmark(defaultParams)
		assert.Nil(t, err)
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
