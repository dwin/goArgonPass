# goArgonPass

[![GoDoc](https://godoc.org/github.com/dwin/goArgonPass?status.svg)](https://godoc.org/github.com/dwin/goArgonPass)
[![cover.run](https://cover.run/go/github.com/dwin/goArgonPass.svg?style=flat&tag=golang-1.10)](https://cover.run/go?tag=golang-1.10&repo=github.com%2Fdwin%2FgoArgonPass)
[![Go Report Card](https://goreportcard.com/badge/github.com/dwin/goArgonPass)](https://goreportcard.com/report/github.com/dwin/goArgonPass)

**_All hashing and crypto is done by Go library packages. This is only a utility package to make the process described easier._**

## What?

goArgonPass is a Argon2 Password utility package for Go using the crypto library package [Argon2](https://godoc.org/golang.org/x/crypto/argon2). Argon2 was the winner of the most recent [Password Hashing Competition](https://password-hashing.net/#phc) and doesn't suffer from issues that Bcrypt has such as truncating input over 72 characters. This is designed for use anywhere password hashing and verification might be needed and is intended to replace implementations using bcrypt or Scrypt. The string input/output format was designed to be compatible with [Passlib for Python](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html) and [Argon2 PHP](https://wiki.php.net/rfc/argon2_password_hash), and you should have full compatibility using the ```argon2i``` function, but will not be able to use ```argon2id```, which is the default for this pacakge until those libraries are updated to support it. I encourage you to find the parameters that work best for your application, but the defaults are resonable for an interactive use such as a web application login.

The default Argon2 function is ```Argon2id```, which is a hybrid version of Argon2 combining Argon2i and Argon2d. Argon2id is side-channel resistant and provides better brute- force cost savings due to time-memory tradeoffs than Argon2i, but Argon2i is still plenty secure.

[IETF Recommendation](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-9.4) is: 
> Argon2id variant with t=1 and maximum available memory is recommended as a default setting for all environments.  This setting is secure against side-channel attacks and maximizes adversarial costs on dedicated bruteforce hardware.

## Get Started
```
go get github.com/dwin/goArgonPass
```

See [example/example.go](https://github.com/dwin/goArgonPass/blob/master/example/example.go):
```go
import (
	"fmt"
	"os"

	"github.com/dwin/goArgonPass"
)

func main() {
	// Obtain user password from form or other input
	userPassInput := "password"

	// Hash with Default Parameters
	hash, err := argonpass.Hash(userPassInput)
	if err != nil {
		// Handle Error
		os.Exit(1)
	}
	fmt.Println("Hash Output: ", hash)
	// Verify Hash
	err = argonpass.Verify(userPassInput, hash)
	if err != nil {
		fmt.Println("Hash verification error: ", err)
	}
	fmt.Println("Hash verified")
}

```

**Output Format**
```
$argon2id$v=19$m=65536,t=1,p=4$in2Oi1x57p0=$FopwSR12aLJ9OGPw1rKU5K5osAOGxOJzxC/shk+i850=

$argon2{function(i/id)}$v={version}$m={memory},t={time},p={parallelism}${salt(base64)}${digest(base64)}
```

