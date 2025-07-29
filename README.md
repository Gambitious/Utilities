# Utilities

A comprehensive Go utilities package providing various helper functions for common tasks including captcha solving, HTTP requests, hashing, parsing, and more.

## Features

- **Captcha Solving**: Support for various captcha types (reCAPTCHA v2/v3, hCaptcha, Turnstile, FunCaptcha, Image captcha)
- **HTTP Utilities**: TLS client management, request handling, and user agent generation
- **Hashing Functions**: SHA256, SHA1, MD5, HMAC, PBKDF2, and more
- **Parsing Utilities**: JSON parsing, regex parsing, string manipulation
- **Random Generation**: Secure random string generation, PKCE pair generation
- **Encoding/Decoding**: Base64, URL encoding, and more

## Installation

```bash
go get github.com/Gambitious/Utilities
```

## Usage

### Captcha Solving

```go
package main

import (
    "fmt"
    "github.com/Gambitious/Utilities"
)

func main() {
    // Solve reCAPTCHA v2
    solution, err := utilities.SolveRecaptchaV2(
        "site-key",
        "https://example.com",
        false, // isInvisible
        false, // isEnterprise
        "user-agent",
        "captcha-api-key",
        "", // proxy (empty for proxyless)
        true, // proxyless
    )
    
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Solution: %s\n", solution)
}
```

### HTTP Utilities

```go
package main

import (
    "github.com/Gambitious/Utilities"
    "github.com/bogdanfinn/tls-client/profiles"
)

func main() {
    // Initialize TLS client
    client := utilities.InitTLS(
        "", // proxy
        30, // timeout
        profiles.Chrome_120,
    )
    
    // Generate random user agent
    userAgent := utilities.RandomUserAgent()
    fmt.Printf("User Agent: %s\n", userAgent)
}
```

### Hashing Functions

```go
package main

import (
    "crypto/sha256"
    "github.com/Gambitious/Utilities"
)

func main() {
    // SHA256 hash
    hash := utilities.SHA256("hello world")
    fmt.Printf("SHA256: %s\n", hash)
    
    // HMAC
    hmac := utilities.HMAC("key", "message", crypto.SHA256, false)
    fmt.Printf("HMAC: %s\n", hmac)
}
```

### Parsing Utilities

```go
package main

import (
    "github.com/Gambitious/Utilities"
)

func main() {
    jsonStr := `{"user": {"name": "John", "age": 30}}`
    
    // Extract value from JSON
    name := utilities.GetValuesByKey(jsonStr, "user.name")
    fmt.Printf("Name: %s\n", name[0])
    
    // Parse with regex
    results, err := utilities.RegexParse(
        "Hello World 123",
        `(\w+) (\w+) (\d+)`,
        "[1] [2] [3]",
        false,
    )
    if err == nil {
        fmt.Printf("Parsed: %v\n", results)
    }
}
```

## API Reference

### Captcha Functions

- `SolveImageCaptcha(imageData, capKey string) (string, error)`
- `SolveHCaptcha(siteKey, siteUrl string, isInvisible bool, userAgent, capKey string) (string, error)`
- `SolveTurnstile(siteKey, siteUrl, capKey string) (string, error)`
- `SolveFunCaptcha(siteUrl, siteKey, subdomainHost, capKey string) (string, error)`
- `SolveRecaptchaV2(siteKey, siteUrl string, isInvisible, isEnterprise bool, userAgent, capKey, proxy string, proxyless bool) (string, error)`
- `SolveRecaptchaV3(siteKey, siteUrl, siteAction string, isInvisible, isEnterprise bool, userAgent, capKey, proxy string, proxyless bool) (string, error)`

### HTTP Functions

- `InitTLS(proxy string, timeout int, profile profiles.ClientProfile) tls_client.HttpClient`
- `InitTLSProxyless(timeout int, profile profiles.ClientProfile) tls_client.HttpClient`
- `RandomUserAgent() string`
- `GetRandomProfile() (string, profiles.ClientProfile)`
- `MakeRequest(TLS tls_client.HttpClient, uri, content, method string, headers http.Header) (*http.Response, error)`

### Hashing Functions

- `SHA256(input string) string`
- `SHA1(input string) string`
- `HMAC(key, input string, hashType crypto.Hash, b64 bool) string`
- `PBKDF2(password, salt []byte, algorithm string, iterations int) []byte`

### Parsing Functions

- `GetValuesByKey(jsonStr, path string) []string`
- `RegexParse(input, pattern, outputFormat string, multiline bool) ([]string, error)`
- `LR(source, left, right string, recursion bool) []string`
- `JSON(source, field string, recursion bool) []string`

### Utility Functions

- `RandomString(input string) string`
- `GeneratePKCEPair() (codeVerifier string, codeChallenge string)`
- `Base64Encode(text string) string`
- `Base64Decode(text string) string`
- `ReverseString(s string) string`
- `Distinct(input []string) []string`

## Dependencies

This package uses the following external dependencies:

- `github.com/bogdanfinn/fhttp` - HTTP client
- `github.com/bogdanfinn/tls-client` - TLS client
- `github.com/go-resty/resty/v2` - HTTP client for captcha solving
- `github.com/golang-jwt/jwt` - JWT handling
- `github.com/xdg-go/pbkdf2` - PBKDF2 implementation
- `golang.org/x/crypto` - Cryptographic functions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Disclaimer

This package includes functionality for solving captchas. Please ensure you comply with the terms of service of the websites you interact with and the captcha solving services you use. 