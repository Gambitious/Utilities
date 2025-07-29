package utilities

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	Rand "math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/golang-jwt/jwt"
)

// Define character sets
var (
	lowercase = "abcdefghijklmnopqrstuvwxyz"
	uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits    = "0123456789"
	symbols   = "\\!\"£$%&/()=?^'{}[]@#,;.:-_*+"
	hexs      = digits + "abcdef"
	udChars   = uppercase + digits
	ldChars   = lowercase + digits
	upperlwr  = lowercase + uppercase
	ludChars  = lowercase + uppercase + digits
	allChars  = lowercase + uppercase + digits + symbols
)

func ParseProxyFasthttp(proxy string) string {
	if strings.Contains(proxy, "://") {
		proxy = strings.Split(proxy, "://")[1]
	}
	parts := strings.Split(proxy, ":")
	switch len(parts) {
	case 2: // ip:port
		return proxy
	case 3: // user:pass@ip:port
		return proxy
	case 4: // ip:port:user:pass -> user:pass@ip:port
		return parts[2] + ":" + parts[3] + "@" + parts[0] + ":" + parts[1]
	default:
		return ""
	}

}
func ParseProxyTLS(proxy string) string {
	if !strings.Contains(proxy, "://") { // user:pass@ip:port -> http://user:pass@ip:port
		proxy = "http://" + proxy
	}
	parts := strings.Split(strings.Split(proxy, "://")[1], ":")
	switch len(parts) {
	case 2: // http://ip:port
		return proxy
	case 3: // http://user:pass@ip:port
		return proxy
	case 4: // http://ip:port:user:pass -> http://user:pass@ip:port
		// fmt.Println(proxy)
		// fmt.Println(strings.Join(parts, "-"))
		// fmt.Println(len(parts))
		// fmt.Println(strings.Split(proxy, "://")[0] + "://" + parts[2] + ":" + parts[3] + "@" + parts[0] + ":" + parts[1])
		return strings.Split(proxy, "://")[0] + "://" + parts[2] + ":" + parts[3] + "@" + parts[0] + ":" + parts[1]
	default:
		return ""
	}

}
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func randomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64URLEncode(bytes), nil
}
func generateRandomString(length int) string {
	const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
	Rand.Seed(time.Now().UnixNano())
	var randomString strings.Builder
	for i := 0; i < length; i++ {
		randomIndex := Rand.Intn(len(characters))
		randomString.WriteByte(characters[randomIndex])
	}
	return randomString.String()
}

// Function to generate a code verifier and code challenge
func GeneratePKCEPair() (codeVerifier string, codeChallenge string) {
	// Generate a valid code verifier
	codeVerifier = generateRandomString(43)

	// Generate the code challenge by hashing the code verifier
	hash := sha256.New()
	hash.Write([]byte(codeVerifier))
	sha256Hash := hash.Sum(nil)

	// Encode the hash in base64 URL format
	codeChallenge = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha256Hash)

	return
}
func GenerateOAuth2Params(length int) (state, codeVerifier, codeChallenge string, err error) {
	state, err = randomString(length)
	if err != nil {
		return
	}

	codeVerifier, err = randomString(length)
	if err != nil {
		return
	}

	codeChallenge = SHA256(codeVerifier)
	return
}

func SHA256(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func SHA1(input string) string {
	hasher := sha1.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

// RandomString generates a random string given a mask
func RandomString(input string) string {

	replaceFunc := func(input string, pattern string, chars string) string {
		re := regexp.MustCompile(pattern)
		return re.ReplaceAllStringFunc(input, func(m string) string {
			return string(chars[Rand.Intn(len(chars))])
		})
	}

	input = replaceFunc(input, `\?l`, lowercase)
	input = replaceFunc(input, `\?u`, uppercase)
	input = replaceFunc(input, `\?d`, digits)
	input = replaceFunc(input, `\?s`, symbols)
	input = replaceFunc(input, `\?h`, hexs)
	input = replaceFunc(input, `\?H`, strings.ToUpper(hexs))
	input = replaceFunc(input, `\?a`, allChars)
	input = replaceFunc(input, `\?m`, udChars)
	input = replaceFunc(input, `\?n`, ldChars)
	input = replaceFunc(input, `\?i`, ludChars)
	input = replaceFunc(input, `\?f`, upperlwr)

	return input
}

func CurrentUnixTime(useUtc bool) int64 {
	var currentTime time.Time

	if useUtc {
		currentTime = time.Now().UTC()
	} else {
		currentTime = time.Now()
	}

	return currentTime.Unix()
}

func RandomUserAgent() string {
	// switch Rand.Intn(3) {
	// case 0: //15_5
	// 	return "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1"
	// case 1: //15_6
	// 	return "Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1"
	// case 2: //16_0
	// 	return "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
	// }
	browserTemplates := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%d.0) Gecko/20100101 Firefox/%d.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/%d.0 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/%d.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_%d_0) AppleWebKit/%d.0 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/%d.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/%d.0 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/%d.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 10_%d like Mac OS X) AppleWebKit/%d.0 (KHTML, like Gecko) Version/%d.0 Mobile/14E304 Safari/%d.0",
		"Mozilla/5.0 (iPad; CPU OS 10_%d like Mac OS X) AppleWebKit/%d.0 (KHTML, like Gecko) Version/%d.0 Mobile/14E304 Safari/%d.0",
	}
	template := browserTemplates[Rand.Intn(len(browserTemplates))]
	version := Rand.Intn(30) + 100 // Random version between 100 and 130
	return fmt.Sprintf(template, version, version, version, version)
}
func GetRandomIOSProfile() (string, profiles.ClientProfile) {
	switch Rand.Intn(3) {
	case 0: //15_5
		return "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", profiles.Safari_IOS_15_5
	case 1: //15_6
		return "Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1", profiles.Safari_IOS_15_6
	case 2: //16_0
		return "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", profiles.Safari_IOS_16_0
	}
	return "", profiles.DefaultClientProfile
}
func RandomAndroidUserAgent() string {

	version := strconv.Itoa(Rand.Intn(500)) + "." + strconv.Itoa(Rand.Intn(400))
	androidVer := strconv.Itoa(Rand.Intn(9)+1) + "." + strconv.Itoa(Rand.Intn(9)+1) + "." + strconv.Itoa(Rand.Intn(9)+1)
	chromeVer := strconv.Itoa(Rand.Intn(55)+25) + ".0"
	return "Mozilla/5.0 (Linux; Android " + androidVer + "; SM-G" + strconv.Itoa(Rand.Intn(800)) + "S Build/MMB29K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/" + version + " Chrome/" + chromeVer + " Mobile Safari/537.36"

}
func Zip(a, b []string, format string) ([]string, error) {

	if len(a) != len(b) {
		return nil, fmt.Errorf("zip: arguments must be of same length")
	}

	r := make([]string, len(a))

	for i, e := range a {
		r[i] = strings.Replace(strings.Replace(format, "[0]", e, -1), "[1]", b[i], -1)
	}

	return r, nil
}

func GenerateRandomHex(length int) (string, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes), nil
}

func GetCurrentISO8601Datetime() string {
	return time.Now().Format("2006-01-02T15:04:05.999Z")

}

func Base64Encode(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}
func Base64Decode(text string) string {
	str, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return err.Error()
	}
	return string(str)
}

func RSAEncrypt(data, modulus, exponent string) (string, error) {
	modulusBytes, err := base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		return "", fmt.Errorf("failed to decode modulus: %w", err)
	}

	exponentBytes, err := base64.StdEncoding.DecodeString(exponent)
	if err != nil {
		return "", fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponentBytes to a big-endian unsigned integer
	exponentInt := new(big.Int).SetBytes(exponentBytes)

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(exponentInt.Uint64()),
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(data))
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func ConvertToJsonSingleLine(input string) (string, error) {
	var jsonObject interface{}

	// Unmarshal the input JSON string into an interface.
	err := json.Unmarshal([]byte(input), &jsonObject)
	if err != nil {
		return "", fmt.Errorf("invalid JSON input: %v", err)
	}

	// Marshal the object back into a single-line JSON string.
	output, err := json.Marshal(jsonObject)
	if err != nil {
		return "", fmt.Errorf("error marshaling JSON: %v", err)
	}

	return string(output), nil
}

func RemoveElement(s []string, r string) []string {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func RemoveCookieByName(cookies []*http.Cookie, namesToRemove ...string) []*http.Cookie {
	nameMap := make(map[string]bool)
	for _, name := range namesToRemove {
		nameMap[name] = true
	}

	var filteredCookies []*http.Cookie
	for _, cookie := range cookies {
		if _, found := nameMap[cookie.Name]; !found {
			filteredCookies = append(filteredCookies, cookie)
		}
	}

	return filteredCookies
}

func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
func UnixTimeToDate(timestamp int64, format string) string {
	t := time.UnixMilli(timestamp)
	return t.Format(format)
}

func GetRandomProfile() (string, profiles.ClientProfile) {
	switch Rand.Intn(5) {
	case 0: //Chrome
		platforms := []string{"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_6", "X11; Linux x86_64"}
		platform := platforms[Rand.Intn(len(platforms))]
		switch Rand.Intn(14) {
		case 0: //103
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", profiles.Chrome_103
		case 1: //104
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36", profiles.Chrome_104
		case 2: //105
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", profiles.Chrome_105
		case 3: //106
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36", profiles.Chrome_106
		case 4: //107
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", profiles.Chrome_107
		case 5: //108
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", profiles.Chrome_108
		case 6: //109
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", profiles.Chrome_109
		case 7: //110
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36", profiles.Chrome_110
		case 8: //111
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36", profiles.Chrome_111
		case 9: //112
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", profiles.Chrome_112
		case 10: //116 PSK
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", profiles.Chrome_116_PSK
		case 11: //116 PSK PQ
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", profiles.Chrome_116_PSK_PQ
		case 12: //117
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36", profiles.Chrome_117
		case 13: //120
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", profiles.Chrome_120
		}
	case 1: //Firefox
		platforms := []string{"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_6", "X11; Linux x86_64"}
		platform := platforms[Rand.Intn(len(platforms))]
		switch Rand.Intn(8) {
		case 0: //102
			return "Mozilla/5.0 (" + platform + "; rv:102.0) Gecko/20100101 Firefox/102.0", profiles.Firefox_102
		case 1: //104
			return "Mozilla/5.0 (" + platform + "; rv:104.0) Gecko/20100101 Firefox/104.0", profiles.Firefox_104
		case 2: //105
			return "Mozilla/5.0 (" + platform + "; rv:105.0) Gecko/20100101 Firefox/105.0", profiles.Firefox_105
		case 3: //106
			return "Mozilla/5.0 (" + platform + "; rv:106.0) Gecko/20100101 Firefox/106.0", profiles.Firefox_106
		case 4: //108
			return "Mozilla/5.0 (" + platform + "; rv:108.0) Gecko/20100101 Firefox/108.0", profiles.Firefox_108
		case 5: //110
			return "Mozilla/5.0 (" + platform + "; rv:110.0) Gecko/20100101 Firefox/110.0", profiles.Firefox_110
		case 6: //117
			return "Mozilla/5.0 (" + platform + "; rv:117.0) Gecko/20100101 Firefox/117.0", profiles.Firefox_117
		case 7: //120
			return "Mozilla/5.0 (" + platform + "; rv:120.0) Gecko/20100101 Firefox/120.0", profiles.Firefox_120
		}
	case 2: //Opera
		platforms := []string{"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_6", "X11; Linux x86_64"}
		platform := platforms[Rand.Intn(len(platforms))]
		chromeVersion := Rand.Intn(18) + 103 // Chrome version 103-120
		switch Rand.Intn(3) {
		case 0: //89
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeVersion) + ".0.0.0 Safari/537.36 OPR/89.0.0.0", profiles.Opera_89
		case 1: //90
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeVersion) + ".0.0.0 Safari/537.36 OPR/90.0.0.0", profiles.Opera_90
		case 2: //91
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeVersion) + ".0.0.0 Safari/537.36 OPR/91.0.0.0", profiles.Opera_91
		}
	case 3: //iOS
		switch Rand.Intn(3) {
		case 0: //15_5
			return "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", profiles.Safari_IOS_15_5
		case 1: //15_6
			return "Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1", profiles.Safari_IOS_15_6
		case 2: //16_0
			return "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", profiles.Safari_IOS_16_0
		}
	case 4: //Safari
		switch Rand.Intn(2) {
		case 0: //15_6_1
			return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15", profiles.Safari_15_6_1
		case 1: //16_0
			return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_16_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15", profiles.Safari_16_0
		}

	}
	return "Mozilla/5.0 (Windows) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", profiles.Chrome_120
}

func GetRandomDesktopProfile() (string, profiles.ClientProfile) {
	switch Rand.Intn(4) {
	case 0: //Chrome
		platforms := []string{"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_6", "X11; Linux x86_64"}
		platform := platforms[Rand.Intn(len(platforms))]
		switch Rand.Intn(14) {
		case 0: //103
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", profiles.Chrome_103
		case 1: //104
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36", profiles.Chrome_104
		case 2: //105
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", profiles.Chrome_105
		case 3: //106
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36", profiles.Chrome_106
		case 4: //107
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", profiles.Chrome_107
		case 5: //108
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", profiles.Chrome_108
		case 6: //109
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", profiles.Chrome_109
		case 7: //110
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36", profiles.Chrome_110
		case 8: //111
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36", profiles.Chrome_111
		case 9: //112
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", profiles.Chrome_112
		case 10: //116 PSK
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", profiles.Chrome_116_PSK
		case 11: //116 PSK PQ
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", profiles.Chrome_116_PSK_PQ
		case 12: //117
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36", profiles.Chrome_117
		case 13: //120
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", profiles.Chrome_120
		}
	case 1: //Firefox
		platforms := []string{"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_6", "X11; Linux x86_64"}
		platform := platforms[Rand.Intn(len(platforms))]
		switch Rand.Intn(8) {
		case 0: //102
			return "Mozilla/5.0 (" + platform + "; rv:102.0) Gecko/20100101 Firefox/102.0", profiles.Firefox_102
		case 1: //104
			return "Mozilla/5.0 (" + platform + "; rv:104.0) Gecko/20100101 Firefox/104.0", profiles.Firefox_104
		case 2: //105
			return "Mozilla/5.0 (" + platform + "; rv:105.0) Gecko/20100101 Firefox/105.0", profiles.Firefox_105
		case 3: //106
			return "Mozilla/5.0 (" + platform + "; rv:106.0) Gecko/20100101 Firefox/106.0", profiles.Firefox_106
		case 4: //108
			return "Mozilla/5.0 (" + platform + "; rv:108.0) Gecko/20100101 Firefox/108.0", profiles.Firefox_108
		case 5: //110
			return "Mozilla/5.0 (" + platform + "; rv:110.0) Gecko/20100101 Firefox/110.0", profiles.Firefox_110
		case 6: //117
			return "Mozilla/5.0 (" + platform + "; rv:117.0) Gecko/20100101 Firefox/117.0", profiles.Firefox_117
		case 7: //120
			return "Mozilla/5.0 (" + platform + "; rv:120.0) Gecko/20100101 Firefox/120.0", profiles.Firefox_120
		}
	case 2: //Opera
		platforms := []string{"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_6", "X11; Linux x86_64"}
		platform := platforms[Rand.Intn(len(platforms))]
		chromeVersion := Rand.Intn(18) + 103 // Chrome version 103-120
		switch Rand.Intn(3) {
		case 0: //89
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeVersion) + ".0.0.0 Safari/537.36 OPR/89.0.0.0", profiles.Opera_89
		case 1: //90
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeVersion) + ".0.0.0 Safari/537.36 OPR/90.0.0.0", profiles.Opera_90
		case 2: //91
			return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeVersion) + ".0.0.0 Safari/537.36 OPR/91.0.0.0", profiles.Opera_91
		}
	case 3: //Safari
		switch Rand.Intn(2) {
		case 0: //15_6_1
			return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15", profiles.Safari_15_6_1
		case 1: //16_0
			return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_16_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15", profiles.Safari_16_0
		}

	}
	return "Mozilla/5.0 (Windows) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", profiles.Chrome_120
}
func Distinct(input []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
func GetRandomChromeProfile() (string, profiles.ClientProfile) {
	platforms := []string{"Windows NT 10.0; Win64; x64", "Macintosh; Intel Mac OS X 10_15_6", "X11; Linux x86_64"}
	platform := platforms[Rand.Intn(len(platforms))]
	switch Rand.Intn(14) {
	case 0: //103
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", profiles.Chrome_103
	case 1: //104
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36", profiles.Chrome_104
	case 2: //105
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", profiles.Chrome_105
	case 3: //106
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36", profiles.Chrome_106
	case 4: //107
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36", profiles.Chrome_107
	case 5: //108
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36", profiles.Chrome_108
	case 6: //109
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", profiles.Chrome_109
	case 7: //110
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36", profiles.Chrome_110
	case 8: //111
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36", profiles.Chrome_111
	case 9: //112
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", profiles.Chrome_112
	case 10: //116 PSK
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", profiles.Chrome_116_PSK
	case 11: //116 PSK PQ
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", profiles.Chrome_116_PSK_PQ
	case 12: //117
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36", profiles.Chrome_117
	case 13: //120
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", profiles.Chrome_120
	}
	return "Mozilla/5.0 (Windows) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", profiles.Chrome_120
}

//	func InitTLS(proxy string, timeout int, profile profiles.ClientProfile) tls_client.HttpClient {
//		cookieJarOptions := []tls_client.CookieJarOption{
//			tls_client.WithAllowEmptyCookies(),
//		}
//		jar := tls_client.NewCookieJar(cookieJarOptions...)
//		options := []tls_client.HttpClientOption{
//			tls_client.WithTimeoutSeconds(timeout),
//			// tls_client.WithNotFollowRedirects(),
//			// tls_client.WithDebug(),
//			tls_client.WithCookieJar(jar),
//			// tls_client.WithRandomTLSExtensionOrder(),
//			tls_client.WithClientProfile(profile),
//			tls_client.WithProxyUrl(proxy),
//		}
//		client, err := tls_client.NewHttpClient(nil /*tls_client.NewDebugLogger(tls_client.NewLogger())*/, options...)
//		if err != nil {
//			fmt.Println("TLS Error: " + err.Error())
//			return nil
//		}
//		return client
//	}
func InitTLS(proxy string, timeout int, profile profiles.ClientProfile) tls_client.HttpClient {
	cookieJarOptions := []tls_client.CookieJarOption{
		tls_client.WithAllowEmptyCookies(),
	}
	jar := tls_client.NewCookieJar(cookieJarOptions...)
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(timeout),
		tls_client.WithCookieJar(jar),
		tls_client.WithClientProfile(profile),
		tls_client.WithProxyUrl(proxy),
	}

	// Create a basic logger instead of passing nil
	client, err := tls_client.NewHttpClient(tls_client.NewLogger(), options...)
	if err != nil {
		fmt.Println("TLS Error: " + err.Error())
		return nil
	}
	return client
}
func InitTLSProxyless(timeout int, profile profiles.ClientProfile) tls_client.HttpClient {
	cookieJarOptions := []tls_client.CookieJarOption{
		tls_client.WithAllowEmptyCookies(),
	}
	jar := tls_client.NewCookieJar(cookieJarOptions...)
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(timeout),
		tls_client.WithCookieJar(jar),
		tls_client.WithClientProfile(profile),
	}

	// Create a basic logger instead of passing nil
	client, err := tls_client.NewHttpClient(tls_client.NewLogger(), options...)
	if err != nil {
		fmt.Println("TLS Error: " + err.Error())
		return nil
	}
	return client
}

func InitTLSOF(proxy string, timeout int, profile profiles.ClientProfile) tls_client.HttpClient {
	cookieJarOptions := []tls_client.CookieJarOption{
		tls_client.WithAllowEmptyCookies(),
	}
	jar := tls_client.NewCookieJar(cookieJarOptions...)
	options := []tls_client.HttpClientOption{
		tls_client.WithForceHttp1(),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithTimeoutSeconds(timeout),
		tls_client.WithCookieJar(jar),
		tls_client.WithClientProfile(profile),
		tls_client.WithProxyUrl(proxy),
	}

	// Create a basic logger instead of passing nil
	client, err := tls_client.NewHttpClient(tls_client.NewLogger(), options...)
	if err != nil {
		fmt.Println("TLS Error: " + err.Error())
		return nil
	}
	return client
}

func InitTLSSkipVerify(proxy string, timeout int, profile profiles.ClientProfile) tls_client.HttpClient {
	cookieJarOptions := []tls_client.CookieJarOption{
		tls_client.WithAllowEmptyCookies(),
	}
	jar := tls_client.NewCookieJar(cookieJarOptions...)
	options := []tls_client.HttpClientOption{
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithTimeoutSeconds(timeout),
		tls_client.WithCookieJar(jar),
		tls_client.WithClientProfile(profile),
		tls_client.WithProxyUrl(proxy),
	}

	// Create a basic logger instead of passing nil
	client, err := tls_client.NewHttpClient(tls_client.NewLogger(), options...)
	if err != nil {
		fmt.Println("TLS Error: " + err.Error())
		return nil
	}
	return client
}
func MakeRequest(TLS tls_client.HttpClient, uri, content, method string, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequest(method, uri, nil)
	if err != nil || req == nil || TLS == nil {
		return nil, err
	}
	req.TransferEncoding = []string{"identity"}
	if content != "" {
		req.Body = io.NopCloser(strings.NewReader(content))
	}
	req.Header = headers
	resp, err := TLS.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// func MakeRequest(TLS tls_client.HttpClient, uri, content, method string, headers http.Header) (*http.Response, error) {
// 	var resp *http.Response
// 	var finalErr error

// 	func() {
// 		defer func() {
// 			if r := recover(); r != nil {
// 				finalErr = fmt.Errorf("check module panic recovered: %v", r)
// 			}
// 		}()

// 		req, err := http.NewRequest(method, uri, nil)
// 		if err != nil || req == nil || TLS == nil {
// 			finalErr = err
// 			return
// 		}
// 		req.TransferEncoding = []string{"identity"}
// 		if content != "" {
// 			req.Body = io.NopCloser(strings.NewReader(content))
// 		}

// 		req.Header = headers

// 		resp, finalErr = TLS.Do(req)
// 	}()

// 	return resp, finalErr
// }

// func MakeRequest(TLS tls_client.HttpClient, uri, content, method string, headers http.Header) (http.Response, error) {
// 	req, err := http.NewRequest(method, uri, nil)
// 	if err != nil {
// 		return http.Response{}, err
// 	}
// 	req.TransferEncoding = []string{"identity"}
// 	if content != "" {
// 		req.Body = io.NopCloser(strings.NewReader(content))
// 	}

// 	req.Header = headers
// 	resp, err := TLS.Do(req)
// 	if err != nil {
// 		return http.Response{}, err
// 	}
// 	return *resp, nil

// }
func MakeRequestCookies(TLS tls_client.HttpClient, url, content, method string, headers http.Header, cookies []http.Cookie) (http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return http.Response{}, err
	}

	for _, cookie := range cookies {
		req.AddCookie(&cookie)
	}
	req.TransferEncoding = []string{"identity"}
	if content != "" {
		req.Body = io.NopCloser(strings.NewReader(content))
	}

	req.Header = http.Header{}
	req.Header = headers
	resp, err := TLS.Do(req)
	// fmt.Println(req.Cookies())
	if err != nil {
		return http.Response{}, err
	}

	return *resp, nil

}
func FormatInt64(n int64) string {
	in := strconv.FormatInt(n, 10)
	numOfDigits := len(in)
	if n < 0 {
		numOfDigits-- // First character is the - sign (not a digit)
	}
	numOfCommas := (numOfDigits - 1) / 3

	out := make([]byte, len(in)+numOfCommas)
	if n < 0 {
		in, out[0] = in[1:], '-'
	}

	for i, j, k := len(in)-1, len(out)-1, 0; ; i, j = i-1, j-1 {
		out[j] = in[i]
		if i == 0 {
			return string(out)
		}
		if k++; k == 3 {
			j, k = j-1, 0
			out[j] = ','
		}
	}
}
func FormatInt(n int) string {
	in := strconv.Itoa(n)
	numOfDigits := len(in)
	if n < 0 {
		numOfDigits-- // First character is the - sign (not a digit)
	}
	numOfCommas := (numOfDigits - 1) / 3

	out := make([]byte, len(in)+numOfCommas)
	if n < 0 {
		in, out[0] = in[1:], '-'
	}

	for i, j, k := len(in)-1, len(out)-1, 0; ; i, j = i-1, j-1 {
		out[j] = in[i]
		if i == 0 {
			return string(out)
		}
		if k++; k == 3 {
			j, k = j-1, 0
			out[j] = ','
		}
	}
}
