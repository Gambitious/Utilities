package utilities

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

func SolveImageCaptcha(imageData, capKey string) (string, error) {
	var solution string
	c := resty.New().SetTimeout(time.Second * 15).SetContentLength(true)
	res1, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"task\":{\"type\":\"ImageToTextTask\",\"body\":\"" + imageData + "\",\"case\":true}}").
		Post("https://api.capsolver.com/createTask")
	if err != nil {
		return solution, err
	}
	res1.RawResponse.Body.Close()
	if strings.Contains(string(res1.Body()), `"status":"ready"`) {
		solution = strings.Join(LR(string(res1.Body()), "\"text\":\"", "\"", false), "")
		if solution == "" {
			return solution, errors.New("empty_solution")
		}
		return solution, nil
	}
	if !strings.Contains(string(res1.Body()), "errorId\":0") {
		fmt.Println(string(res1.Body()))
		return solution, errors.New("see_console")
	}
	taskId := JSON(string(res1.Body()), "taskId", false)
	time.Sleep(time.Millisecond * 1500)
	var retries int
GET:
	res2, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"taskId\":\"" + taskId[0] + "\"}").
		Post("https://api.capsolver.com/getTaskResult")
	if err != nil {
		return solution, err
	}
	res2.RawResponse.Body.Close()

	if strings.Contains(string(res2.Body()), "errorId\":-1") {
		// fmt.Println(string(res2.Body()))
		return solution, errors.New("see_console")
	}
	if strings.Contains(string(res2.Body()), "processing") || strings.Contains(string(res2.Body()), "idle") {
		if retries > 20 {
			return solution, errors.New("timeout")
		}
		time.Sleep(time.Second * 3)
		retries++
		goto GET
	}
	// fmt.Println(string(res2.Body()))
	solution = strings.Join(LR(string(res2.Body()), "\"text\":\"", "\"", false), "")
	if solution == "" {
		return solution, errors.New("empty_solution")
	}
	return solution, nil
}
func SolveHCaptcha(siteKey, siteUrl string, isInvisible bool, userAgent, capKey string) (string, error) {
	var solution string
	c := resty.New().SetTimeout(time.Second * 15).SetContentLength(true)
	_type := "HCaptchaTaskProxyLess"
	res1, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"task\":{\"type\":\"" + _type + "\",\"websiteURL\":\"" + siteUrl + "\",\"websiteKey\":\"" + siteKey + "\",\"isInvisible\":" + strconv.FormatBool(isInvisible) + ",\"userAgent\":\"" + userAgent + "\"}}").
		Post("https://api.capsolver.com/createTask")
	if err != nil {
		return solution, err
	}
	res1.RawResponse.Body.Close()

	if !strings.Contains(string(res1.Body()), "errorId\":0") {
		// fmt.Println(string(res1.Body()))
		return solution, errors.New("see_console")
	}
	taskId := JSON(string(res1.Body()), "taskId", false)
	time.Sleep(time.Millisecond * 1500)
	var retries int
GET:
	res2, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"taskId\":\"" + taskId[0] + "\"}").
		Post("https://api.capsolver.com/getTaskResult")
	if err != nil {
		return solution, err
	}
	res2.RawResponse.Body.Close()

	if strings.Contains(string(res2.Body()), "errorId\":-1") {
		// fmt.Println(string(res2.Body()))
		return solution, errors.New("see_console")
	}
	if strings.Contains(string(res2.Body()), "processing") || strings.Contains(string(res2.Body()), "idle") {
		if retries > 20 {
			return solution, errors.New("timeout")
		}
		time.Sleep(time.Second * 3)
		retries++
		goto GET
	}
	// fmt.Println(string(res2.Body()))
	solution = strings.Join(LR(string(res2.Body()), "\"gRecaptchaResponse\":\"", "\"", false), "")
	if solution == "" {
		return solution, errors.New("empty_solution")
	}
	return solution, nil
}
func SolveTurnstile(siteKey, siteUrl, capKey string) (string, error) {
	var solution string
	c := resty.New().SetTimeout(time.Second * 15).SetContentLength(true)
	_type := "AntiTurnstileTaskProxyLess"
	res1, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"task\":{\"type\":\"" + _type + "\",\"websiteURL\":\"" + siteUrl + "\",\"websiteKey\":\"" + siteKey + "\"}}").
		Post("https://api.capsolver.com/createTask")
	if err != nil {
		return solution, err
	}
	res1.RawResponse.Body.Close()

	if !strings.Contains(string(res1.Body()), "errorId\":0") {
		// fmt.Println(string(res1.Body()))
		return solution, errors.New("see_console")
	}
	taskId := JSON(string(res1.Body()), "taskId", false)
	time.Sleep(time.Millisecond * 1500)
	var retries int
GET:
	res2, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"taskId\":\"" + taskId[0] + "\"}").
		Post("https://api.capsolver.com/getTaskResult")
	if err != nil {
		return solution, err
	}
	res2.RawResponse.Body.Close()

	if strings.Contains(string(res2.Body()), "errorId\":-1") {
		// fmt.Println(string(res2.Body()))
		return solution, errors.New("see_console")
	}
	if strings.Contains(string(res2.Body()), "processing") || strings.Contains(string(res2.Body()), "idle") {
		if retries > 20 {
			return solution, errors.New("timeout")
		}
		time.Sleep(time.Second * 3)
		retries++
		goto GET
	}
	// fmt.Println(string(res2.Body()))
	solution = strings.Join(LR(string(res2.Body()), "\"token\":\"", "\"", false), "")
	if solution == "" {
		return solution, errors.New("empty_solution")
	}
	return solution, nil
}
func SolveFunCaptcha(siteUrl, siteKey, subdomainHost, capKey string) (string, error) {
	var solution string
	c := resty.New().SetTimeout(time.Second * 15).SetContentLength(true)
	_type := "FunCaptchaTaskProxyless"
	res1, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capmonster.cloud",
		}).
		SetBody(`{"clientKey":"` + capKey + `","task":{"type":"` + _type + `","captchaApiJSSubdomain":"` + subdomainHost + `","websiteURL":"` + siteUrl + `","websitePublicKey":"` + siteKey + `"}}`).
		Post("https://api.capmonster.cloud/createTask")
	if err != nil {
		return solution, err
	}
	res1.RawResponse.Body.Close()

	if !strings.Contains(string(res1.Body()), "errorId\":0") {
		// fmt.Println(string(res1.Body()))
		return solution, errors.New("see_console")
	}
	taskId := LR(string(res1.Body()), "taskId\":", ",", false)
	time.Sleep(time.Millisecond * 1500)
	var retries int
GET:
	res2, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capmonster.cloud",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"taskId\":" + taskId[0] + "}").
		Post("https://api.capmonster.cloud/getTaskResult")
	if err != nil {
		return solution, err
	}
	res2.RawResponse.Body.Close()

	if strings.Contains(string(res2.Body()), "errorId\":-1") {
		// fmt.Println(string(res2.Body()))
		return solution, errors.New("see_console")
	}
	if strings.Contains(string(res2.Body()), "processing") || strings.Contains(string(res2.Body()), "idle") {
		if retries > 20 {
			return solution, errors.New("timeout")
		}
		time.Sleep(time.Second * 3)
		retries++
		goto GET
	}
	// fmt.Println(string(res2.Body()))
	solution = strings.Join(LR(string(res2.Body()), "\"token\":\"", "\"", false), "")
	if solution == "" {
		// fmt.Println(string(res2.Body()))
		return solution, errors.New("empty_solution")
	}
	return solution, nil
}
func SolveRecaptchaV2(siteKey, siteUrl string, isInvisible, isEnterprise bool, userAgent, capKey, proxy string, proxyless bool) (string, error) {
	var solution string
	c := resty.New().SetTimeout(time.Second * 15).SetContentLength(true)
	_type := "ReCaptchaV2"
	_type += "Task"
	var proxyUrl *url.URL
	var err error
	if proxyless {
		_type += "ProxyLess"
	}
	proxyUrl, err = url.Parse(ParseProxyTLS(proxy))
	if err != nil {
		return solution, err
	}
	res1, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"task\":{\"type\":\"" + _type + "\",\"websiteURL\":\"" + siteUrl + "\",\"websiteKey\":\"" + siteKey + "\",\"proxy\":\"http:" + proxyUrl.Host + ":" + proxyUrl.Port() + ":" + proxyUrl.User.String() + "\",\"isInvisible\":" + strconv.FormatBool(isInvisible) + ",\"userAgent\":\"" + userAgent + "\"}}").
		Post("https://api.capsolver.com/createTask")
	if err != nil {
		return solution, err
	}
	res1.RawResponse.Body.Close()

	if !strings.Contains(string(res1.Body()), "errorId\":0") {
		// fmt.Println(string(res1.Body()))
		return solution, errors.New("see_console")
	}
	taskId := JSON(string(res1.Body()), "taskId", false)
	time.Sleep(time.Millisecond * 1500)
	var retries int
GET:
	res2, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"taskId\":\"" + taskId[0] + "\"}").
		Post("https://api.capsolver.com/getTaskResult")
	if err != nil {
		return solution, err
	}
	res2.RawResponse.Body.Close()

	if strings.Contains(string(res2.Body()), "errorId\":-1") {
		// fmt.Println(string(res2.Body()))
		return solution, errors.New("see_console")
	}
	if strings.Contains(string(res2.Body()), "processing") || strings.Contains(string(res2.Body()), "idle") {
		if retries > 20 {
			return solution, errors.New("timeout")
		}
		time.Sleep(time.Second * 3)
		retries++
		goto GET
	}
	// fmt.Println(string(res2.Body()))
	solution = strings.Join(LR(string(res2.Body()), "\"gRecaptchaResponse\":\"", "\"", false), "")
	if solution == "" {
		return solution, errors.New("empty_solution")
	}
	return solution, nil
}

func SolveRecaptchaV2EnterpriseNextCaptcha(siteKey, siteUrl string, isInvisible bool, title, websiteInfo, apiDomain, action, capKey string) (string, error) {
	var solution string
	c := resty.New().SetTimeout(time.Second * 15).SetContentLength(true)
	// body := `{"clientKey":"` + capKey + `","task":{"type":"RecaptchaV2EnterpriseTaskProxyless","websiteURL":"` + siteUrl + `","title":"` + title + `","websiteKey":"` + siteKey + `","isInvisible":` + strconv.FormatBool(isInvisible) + `,"websiteInfo":"` + websiteInfo + `","apiDomain":"` + apiDomain + `","pageAction":"` + action + `"}}`
	body := `{"softId":"next_softId_39f52c2d326b8041bd6bb65263a0e94fe9","clientKey":"` + capKey + `","task":{"type":"RecaptchaV2EnterpriseTaskProxyless","websiteURL":"` + siteUrl + `","websiteKey":"` + siteKey + `","websiteInfo":"` + websiteInfo + `","apiDomain":"` + apiDomain + `","pageAction":"` + action + `","title":"` + title + `"}}`
	// fmt.Println(body)
	res1, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api-v2.nextcaptcha.com",
		}).
		SetBody(body).
		Post("https://api-v2.nextcaptcha.com/getToken")
	if err != nil {
		return solution, err
	}
	res1.RawResponse.Body.Close()

	if !strings.Contains(string(res1.Body()), "0|") {
		fmt.Println(string(res1.Body()))
		return solution, errors.New("see_console")
	}
	solution = strings.Join(LR(string(res1.Body())+"|", "0|", "|", false), "")
	if solution == "" {
		return solution, errors.New("empty_solution")
	}
	return solution, nil
}

func SolveRecaptchaV3(siteKey, siteUrl, siteAction string, isInvisible, isEnterprise bool, userAgent, capKey, proxy string, proxyless bool) (string, error) {
	var solution string
	c := resty.New().SetTimeout(time.Second * 15).SetContentLength(true)
	_type := "ReCaptchaV3"
	if isEnterprise {
		_type += "M1"
	}
	_type += "Task"
	var proxyUrl *url.URL
	var err error
	if proxyless {
		_type += "ProxyLess"
	}
	proxyUrl, err = url.Parse(ParseProxyTLS(proxy))
	if err != nil {
		return solution, err
	}
	res1, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"task\":{\"type\":\"" + _type + "\",\"pageAction\":\"" + siteAction + "\",\"websiteURL\":\"" + siteUrl + "\",\"websiteKey\":\"" + siteKey + "\",\"proxy\":\"http:" + proxyUrl.Host + ":" + proxyUrl.Port() + ":" + proxyUrl.User.String() + "\",\"isInvisible\":" + strconv.FormatBool(isInvisible) + ",\"userAgent\":\"" + userAgent + "\"}}").
		Post("https://api.capsolver.com/createTask")
	if err != nil {
		return solution, err
	}
	res1.RawResponse.Body.Close()

	if !strings.Contains(string(res1.Body()), "errorId\":0") {
		// fmt.Println(string(res1.Body()))
		return solution, errors.New("see_console")
	}
	taskId := JSON(string(res1.Body()), "taskId", false)
	time.Sleep(time.Millisecond * 1500)
	var retries int
GET:
	res2, err := c.NewRequest().
		SetHeaders(map[string]string{
			"content-type": "application/json",
			"host":         "api.capsolver.com",
		}).
		SetBody("{\"clientKey\":\"" + capKey + "\",\"taskId\":\"" + taskId[0] + "\"}").
		Post("https://api.capsolver.com/getTaskResult")
	if err != nil {
		return solution, err
	}
	res2.RawResponse.Body.Close()

	if strings.Contains(string(res2.Body()), "errorId\":-1") {
		// fmt.Println(string(res2.Body()))
		return solution, errors.New("see_console")
	}
	if strings.Contains(string(res2.Body()), "processing") || strings.Contains(string(res2.Body()), "idle") {
		if retries > 20 {
			return solution, errors.New("timeout")
		}
		time.Sleep(time.Second * 3)
		retries++
		goto GET
	}
	// fmt.Println(string(res2.Body()))
	solution = strings.Join(LR(string(res2.Body()), "\"gRecaptchaResponse\":\"", "\"", false), "")
	if solution == "" {
		return solution, errors.New("empty_solution")
	}
	return solution, nil
}
