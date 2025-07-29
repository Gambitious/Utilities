package utilities

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

func QueryJsonToken(jsonStr, jToken, prefix, suffix string, urlEncodeOutput bool) string {
	parsed := GetValuesByKey(jsonStr, jToken)
	if len(parsed) == 0 {
		return prefix + suffix
	}

	result := prefix + parsed[0] + suffix
	if urlEncodeOutput {
		result = url.QueryEscape(result)
	}

	return result
}

func GetValuesByKey(jsonStr, path string) []string {
	if jsonStr == "" {
		return nil
	}
	if path == "" {
		return nil
	}

	var container interface{}
	err := json.Unmarshal([]byte(jsonStr), &container)
	if err != nil {
		return nil
	}

	paths := strings.Split(path, ".")
	value := findValue(container, paths)
	if value == nil {
		return []string{}
	}

	return []string{convertToken(value)}
}

func convertToken(value interface{}) string {
	switch v := value.(type) {
	case float64:
		return fmt.Sprintf("%g", v)
	case []interface{}:
		bytes, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(bytes)
	case map[string]interface{}:
		bytes, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(bytes)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func findValue(data interface{}, paths []string) interface{} {
	if len(paths) == 0 {
		return data
	}

	currentPath := paths[0]
	remainingPaths := paths[1:]

	switch v := data.(type) {
	case map[string]interface{}:
		if val, ok := v[currentPath]; ok {
			return findValue(val, remainingPaths)
		}
	case []interface{}:
		return data
	}

	return nil
}
func RegexParse(input, pattern, outputFormat string, multiline bool) ([]string, error) {
	// Go strings are never nil; empty input is fine.
	// Handle “multiline” the same way RegexOptions.Multiline does in .NET:
	if multiline {
		input = strings.ReplaceAll(input, "\r\n", "\n")
		pattern = "(?m)" + pattern
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Find all matches with their capture groups
	allMatches := re.FindAllStringSubmatch(input, -1)
	results := make([]string, 0, len(allMatches))

	for _, match := range allMatches {
		sb := outputFormat
		for i, group := range match {
			placeholder := fmt.Sprintf("[%d]", i)
			sb = strings.ReplaceAll(sb, placeholder, group)
		}
		results = append(results, sb)
	}

	return results, nil
}

func LR(source, left, right string, recursion bool) []string {
	results := []string{}
	if !recursion {
		start := strings.Index(source, left)
		if start == -1 {
			return results
		}
		start += len(left)
		end := strings.Index(source[start:], right)
		if end == -1 {
			return results
		}
		results = append(results, source[start:start+end])
		return results
	}
	for {
		start := strings.Index(source, left)
		if start == -1 {
			break
		}
		start += len(left)
		end := strings.Index(source[start:], right)
		if end == -1 {
			break
		}
		results = append(results, source[start:start+end])
		source = source[start+end:]
	}
	return results
}

func JSON(source, field string, recursion bool) []string {
	results := []string{}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(source), &m); err != nil {
		return results
	}
	if !recursion {
		if v, ok := m[field]; ok {
			results = append(results, fmt.Sprint(v))
		}
		return results
	}
	for k, v := range m {
		if k == field {
			results = append(results, fmt.Sprint(v))
		}
		if nestedMap, ok := v.(map[string]interface{}); ok {
			results = append(results, JSON(fmt.Sprint(nestedMap), field, true)...)
		}
	}
	return results
}

func JToken(JSON, jToken string, recursive bool) []string {
	// Parse the JSON string into a map[string]interface{}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(JSON), &parsed); err != nil {
		return nil
	}

	// Extract values using the specified JToken
	values := JsonParserGetValuesByKey(parsed, strings.Split(jToken, "."))

	// URL encode the output if specified
	if !recursive {
		if len(values) == 0 {
			return []string{}
		}
		return []string{values[0]}
	}

	return values
}

// JsonParserGetValuesByKey function in Go
func JsonParserGetValuesByKey(data interface{}, keys []string) []string {
	var values []string

	for _, key := range keys {
		switch t := data.(type) {
		case map[string]interface{}:
			if val, ok := t[key]; ok {
				data = val
				switch val := val.(type) {
				case string:
					values = append(values, val)
				case []interface{}:
					for _, item := range val {
						if str, isString := item.(string); isString {
							values = append(values, str)
						}
					}
				}
			} else {
				break
			}
		default:
			break
		}
	}

	return values
}
