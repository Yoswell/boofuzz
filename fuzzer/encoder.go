// encoder.go
package fuzzer

import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "html"
    "net/url"
    "regexp"
    "strings"
    "unicode/utf16"
)

/*
This package provides a flexible string Encoder for fuzzing purposes.
It allows defining a sequence or chain of encoding/hashing/transformation functions
(e.g., "base64(md5(input))") to modify an input payload for injection testing.
The Encoder registers numerous default functions for security testing (Base64, URL-encoding, Hashing, etc.).
*/

// Encoder holds the configuration and the map of available encoding functions.
type Encoder struct {
    chains []string
    functions map[string]func(string) string
}

// NewEncoder creates a new Encoder instance based on the provided configuration.
func NewEncoder(config EncoderConfig) *Encoder {
    e := &Encoder{
        chains: config.Chains,
        functions: make(map[string]func(string) string),
    }
    
    e.registerDefaultFunctions()
    return e
}

// registerDefaultFunctions registers all built-in encoding, hashing, and transformation functions.
func (e *Encoder) registerDefaultFunctions() {
    // Basic encoders
    e.functions["base64"] = e.base64Encode
    e.functions["b64"] = e.base64Encode
    e.functions["base64encode"] = e.base64Encode
    
    e.functions["base64decode"] = e.base64Decode
    
    e.functions["urlencode"] = e.urlEncode
    e.functions["url"] = e.urlEncode
    
    e.functions["urldouble"] = e.urlDoubleEncode
    e.functions["urltriple"] = e.urlTripleEncode
    
    e.functions["htmlescape"] = e.htmlEscape
    e.functions["htmlencode"] = e.htmlEscape
    
    e.functions["htmlunescape"] = e.htmlUnescape
    e.functions["htmldecode"] = e.htmlUnescape
    
    // Hash functions
    e.functions["md5"] = e.md5Hash
    e.functions["md5hex"] = e.md5Hash
    
    e.functions["sha1"] = e.sha1Hash
    e.functions["sha1hex"] = e.sha1Hash
    
    e.functions["sha256"] = e.sha256Hash
    e.functions["sha256hex"] = e.sha256Hash
    
    e.functions["sha512"] = e.sha512Hash
    e.functions["sha512hex"] = e.sha512Hash
    
    // Transformations
    e.functions["upper"] = strings.ToUpper
    e.functions["lower"] = strings.ToLower
    e.functions["reverse"] = e.reverseString
    
    e.functions["rot13"] = e.rot13
    e.functions["caesar"] = e.caesarCipher
    
    // Special encodings
    e.functions["hex"] = e.hexEncode
    e.functions["hexdecode"] = e.hexDecode
    
    e.functions["unicode"] = e.unicodeEncode
    e.functions["utf16"] = e.utf16Encode
    
    e.functions["utf8"] = e.utf8Encode
    
    // For SQL Injection
    e.functions["sqlchar"] = e.sqlCharEncode
    
    // For XSS
    e.functions["jsencode"] = e.jsEncode
    
    // Windows encodings
    e.functions["utf16le"] = e.utf16LEEncode
    e.functions["utf16be"] = e.utf16BEEncode
}

// EncodeChain processes the input through all configured encoding chains.
func (e *Encoder) EncodeChain(input string) (string, error) {
    if len(e.chains) == 0 {
        return input, nil
    }
    
    result := input
    for _, chain := range e.chains {
        // Parse the encoder chain string (e.g., "base64(md5(input))")
        encoded, err := e.parseAndApplyChain(chain, result)
        if err != nil {
            return "", err
        }
        result = encoded
    }
    
    return result, nil
}

// parseAndApplyChain recursively parses and applies nested encoding functions.
func (e *Encoder) parseAndApplyChain(chain string, input string) (string, error) {
    // Pattern to find nested functions
    pattern := `([a-zA-Z0-9_]+)\(([^)]*)\)`
    re := regexp.MustCompile(pattern)
    
    result := chain
    for {
        matches := re.FindStringSubmatch(result)
        if matches == nil {
            break
        }
        
        funcName := matches[1]
        funcParam := matches[2]
        
        // If the parameter is "input", use the current input
        if funcParam == "input" || funcParam == "FUZZ" || funcParam == "PAYLOAD" {
            funcParam = input
        } else if strings.Contains(funcParam, "(") {
            // Nested function, process recursively
            nestedResult, err := e.parseAndApplyChain(funcParam, input)
            if err != nil {
                return "", err
            }
            funcParam = nestedResult
        }
        
        // Apply the function
        fn, exists := e.functions[funcName]
        if !exists {
            return "", fmt.Errorf("unknown encoder function: %s", funcName)
        }
        
        encoded := fn(funcParam)
        
        // Replace in the original chain
        result = strings.Replace(result, matches[0], encoded, 1)
    }
    
    // If there are no functions, apply directly
    if result == chain {
        fn, exists := e.functions[chain]
        if exists {
            return fn(input), nil
        }
        return input, nil
    }
    
    return result, nil
}

// Encoding Functions

func (e *Encoder) base64Encode(input string) string {
    return base64.StdEncoding.EncodeToString([]byte(input))
}

func (e *Encoder) base64Decode(input string) string {
    decoded, err := base64.StdEncoding.DecodeString(input)
    if err != nil {
        return input
    }
    return string(decoded)
}

func (e *Encoder) urlEncode(input string) string {
    return url.QueryEscape(input)
}

func (e *Encoder) urlDoubleEncode(input string) string {
    return url.QueryEscape(url.QueryEscape(input))
}

func (e *Encoder) urlTripleEncode(input string) string {
    return url.QueryEscape(url.QueryEscape(url.QueryEscape(input)))
}

func (e *Encoder) htmlEscape(input string) string {
    return html.EscapeString(input)
}

func (e *Encoder) htmlUnescape(input string) string {
    return html.UnescapeString(input)
}

// Hash Functions

func (e *Encoder) md5Hash(input string) string {
    hash := md5.Sum([]byte(input))
    return hex.EncodeToString(hash[:])
}

func (e *Encoder) sha1Hash(input string) string {
    hash := sha1.Sum([]byte(input))
    return hex.EncodeToString(hash[:])
}

func (e *Encoder) sha256Hash(input string) string {
    hash := sha256.Sum256([]byte(input))
    return hex.EncodeToString(hash[:])
}

func (e *Encoder) sha512Hash(input string) string {
    hash := sha512.Sum512([]byte(input))
    return hex.EncodeToString(hash[:])
}

// Transformations
func (e *Encoder) reverseString(input string) string {
    runes := []rune(input)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

func (e *Encoder) rot13(input string) string {
    var result strings.Builder
    for _, r := range input {
        switch {
        case r >= 'A' && r <= 'Z':
            result.WriteRune('A' + (r-'A'+13)%26)
        case r >= 'a' && r <= 'z':
            result.WriteRune('a' + (r-'a'+13)%26)
        default:
            result.WriteRune(r)
        }
    }
    return result.String()
}

func (e *Encoder) caesarCipher(input string) string {
    // Caesar cipher with shift 3 (classic)
    var result strings.Builder
    for _, r := range input {
        switch {
        case r >= 'A' && r <= 'Z':
            result.WriteRune('A' + (r-'A'+3)%26)
        case r >= 'a' && r <= 'z':
            result.WriteRune('a' + (r-'a'+3)%26)
        default:
            result.WriteRune(r)
        }
    }
    return result.String()
}

// Special Encodings
func (e *Encoder) hexEncode(input string) string {
    return hex.EncodeToString([]byte(input))
}

func (e *Encoder) hexDecode(input string) string {
    decoded, err := hex.DecodeString(input)
    if err != nil {
        return input
    }
    return string(decoded)
}

func (e *Encoder) unicodeEncode(input string) string {
    var result strings.Builder
    for _, r := range input {
        result.WriteString(fmt.Sprintf("\\u%04x", r))
    }
    return result.String()
}

func (e *Encoder) utf16Encode(input string) string {
    return e.unicodeEncode(input)
}

func (e *Encoder) utf8Encode(input string) string {
    var result strings.Builder
    for _, r := range input {
        if r < 128 {
            // Keep ASCII characters as is (assuming the intention)
            result.WriteRune(r)
        } else {
            // Encode non-ASCII characters as \uXXXX (common for JS/JSON escaping)
            result.WriteString(fmt.Sprintf("\\u%04x", r))
        }
    }
    return result.String()
}

func (e *Encoder) sqlCharEncode(input string) string {
    var result strings.Builder
    for _, r := range input {
        result.WriteString(fmt.Sprintf("CHAR(%d),", r))
    }
    return strings.TrimSuffix(result.String(), ",")
}

func (e *Encoder) jsEncode(input string) string {
    var result strings.Builder
    // Simple hex encoding for XSS testing
    for _, r := range input {
        result.WriteString(fmt.Sprintf("\\x%02x", r))
    }
    return result.String()
}

func (e *Encoder) utf16LEEncode(input string) string {
    var result []byte
    for _, r := range input {
        // UTF-16 Little Endian
        utf16 := utf16.Encode([]rune{r})
        for _, v := range utf16 {
            result = append(result, byte(v&0xFF))
            result = append(result, byte(v>>8))
        }
    }
    return hex.EncodeToString(result)
}

func (e *Encoder) utf16BEEncode(input string) string {
    var result []byte
    for _, r := range input {
        // UTF-16 Big Endian
        utf16 := utf16.Encode([]rune{r})
        for _, v := range utf16 {
            result = append(result, byte(v>>8))
            result = append(result, byte(v&0xFF))
        }
    }
    return hex.EncodeToString(result)
}

// Helper methods
// RegisterFunction allows adding custom encoding functions to the Encoder.
func (e *Encoder) RegisterFunction(name string, fn func(string) string) {
    e.functions[name] = fn
}

// GetAvailableFunctions returns a list of all registered encoder function names.
func (e *Encoder) GetAvailableFunctions() []string {
    var functions []string
    for name := range e.functions {
        functions = append(functions, name)
    }
    return functions
}

// ApplyEncoderChain is a utility function to quickly apply a slice of encoders.
func ApplyEncoderChain(input string, encoders []string) (string, error) {
    config := EncoderConfig{Chains: encoders}
    encoder := NewEncoder(config)
    return encoder.EncodeChain(input)
}