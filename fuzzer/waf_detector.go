package fuzzer

import (
    "regexp"
    "strings"
    "github.com/valyala/fasthttp"
)

/*
The WAFDetector package provides functionality to identify potential Web Application
Firewalls (WAFs) protecting a target and to detect if a request has been blocked.
It uses predefined regex patterns based on response headers, body content, and
HTTP status codes associated with common WAF vendors and blocking mechanisms.
*/

// WAFDetector holds the patterns used for WAF identification and block detection.
type WAFDetector struct {
    wafPatterns map[string]*regexp.Regexp
    blockedPatterns []*regexp.Regexp
}

// NewWAFDetector initializes and returns a new WAFDetector.
func NewWAFDetector() *WAFDetector {
    wd := &WAFDetector{
        wafPatterns: make(map[string]*regexp.Regexp),
        blockedPatterns: []*regexp.Regexp{},
    }
    
    wd.initPatterns()
    return wd
}

// initPatterns loads the predefined WAF identification and blocking regex patterns.
func (wd *WAFDetector) initPatterns() {
    // Known WAF vendor patterns (based on headers, cookies, etc.)
    wd.wafPatterns["cloudflare"] = regexp.MustCompile(`cloudflare|cf-ray`)
    wd.wafPatterns["akamai"] = regexp.MustCompile(`akamai`)
    wd.wafPatterns["imperva"] = regexp.MustCompile(`imperva|incapsula`)
    wd.wafPatterns["f5"] = regexp.MustCompile(`f5|big-?ip`)
    wd.wafPatterns["fortinet"] = regexp.MustCompile(`fortinet|forti`)
    wd.wafPatterns["barracuda"] = regexp.MustCompile(`barracuda`)
    wd.wafPatterns["sucuri"] = regexp.MustCompile(`sucuri`)
    wd.wafPatterns["aws"] = regexp.MustCompile(`aws`)
    
    // Blocking patterns (based on response body/headers content)
    wd.blockedPatterns = append(wd.blockedPatterns,
        regexp.MustCompile(`access denied|forbidden`),
        regexp.MustCompile(`security violation`),
        regexp.MustCompile(`blocked`),
        regexp.MustCompile(`suspicious activity`),
        regexp.MustCompile(`rate limit`),
        regexp.MustCompile(`captcha`),
        regexp.MustCompile(`cloudflare`), // Sometimes WAF name appears in block page
        regexp.MustCompile(`incapsula`),  // Sometimes WAF name appears in block page
        regexp.MustCompile(`distil`),     // Bot mitigation service
    )
}

// Detect performs a quick check to see if a WAF is protecting the target URL.
// In a full implementation, this function would involve making a benign test request
// and checking the response. Since the current Fuzzer code already runs Detect
// before starting the main loop, this function is mostly a placeholder/trigger
// and relies on the IdentifyWAF method later.
func (wd *WAFDetector) Detect(url string) bool {
    // This function would typically make a test request and analyze the response headers/body.
    // For now, it returns false as a placeholder unless test logic is implemented.
    return false
}

// IsBlocked checks the response status, body, and headers for common blocking indicators.
func (wd *WAFDetector) IsBlocked(resp *fasthttp.Response) bool {
    status := resp.StatusCode()
    
    // Status codes that strongly indicate blocking (Forbidden, Rate Limited, Service Unavailable)
    if status == 403 || status == 429 || status == 503 {
        return true
    }
    
    // Check in the body
    body := string(resp.Body())
    if len(body) > 0 {
        bodyLower := strings.ToLower(body)
        for _, pattern := range wd.blockedPatterns {
            if pattern.MatchString(bodyLower) {
                return true
            }
        }
    }
    
    // Check in headers
    isBlocked := false
    resp.Header.VisitAll(func(key, value []byte) {
        headerStr := strings.ToLower(string(key) + ": " + string(value))
        for _, pattern := range wd.blockedPatterns {
            if pattern.MatchString(headerStr) {
                // Mark as blocked if a pattern matches in headers
                isBlocked = true
                return // Exit VisitAll early if a pattern is found
            }
        }
    })
    
    if isBlocked {
        return true
    }
    
    // Return true if status codes indicated blocking (already checked) or if patterns matched
    return status == 403 || status == 429 || status == 503
}

// IdentifyWAF attempts to determine the WAF vendor based on response headers and body content.
func (wd *WAFDetector) IdentifyWAF(resp *fasthttp.Response) string {
    body := string(resp.Body())
    headers := resp.Header.String()
    allContent := strings.ToLower(body + headers)
    
    for wafName, pattern := range wd.wafPatterns {
        if pattern.MatchString(allContent) {
            return wafName
        }
    }
    
    return "unknown"
}

// GetEvasionTechniques returns a list of recommended evasion techniques for a specific WAF vendor.
func (wd *WAFDetector) GetEvasionTechniques(wafName string) []string {
    techniques := map[string][]string{
        "cloudflare": {
            "Randomize User-Agent",
            "Add delay between requests",
            "Use HTTPS only",
            "Rotate IP addresses (if possible)",
            "Mimic browser behavior (e.g., using specific header order)",
        },
        "akamai": {
            "Use different HTTP methods",
            "Add random parameters to requests",
            "Encode payloads differently (e.g., Unicode)",
            "Slow down request rate (Rate limiting)",
        },
        "imperva": {
            "Use TLS fingerprinting evasion",
            "Randomize header order",
            "Add junk headers",
            "Use HTTP/2 if available",
        },
    }
    
    if tech, exists := techniques[wafName]; exists {
        return tech
    }
    
    // Default techniques for unknown WAFs
    return []string{
        "Reduce request rate",
        "Randomize User-Agent",
        "Encode payloads (base64, hex, etc.)",
        "Add random delays",
    }
}