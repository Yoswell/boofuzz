package fuzzer

import (
    "crypto/tls"
    "encoding/base64"
    "fmt"
    "net/http/cookiejar"
    "net/url"
    "regexp"
    "strings"
    "time"
    
    "github.com/valyala/fasthttp"
    "golang.org/x/net/publicsuffix"
)

/*
Authentication Manager for the fuzzer.
Handles various authentication mechanisms including Basic Auth, Bearer tokens,
form-based login, and OAuth2. Manages session cookies, CSRF tokens, and
maintains authenticated state throughout the fuzzing session.
*/

// AuthConfig holds authentication configuration
type AuthConfig struct {
    Type            string   // "basic", "bearer", "form", "oauth2"
    Username        string
    Password        string
    LoginURL        string
    LoginPattern    string
    SessionCookies  []string
    Headers         []string
}

// AuthManager handles authentication workflows and session management
type AuthManager struct {
    config     AuthConfig    
    client     *fasthttp.Client
    jar        *cookiejar.Jar
    sessionID  string
    csrfToken  string
    isLoggedIn bool
}

// NewAuthManager creates a new authentication manager with the given configuration
func NewAuthManager(config AuthConfig) *AuthManager {
    jar, _ := cookiejar.New(&cookiejar.Options{
        PublicSuffixList: publicsuffix.List,
    })
    
    client := &fasthttp.Client{
        Name:                "boofuzz-auth",
        MaxConnsPerHost:     10,
        ReadTimeout:         30 * time.Second,
        WriteTimeout:        30 * time.Second,
        MaxIdleConnDuration: 30 * time.Second,
        TLSConfig: &tls.Config{
            InsecureSkipVerify: true, // Allow self-signed certificates for testing
        },
    }
    
    return &AuthManager{
        config: config,
        client: client,
        jar:    jar,
    }
}

// Authenticate performs authentication based on the configured type
func (am *AuthManager) Authenticate() error {
    switch strings.ToLower(am.config.Type) {
    case "basic":
        return am.authenticateBasic()
    case "bearer":
        return am.authenticateBearer()
    case "form":
        return am.authenticateForm()
    case "oauth2":
        return am.authenticateOAuth2()
    case "ntlm", "digest":
        return fmt.Errorf("authentication type %s not yet implemented", am.config.Type)
    default:
        return fmt.Errorf("unknown authentication type: %s", am.config.Type)
    }
}

// authenticateBasic handles HTTP Basic Authentication
func (am *AuthManager) authenticateBasic() error {
    credentials := am.config.Username + ":" + am.config.Password
    encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
    am.config.Headers = append(am.config.Headers, "Authorization: Basic "+encoded)
    am.isLoggedIn = true
    return nil
}

// authenticateBearer handles Bearer token authentication
func (am *AuthManager) authenticateBearer() error {
    am.config.Headers = append(am.config.Headers, "Authorization: Bearer "+am.config.Password)
    am.isLoggedIn = true
    return nil
}

// authenticateForm handles form-based authentication with CSRF protection
func (am *AuthManager) authenticateForm() error {
    if am.config.LoginURL == "" {
        return fmt.Errorf("login URL required for form authentication")
    }
    
    // Extract CSRF token from login page
    csrfToken, err := am.extractCSRFToken(am.config.LoginURL)
    
    if err != nil {
        fmt.Printf("[warning] :: Could not extract CSRF token: %v\n", err)
    }

    am.csrfToken = csrfToken
    
    // Prepare form data for login request
    formData := url.Values{}
    formData.Set("username", am.config.Username)
    formData.Set("password", am.config.Password)
    
    // Include CSRF token if available
    if csrfToken != "" {
        csrfField := am.detectCSRFFieldName(am.config.LoginURL)
        if csrfField != "" {
            formData.Set(csrfField, csrfToken)
        }
    }
    
    // Execute login request
    req := fasthttp.AcquireRequest()
    resp := fasthttp.AcquireResponse()
    defer fasthttp.ReleaseRequest(req)
    defer fasthttp.ReleaseResponse(resp)
    
    req.SetRequestURI(am.config.LoginURL)
    req.Header.SetMethod("POST")
    req.Header.SetContentType("application/x-www-form-urlencoded")
    req.SetBodyString(formData.Encode())
    
    // Include existing cookies
    u, _ := url.Parse(am.config.LoginURL)
    cookies := am.jar.Cookies(u)
    for _, cookie := range cookies {
        req.Header.Set("Cookie", cookie.Name+"="+cookie.Value)
    }
    
    err = am.client.Do(req, resp)
    if err != nil {
        return fmt.Errorf("login request failed: %v", err)
    }
    
    // Validate login success
    if am.isLoginSuccessful(resp) {
        am.isLoggedIn = true
        
        // Extract and store session cookies
        var cookieHeader strings.Builder
        resp.Header.VisitAllCookie(func(key, value []byte) {
            cookieHeader.WriteString(string(key))
            cookieHeader.WriteString("=")
            cookieHeader.WriteString(string(value))
            cookieHeader.WriteString("; ")
        })
        
        if cookieHeader.Len() > 0 {
            am.sessionID = strings.TrimSuffix(cookieHeader.String(), "; ")
        }
        
        fmt.Println("[info] :: Form authentication successful")
        return nil
    }
    
    return fmt.Errorf("form authentication failed (status: %d)", resp.StatusCode())
}

// authenticateOAuth2 handles OAuth2 token-based authentication
func (am *AuthManager) authenticateOAuth2() error {
    am.config.Headers = append(am.config.Headers, "Authorization: Bearer "+am.config.Password)
    am.isLoggedIn = true
    return nil
}

// extractCSRFToken retrieves CSRF token from login page HTML
func (am *AuthManager) extractCSRFToken(loginURL string) (string, error) {
    req := fasthttp.AcquireRequest()
    resp := fasthttp.AcquireResponse()
    defer fasthttp.ReleaseRequest(req)
    defer fasthttp.ReleaseResponse(resp)
    
    req.SetRequestURI(loginURL)
    req.Header.SetMethod("GET")
    
    err := am.client.Do(req, resp)
    if err != nil {
        return "", err
    }
    
    body := string(resp.Body())
    
    // Common CSRF token patterns in HTML
    patterns := []string{
        `name="csrf_token" value="([^"]+)"`,
        `name="csrf" value="([^"]+)"`,
        `name="_token" value="([^"]+)"`,
        `name="authenticity_token" value="([^"]+)"`,
        `csrf-token" content="([^"]+)"`,
        `"csrfToken":"([^"]+)"`,
    }
    
    for _, pattern := range patterns {
        re := regexp.MustCompile(pattern)
        matches := re.FindStringSubmatch(body)
        if len(matches) > 1 {
            return matches[1], nil
        }
    }
    
    return "", nil
}

// detectCSRFFieldName identifies the form field name for CSRF tokens
func (am *AuthManager) detectCSRFFieldName(loginURL string) string {
    req := fasthttp.AcquireRequest()
    resp := fasthttp.AcquireResponse()
    defer fasthttp.ReleaseRequest(req)
    defer fasthttp.ReleaseResponse(resp)
    
    req.SetRequestURI(loginURL)
    req.Header.SetMethod("GET")
    
    err := am.client.Do(req, resp)
    if err != nil {
        return ""
    }
    
    body := string(resp.Body())
    
    // Patterns for CSRF field names
    csrfPatterns := []*regexp.Regexp{
        regexp.MustCompile(`name="(csrf[^"]*)"`),
        regexp.MustCompile(`name="(_token[^"]*)"`),
        regexp.MustCompile(`name="(authenticity_token[^"]*)"`),
        regexp.MustCompile(`name="([^"]*token[^"]*)"`),
    }
    
    for _, pattern := range csrfPatterns {
        matches := pattern.FindStringSubmatch(body)
        if len(matches) > 1 {
            return matches[1]
        }
    }
    
    return ""
}

// isLoginSuccessful determines if authentication was successful based on response
func (am *AuthManager) isLoginSuccessful(resp *fasthttp.Response) bool {
    // Check HTTP status code
    if resp.StatusCode() >= 200 && resp.StatusCode() < 300 {
        body := string(resp.Body())
        
        // Common indicators of successful login
        successPatterns := []string{
            "logout",
            "Logout",
            "LOGOUT",
            "welcome",
            "Welcome",
            "WELCOME",
            "dashboard",
            "Dashboard",
            "DASHBOARD",
        }
        
        // Use custom pattern if configured
        if am.config.LoginPattern != "" {
            re := regexp.MustCompile(am.config.LoginPattern)
            return re.MatchString(body)
        }
        
        // Check for common success indicators
        for _, pattern := range successPatterns {
            if strings.Contains(body, pattern) {
                return true
            }
        }
        
        // Check for redirect to non-login page
        location := resp.Header.Peek("Location")
        if len(location) > 0 && !strings.Contains(string(location), "login") &&
           !strings.Contains(string(location), "error") {
            return true
        }
    }
    
    return false
}

// GetSessionCookies returns all active session cookies
func (am *AuthManager) GetSessionCookies() []string {
    var cookies []string
    
    if am.sessionID != "" {
        cookies = append(cookies, am.sessionID)
    }
    
    // Include configured session cookies
    cookies = append(cookies, am.config.SessionCookies...)
    
    return cookies
}

// GetAuthHeaders returns authentication headers to be added to requests
func (am *AuthManager) GetAuthHeaders() []string {
    return am.config.Headers
}

// IsAuthenticated returns the current authentication status
func (am *AuthManager) IsAuthenticated() bool {
    return am.isLoggedIn
}

// GetCSRFToken returns the current CSRF token
func (am *AuthManager) GetCSRFToken() string {
    return am.csrfToken
}