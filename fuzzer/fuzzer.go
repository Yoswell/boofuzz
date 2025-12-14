package fuzzer

import (
    "bufio"
    "context"
    "encoding/base64"
    "fmt"
    "math/rand"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/valyala/fasthttp"
    "boofuzz/assets"
)

/*
This package implements the core Fuzzer logic, orchestrating the entire process.
It handles configuration loading, wordlist processing (including encoding),
request generation (Cartesian product), concurrent worker execution, rate limiting,
authentication management, WAF detection, and result filtering/printing.

It utilizes advanced features like Rate Limiting, Authentication, Encoders,
and WAF Evasion Techniques to perform more robust and stealthy fuzzing.
*/

// WordlistSpec holds the path to a wordlist and its associated substitution keyword (BooID).
type WordlistSpec struct {
    Path  string
    BooID string
}

// WordlistSpecs is a slice of WordlistSpec used for configuration parsing.
type WordlistSpecs []WordlistSpec

// String returns the string representation of WordlistSpecs.
func (w *WordlistSpecs) String() string {
    return fmt.Sprintf("%v", *w)
}

// Set parses a single wordlist definition (path or path:KEYWORD) into the slice.
func (w *WordlistSpecs) Set(value string) error {
    if !strings.Contains(value, ":") {
        *w = append(*w, WordlistSpec{Path: value, BooID: "BOO"})
        return nil
    }
    
    parts := strings.SplitN(value, ":", 2)
    if len(parts) != 2 {
        return fmt.Errorf("[error] :: invalid wordlist format, expected path:KEYWORD")
    }
    
    keyword := strings.ToUpper(strings.TrimSpace(parts[1]))
    
    *w = append(*w, WordlistSpec{
        Path:  parts[0],
        BooID: keyword,
    })
    return nil
}


// Config holds all user-defined configuration for the fuzzer.
type Config struct {
    URL             string
    RequestFile     string
    Wordlists       []WordlistSpec
    Method          string
    Headers         []string
    Data            string
    Cookie          string
    Proxy           string
    FollowRedirects bool
    HTTP2           bool
    Raw             bool
    Recursive       bool
    RecursionDepth  int
    Threads         int
    ShowBody        bool
    ShowHeaders     bool
    Silent          bool
    Verbose         bool
    JSONOutput      bool
    Colorize        bool
    NoErrors        bool
    Extensions      string
    Matchers        MatcherConfig
    Filters         FilterConfig
    RateLimiter     RateLimiterConfig  // New: Rate limiting configuration
    Auth            AuthConfig         // New: Authentication configuration
    Encoders        EncoderConfig      // New: Encoder chain configuration
    Advanced        AdvancedConfig     // New: Advanced options like WAF evasion
}

// MatcherConfig defines criteria for showing results.
type MatcherConfig struct {
    StatusCodes string
    Lines       string
    Words       string
    Size        string
    Regex       string
    Extensions  string
}

// FilterConfig defines criteria for hiding results.
type FilterConfig struct {
    StatusCodes string
    Lines       string
    Words       string
    Size        string
    Regex       string
    Extensions  string
}

// RateLimiterConfig holds rate limiting configuration
type RateLimiterConfig struct {
    RequestsPerSecond int
    Burst             int
    Adaptive          bool
    Jitter            bool
    MaxRetries        int
    BackoffStrategy   string
}

// EncoderConfig holds encoder configuration
type EncoderConfig struct {
    Chains []string
}

// AdvancedConfig holds advanced fuzzing options
type AdvancedConfig struct {
    DetectWAF      bool
    EvasionLevel   int
    RandomizeUA    bool
}

// Result holds the results of a fuzzing request
type Result struct {
    URL      string
    Payload  string
    Status   int
    Size     int
    Lines    int
    Words    int
    Duration time.Duration
    Body     string
    Headers  string
    Error    string
}

// Fuzzer is the main structure containing the fuzzer's state and components.
type Fuzzer struct {
    config           Config
    client           *fasthttp.Client
    wordlists        map[string][]string // Map of keyword (BooID) to list of words
    results          chan Result
    wg               sync.WaitGroup
    startTime        time.Time
    counter          int
    counterLock      sync.Mutex
    printer          ResultPrinter
    filter           *Filter
    lastWord         string
    progressTicker   *time.Ticker
    progressStop     chan bool
    printerDone      chan bool
    ctx              context.Context
    cancel           context.CancelFunc
    totalCombinations int
    rateLimiter      *RateLimiter      // New: Rate limiter instance
    authManager      *AuthManager      // New: Authentication manager instance
    encoder          *Encoder          // New: Encoder instance for payload manipulation
    wafDetector      *WAFDetector      // New: WAF detection instance
    requestQueue     chan *fasthttp.Request // New: For rate limiting/worker coordination
}

// ResultPrinter defines the interface for displaying fuzzer output.
type ResultPrinter interface {
    Print(result Result)
    ShowProgress(currentWord string, completed, total int, elapsedSeconds float64, rate float64)
    HideProgress()
    Finish()
}

// NewFuzzer initializes the Fuzzer with the given configuration and printer.
func NewFuzzer(config Config, printer ResultPrinter) *Fuzzer {
    client := &fasthttp.Client{
        Name:                "boofuzz",
        MaxConnsPerHost:     1000,
        ReadTimeout:         10 * time.Second,
        WriteTimeout:        10 * time.Second,
        MaxIdleConnDuration: 10 * time.Second,
    }
    
    // Initialize filter based on matchers and filters
    filter := NewFilter(config.Matchers, config.Filters)
    
    // Set default matchers if none are configured
    if config.Matchers.StatusCodes == "" {
        config.Matchers.StatusCodes = "200-299,301,302,307,401,403,405,500"
        filter = NewFilter(config.Matchers, config.Filters) // Re-initialize filter with default matchers
    }
    
    f := &Fuzzer{
        config:       config,
        client:       client,
        results:      make(chan Result, 1000),
        printer:      printer,
        filter:       filter,
        progressStop: make(chan bool, 1),
        printerDone:  make(chan bool, 1),
        requestQueue: make(chan *fasthttp.Request, 10000),
    }
    
    // Initialize advanced components
    if config.RateLimiter.RequestsPerSecond > 0 {
        f.rateLimiter = NewRateLimiter(config.RateLimiter)
    }
    
    if config.Auth.Type != "" {
        f.authManager = NewAuthManager(config.Auth)
    }
    
    if len(config.Encoders.Chains) > 0 {
        f.encoder = NewEncoder(config.Encoders)
    }
    
    if config.Advanced.DetectWAF {
        f.wafDetector = NewWAFDetector()
    }
    
    return f
}

// loadWordlists reads all wordlists specified in the configuration.
func (f *Fuzzer) loadWordlists() error {
    f.wordlists = make(map[string][]string)
    for _, spec := range f.config.Wordlists {
        file, err := os.Open(spec.Path)
        if err != nil {
            return fmt.Errorf("[error] :: error opening wordlist %s: %v", spec.Path, err)
        }
        defer file.Close()

        var words []string
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            word := strings.TrimSpace(scanner.Text())
            if word != "" {
                // Apply encoders if configured
                if f.encoder != nil {
                    encodedWord, err := f.encoder.EncodeChain(word)
                    if err == nil && encodedWord != "" {
                        words = append(words, encodedWord)
                    }
                } else {
                    words = append(words, word)
                }
            }
        }

        if err := scanner.Err(); err != nil {
            return fmt.Errorf("[error] :: error reading wordlist %s: %v", spec.Path, err)
        }

        // Append extensions if specified
        if f.config.Extensions != "" {
            extList := parseExtensions(f.config.Extensions)
            if len(extList) > 0 {
                var extendedWords []string
                for _, word := range words {
                    for _, ext := range extList {
                        extendedWords = append(extendedWords, word+ext)
                    }
                }
                words = extendedWords
            }
        }

        f.wordlists[spec.BooID] = words
    }
    return nil
}

// generatePayloads generates the Cartesian product of all wordlists and sends payloads to the job channel.
func (f *Fuzzer) generatePayloads(jobs chan<- map[string]string) {
    if len(f.wordlists) == 0 {
        return
    }

    // Get all BOO IDs (keywords)
    var booIDs []string
    for booID := range f.wordlists {
        booIDs = append(booIDs, booID)
    }

    // Generate cartesian product
    indices := make([]int, len(booIDs))
    for {
        payload := make(map[string]string)
        for i, booID := range booIDs {
            payload[booID] = f.wordlists[booID][indices[i]]
        }

        select {
        case <-f.ctx.Done():
            return
        case jobs <- payload:
        }

        // Increment indices
        done := true
        for i := len(indices) - 1; i >= 0; i-- {
            indices[i]++
            if indices[i] < len(f.wordlists[booIDs[i]]) {
                done = false
                break
            }
            indices[i] = 0
        }
        if done {
            break
        }
    }
}

// Run executes the fuzzer process, setting up workers and coordinating tasks.
func (f *Fuzzer) Run(ctx context.Context) error {
    f.ctx, f.cancel = context.WithCancel(ctx)
    defer f.cancel()
    
    // Check if keywords are present in the request
    if len(f.config.Wordlists) > 1 {
        keywords := make([]string, 0, len(f.config.Wordlists))
        for _, spec := range f.config.Wordlists {
            keywords = append(keywords, spec.BooID)
        }
        
        hasAllKeywords := f.checkKeywordsInRequest(keywords)
        
        if !hasAllKeywords {
            fmt.Fprintf(os.Stderr, "[warning] :: Keywords %v defined in wordlists, but not all found in request.\n", keywords)
            fmt.Fprintln(os.Stderr, "[warning] :: Make sure to use the same keywords in URL, headers or POST data.")
        }
    }
    
    // Authenticate if necessary
    if f.authManager != nil {
        fmt.Println("[info] :: Authenticating...")
        if err := f.authManager.Authenticate(); err != nil {
            fmt.Printf("[error] :: Authentication failed: %v\n", err)
            return err
        }
        // Add session cookies to the configuration
        for _, cookie := range f.authManager.GetSessionCookies() {
            if f.config.Cookie != "" {
                f.config.Cookie += "; " + cookie
            } else {
                f.config.Cookie = cookie
            }
        }
    }
    
    // Detect WAF if enabled
    if f.wafDetector != nil {
        fmt.Println("[info] :: Detecting WAF...")
        wafDetected := f.wafDetector.Detect(f.config.URL)
        if wafDetected {
            fmt.Println("[warning] :: WAF detected. Enabling evasion techniques.")
            f.config.Advanced.EvasionLevel = 3 // Medium evasion level
        }
    }
    
    if err := f.loadWordlists(); err != nil {
        return err
    }

    assets.PrintBanner()

    // Display configuration information
    const labelWidth = 21

    infoLabels := []struct {
        label string
        value interface{}
    }{
        {"Method", f.config.Method},
        {"URL", f.config.URL},
        {"Follow redirects", f.config.FollowRedirects},
        {"Threads", f.config.Threads},
        {"Rate limit", fmt.Sprintf("%d req/sec", f.config.RateLimiter.RequestsPerSecond)},
    }
    
    // Only show auth type if it's configured
    if f.config.Auth.Type != "" {
        infoLabels = append(infoLabels, struct {
            label string
            value interface{}
        }{"Auth type", f.config.Auth.Type})
    }
    
    for _, item := range infoLabels {
        displayLabel := item.label
        if len(displayLabel) > labelWidth {
            displayLabel = displayLabel[:labelWidth-3] + "..."
        }
        labelColumn := fmt.Sprintf("%-*s", labelWidth, displayLabel)
        fmt.Printf("[info] :: %s: %v\n", labelColumn, item.value)
    }
    

    // Print wordlists
    for _, spec := range f.config.Wordlists {
        labelColumn := fmt.Sprintf("%-*s", labelWidth, "Wordlist")
        fmt.Printf("[info] :: %s: %s [Keyword: FUZZ] (%d words)\n", 
            labelColumn, spec.Path, len(f.wordlists[spec.BooID]))
    }
    
    // Print extensions if configured
    if f.config.Extensions != "" {
        labelColumn := fmt.Sprintf("%-*s", labelWidth, "Extensions")
        fmt.Printf("[info] :: %s: %s\n", labelColumn, f.config.Extensions)
    }
    
    // Display encoders if configured
    if f.encoder != nil {
        labelColumn := fmt.Sprintf("%-*s", labelWidth, "Encoders")
        fmt.Printf("[info] :: %s: %v\n", labelColumn, f.config.Encoders.Chains)
    }

    fmt.Println(f.getMatcherDescription())
    fmt.Println()

    f.startTime = time.Now()

    // Calculate total combinations
    f.totalCombinations = 1
    for _, words := range f.wordlists {
        f.totalCombinations *= len(words)
    }

    // Start rate limiter if configured
    if f.rateLimiter != nil {
        go f.rateLimiter.Run()
    }

    // Start progress update ticker
    f.progressTicker = time.NewTicker(200 * time.Millisecond)
    go f.updateProgress()
    
    jobs := make(chan map[string]string, f.config.Threads*2)

    go f.printResults()

    // Start workers with rate limiting
    for i := 0; i < f.config.Threads; i++ {
        f.wg.Add(1)
        go f.worker(i, jobs)
    }

    // Start payload generator
    go func() {
        defer close(jobs)
        f.generatePayloads(jobs)
    }()
    
    f.wg.Wait()
    close(f.results)
    
    // Wait for the printer to finish processing remaining results
    <-f.printerDone
    
    // Stop progress and rate limiting
    f.progressStop <- true
    f.progressTicker.Stop()
    
    if f.rateLimiter != nil {
        f.rateLimiter.Stop()
    }
    
    f.printer.Finish()
    
    return nil
}

// checkKeywordsInRequest verifies if the wordlist keywords are used in the request structure.
func (f *Fuzzer) checkKeywordsInRequest(keywords []string) bool {
    urlContainsKeyword := false
    for _, keyword := range keywords {
        if strings.Contains(f.config.URL, keyword) {
            urlContainsKeyword = true
            break
        }
    }
    
    dataContainsKeyword := false
    for _, keyword := range keywords {
        if strings.Contains(f.config.Data, keyword) {
            dataContainsKeyword = true
            break
        }
    }
    
    headersContainKeyword := false
    for _, header := range f.config.Headers {
        for _, keyword := range keywords {
            if strings.Contains(header, keyword) {
                headersContainKeyword = true
                break
            }
        }
        if headersContainKeyword {
            break
        }
    }
    
    return urlContainsKeyword || dataContainsKeyword || headersContainKeyword
}

// updateProgress periodically displays the fuzzer's progress.
func (f *Fuzzer) updateProgress() {
    for {
        select {
        case <-f.progressTicker.C:
            f.counterLock.Lock()
            current := f.counter
            currentWord := f.lastWord
            f.counterLock.Unlock()
            
            if currentWord != "" && !f.config.Silent {
                elapsed := time.Since(f.startTime).Seconds()
                rate := float64(current) / elapsed
                
                f.printer.ShowProgress(currentWord, current, f.totalCombinations, elapsed, rate)
            }
        case <-f.progressStop:
            return
        case <-f.ctx.Done():
            return
        }
    }
}

// getMatcherDescription generates a formatted string detailing configured matchers and filters.
func (f *Fuzzer) getMatcherDescription() string {
    const labelWidth = 21
    const prefix = "[info] :: "
    
    var result strings.Builder
    firstLine := true
    
    // Matchers (Show)
    if f.config.Matchers.StatusCodes != "" {
        label := "Show"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        if firstLine {
            result.WriteString(fmt.Sprintf("%s%s: Response status: %s", prefix, labelColumn, f.config.Matchers.StatusCodes))
            firstLine = false
        } else {
            result.WriteString(fmt.Sprintf("\n%s%s: Response status: %s", prefix, labelColumn, f.config.Matchers.StatusCodes))
        }
    } else {
        label := "Show"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        if firstLine {
            result.WriteString(fmt.Sprintf("%s%s: Response status: all", prefix, labelColumn))
            firstLine = false
        } else {
            result.WriteString(fmt.Sprintf("\n%s%s: Response status: all", prefix, labelColumn))
        }
    }
    
    if f.config.Matchers.Lines != "" {
        label := "Show"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        result.WriteString(fmt.Sprintf("\n%s%s: Lines: %s", prefix, labelColumn, f.config.Matchers.Lines))
    }
    
    if f.config.Matchers.Words != "" {
        label := "Show"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        result.WriteString(fmt.Sprintf("\n%s%s: Words: %s", prefix, labelColumn, f.config.Matchers.Words))
    }
    
    if f.config.Matchers.Size != "" {
        label := "Show"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        result.WriteString(fmt.Sprintf("\n%s%s: Size: %s", prefix, labelColumn, f.config.Matchers.Size))
    }
    
    if f.config.Matchers.Regex != "" {
        label := "Show"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        result.WriteString(fmt.Sprintf("\n%s%s: Regex: %s", prefix, labelColumn, f.config.Matchers.Regex))
    }
    
    // Filters (Hide)
    if f.config.Filters.StatusCodes != "" {
        label := "Hide"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        if result.Len() == 0 {
            result.WriteString(fmt.Sprintf("%s%s: Status codes: %s", prefix, labelColumn, f.config.Filters.StatusCodes))
        } else {
            result.WriteString(fmt.Sprintf("\n%s%s: Status codes: %s", prefix, labelColumn, f.config.Filters.StatusCodes))
        }
    }
    
    if f.config.Filters.Lines != "" {
        label := "Hide"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        result.WriteString(fmt.Sprintf("\n%s%s: Lines: %s", prefix, labelColumn, f.config.Filters.Lines))
    }
    
    if f.config.Filters.Words != "" {
        label := "Hide"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        result.WriteString(fmt.Sprintf("\n%s%s: Words: %s", prefix, labelColumn, f.config.Filters.Words))
    }
    
    if f.config.Filters.Size != "" {
        label := "Hide"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        result.WriteString(fmt.Sprintf("\n%s%s: Filter size: %s", prefix, labelColumn, f.config.Filters.Size))
    }
    
    if f.config.Filters.Regex != "" {
        label := "Hide"
        labelColumn := fmt.Sprintf("%-*s", labelWidth, label)
        result.WriteString(fmt.Sprintf("\n%s%s: Filter regex: %s", prefix, labelColumn, f.config.Filters.Regex))
    }
    
    return result.String()
}

// worker fetches payloads from the job channel and executes requests.
func (f *Fuzzer) worker(id int, jobs <-chan map[string]string) {
    defer f.wg.Done()

    for {
        select {
        case <-f.ctx.Done():
            return
        case payload, ok := <-jobs:
            if !ok {
                return
            }
            
            // Apply rate limiting if configured
            if f.rateLimiter != nil {
                f.rateLimiter.Wait()
            }
            
            f.makeRequest(payload)

            f.counterLock.Lock()
            f.counter++
            // Store the payload for progress display
            f.lastWord = formatPayload(payload) 
            f.counterLock.Unlock()
        }
    }
}

// makeRequest builds and sends an HTTP request using fasthttp.
func (f *Fuzzer) makeRequest(payload map[string]string) {
    select {
    case <-f.ctx.Done():
        return
    default:
    }
    
    req := fasthttp.AcquireRequest()
    resp := fasthttp.AcquireResponse()
    defer fasthttp.ReleaseRequest(req)
    defer fasthttp.ReleaseResponse(resp)
    
    // Apply evasion techniques if enabled
    if f.config.Advanced.EvasionLevel > 0 {
        f.applyEvasionTechniques(req)
    }
    
    var targetURL string
    targetURL = f.config.URL
    for booID, word := range payload {
        if f.config.Raw {
            // Raw replacement (no encoding)
            targetURL = strings.ReplaceAll(targetURL, booID, word)
        } else {
            // Apply encoding based on configuration and evasion level
            encodedWord := word
            if f.config.Advanced.EvasionLevel >= 2 {
                encodedWord = applyURLEncoding(encodedWord, f.config.Advanced.EvasionLevel)
            }
            // URL encode the entire word *after* evasion encoding, if not raw
            targetURL = strings.ReplaceAll(targetURL, booID, url.QueryEscape(encodedWord))
        }
    }
    
    req.SetRequestURI(targetURL)
    req.Header.SetMethod(f.config.Method)
    
    // Apply headers with encoding if necessary
    for _, header := range f.config.Headers {
        parts := strings.SplitN(header, ":", 2)
        if len(parts) == 2 {
            key := strings.TrimSpace(parts[0])
            value := strings.TrimSpace(parts[1])
            for booID, word := range payload {
                if strings.Contains(value, booID) {
                    encodedWord := word
                    if f.config.Advanced.EvasionLevel >= 2 {
                        encodedWord = applyHeaderEncoding(encodedWord)
                    }
                    value = strings.ReplaceAll(value, booID, encodedWord)
                }
            }
            req.Header.Set(key, value)
        }
    }
    
    if f.config.Cookie != "" {
        req.Header.Set("Cookie", f.config.Cookie)
    }
    
    // Process POST data
    if f.config.Data != "" {
        data := f.config.Data
        for booID, word := range payload {
            encodedWord := word
            if f.config.Advanced.EvasionLevel >= 2 {
                encodedWord = applyDataEncoding(encodedWord, f.config.Advanced.EvasionLevel)
            }
            data = strings.ReplaceAll(data, booID, encodedWord)
        }
        req.SetBodyString(data)
        if f.config.Method == "POST" {
            // Default content type for POST data if not set explicitly
            req.Header.SetContentType("application/x-www-form-urlencoded")
        }
    }
    
    start := time.Now()
    err := f.client.Do(req, resp)
    duration := time.Since(start)
    
    result := Result{
        URL:      targetURL,
        Payload:  formatPayload(payload),
        Status:   0,
        Duration: duration,
    }
    
    if err != nil {
        result.Error = err.Error()
    } else {
        result.Status = resp.StatusCode()
        result.Size = len(resp.Body())
        result.Body = string(resp.Body())
        result.Headers = resp.Header.String()
        
        bodyStr := string(resp.Body())
        // Count lines and words in the response body
        result.Lines = len(strings.Split(bodyStr, "\n"))
        result.Words = len(strings.Fields(bodyStr))
        
        // Detect rate limiting or blocks
        if f.wafDetector != nil {
            if f.wafDetector.IsBlocked(resp) {
                result.Body += "\n[WARNING: Request blocked by WAF/IPS]"
                // Reduce rate limiting if a block is detected
                if f.rateLimiter != nil {
                    // This is a manual rate adjustment example, adaptive control is better handled in the RateLimiter component itself
                    f.rateLimiter.AdjustRate(-10) // Reduce by 10 req/sec
                }
            }
        }
        
        // Handle redirects
        if f.config.FollowRedirects && (result.Status >= 300 && result.Status < 400) {
            location := resp.Header.Peek("Location")
            if len(location) > 0 {
                result.Body += "\n[Redirect to: " + string(location) + "]"
            }
        }
    }
    
    // Send result to the results channel
    select {
    case <-f.ctx.Done():
        return
    case f.results <- result:
    }
}

// formatPayload converts the payload map into a single string for display.
func formatPayload(payload map[string]string) string {
    var parts []string
    // Note: Iterating maps is non-deterministic, but adequate for simple logging display.
    for _, v := range payload {
        parts = append(parts, v)
    }
    return strings.Join(parts, " | ")
}

// printResults consumes results from the channel, applies filtering, and sends them to the printer.
func (f *Fuzzer) printResults() {
    defer func() {
        f.printerDone <- true
    }()
    
    for {
        select {
        case <-f.ctx.Done():
            return
        case result, ok := <-f.results:
            if !ok {
                return
            }
            
            // Skip non-error results if silent mode is enabled
            if f.config.Silent && result.Error == "" {
                continue
            }
            
            // Apply filtering logic
            if !f.filter.ShouldShow(result) {
                continue
            }
            
            f.printer.Print(result)
        }
    }
}

// --- Evasion Functions ---

// applyEvasionTechniques adds general evasion methods to the request based on the configured level.
func (f *Fuzzer) applyEvasionTechniques(req *fasthttp.Request) {
    // Random User-Agent
    if f.config.Advanced.RandomizeUA {
        req.Header.Set("User-Agent", getRandomUserAgent())
    }
    
    // Add random headers (e.g., XFF)
    if f.config.Advanced.EvasionLevel >= 2 {
        req.Header.Set("X-Forwarded-For", generateRandomIP())
        req.Header.Set("X-Client-IP", generateRandomIP())
    }
    
    // Add random delay
    if f.config.Advanced.EvasionLevel >= 3 {
        // Delay up to 500ms
        time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
    }
    
    // Character encoding (placeholder for advanced encoding logic)
    if f.config.Advanced.EvasionLevel >= 4 {
        // Could involve Unicode or UTF-8 obfuscation logic here
    }
}

// getRandomUserAgent returns a randomly selected User-Agent string.
func getRandomUserAgent() string {
    userAgents := []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36",
        "Mozilla/5.0 (Android 10; Mobile) AppleWebKit/537.36",
    }
    return userAgents[rand.Intn(len(userAgents))]
}

// generateRandomIP creates a random IPv4 address string.
func generateRandomIP() string {
    return fmt.Sprintf("%d.%d.%d.%d", 
        rand.Intn(255), rand.Intn(255), 
        rand.Intn(255), rand.Intn(255))
}

// applyURLEncoding applies payload encoding specific to the URL path/query based on evasion level.
func applyURLEncoding(input string, level int) string {
    if level == 1 {
        return url.QueryEscape(input)
    }
    
    // Double encoding
    if level >= 2 {
        encoded := url.QueryEscape(input)
        return url.QueryEscape(encoded)
    }
    
    // Special encoding for WAF evasion (e.g., partial hex encoding)
    if level >= 3 {
        var result strings.Builder
        for _, r := range input {
            if rand.Intn(100) < 30 { // 30% of characters are hex encoded
                result.WriteString(fmt.Sprintf("%%%02X", r))
            } else {
                result.WriteRune(r)
            }
        }
        return result.String()
    }
    
    return input
}

// applyHeaderEncoding applies encoding specific to header values.
func applyHeaderEncoding(input string) string {
    // For headers, sometimes use base64
    if rand.Intn(100) < 20 {
        return base64.StdEncoding.EncodeToString([]byte(input))
    }
    return input
}

// applyDataEncoding applies encoding specific to POST body data.
func applyDataEncoding(input string, level int) string {
    if level == 1 {
        return input
    }
    
    if level >= 2 {
        // Add null bytes
        if rand.Intn(100) < 10 {
            return input + string([]byte{0})
        }
        
        // Add Unicode characters
        if rand.Intn(100) < 10 {
            return input + "\u200b" // Zero-width space
        }
    }
    
    return input
}