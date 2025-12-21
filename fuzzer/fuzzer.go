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
    "unicode"

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

type WordlistSpec struct {
    Path  string
    BooID string
}

type WordlistSpecs []WordlistSpec

func (w *WordlistSpecs) String() string {
    return fmt.Sprintf("%v", *w)
}

func (w *WordlistSpecs) Set(value string) error {
    if !strings.Contains(value, ":") {
        *w = append(*w, WordlistSpec{Path: value, BooID: "FUZZ"})
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
    RateLimiter     RateLimiterConfig
    Auth            AuthConfig
    Encoders        EncoderConfig
    Advanced        AdvancedConfig
    
    ExcludeComments   bool
    ExcludeDots       bool
    ExcludeNumbers    bool
    ExcludeAllUpper   bool
    ExcludeAllLower   bool
    ExcludeFirstUpper bool
    ExcludeFirstLower bool
}

type MatcherConfig struct {
    StatusCodes string
    Lines       string
    Words       string
    Size        string
    Regex       string
    Extensions  string
}

type FilterConfig struct {
    StatusCodes string
    Lines       string
    Words       string
    Size        string
    Regex       string
    Extensions  string
}

type EncoderConfig struct {
    Chains []string
}

type AdvancedConfig struct {
    DetectWAF      bool
    EvasionLevel   int
    RandomizeUA    bool
}

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

type Fuzzer struct {
    config           Config
    client           *fasthttp.Client
    wordlists        map[string][]string
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
    rateLimiter      *RateLimiter
    authManager      *AuthManager
    encoder          *Encoder
    wafDetector      *WAFDetector
    requestQueue     chan *fasthttp.Request
}

type ResultPrinter interface {
    Print(result Result)
    ShowProgress(currentWord string, completed, total int, elapsedSeconds float64, rate float64)
    HideProgress()
    Finish()
    PrintConfigInfo(config Config, wordlists map[string][]string)  // Nueva interfaz
}

func NewFuzzer(config Config, printer ResultPrinter) *Fuzzer {
    client := &fasthttp.Client{
        Name:                "boofuzz",
        MaxConnsPerHost:     1000,
        ReadTimeout:         10 * time.Second,
        WriteTimeout:        10 * time.Second,
        MaxIdleConnDuration: 10 * time.Second,
    }
    
    filter := NewFilter(config.Matchers, config.Filters)
    
    if config.Matchers.StatusCodes == "" {
        config.Matchers.StatusCodes = "200-299,301,302,307,401,403,405,500"
        filter = NewFilter(config.Matchers, config.Filters)
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
            if word == "" {
                continue
            }
            
            if f.config.ExcludeComments && (strings.HasPrefix(word, "#") || 
               strings.HasPrefix(word, "~") || strings.HasPrefix(word, "/")) {
                continue
            }
            
            if f.config.ExcludeDots && strings.HasPrefix(word, ".") {
                continue
            }
            
            if f.config.ExcludeNumbers && len(word) > 0 && 
               word[0] >= '0' && word[0] <= '9' {
                continue
            }
            
            if f.config.ExcludeAllUpper && isAllUppercase(word) {
                continue
            }
            
            if f.config.ExcludeAllLower && isAllLowercase(word) {
                continue
            }
            
            if f.config.ExcludeFirstUpper && len(word) > 0 && unicode.IsUpper(rune(word[0])) {
                continue
            }
            
            if f.config.ExcludeFirstLower && len(word) > 0 && unicode.IsLower(rune(word[0])) {
                continue
            }
            
            if f.encoder != nil {
                encodedWord, err := f.encoder.EncodeChain(word)
                if err == nil && encodedWord != "" {
                    words = append(words, encodedWord)
                }
            } else {
                words = append(words, word)
            }
        }

        if err := scanner.Err(); err != nil {
            return fmt.Errorf("[error] :: error reading wordlist %s: %v", spec.Path, err)
        }

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

func isAllUppercase(s string) bool {
    for _, r := range s {
        if unicode.IsLetter(r) && !unicode.IsUpper(r) {
            return false
        }
    }
    return true
}

func isAllLowercase(s string) bool {
    for _, r := range s {
        if unicode.IsLetter(r) && !unicode.IsLower(r) {
            return false
        }
    }
    return true
}

func (f *Fuzzer) generatePayloads(jobs chan<- map[string]string) {
    if len(f.wordlists) == 0 {
        return
    }

    var booIDs []string
    for booID := range f.wordlists {
        booIDs = append(booIDs, booID)
    }

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

func (f *Fuzzer) Run(ctx context.Context) error {
    f.ctx, f.cancel = context.WithCancel(ctx)
    defer f.cancel()
    
    if len(f.config.Wordlists) > 0 {
        keywords := make([]string, 0, len(f.config.Wordlists))
        for _, spec := range f.config.Wordlists {
            keywords = append(keywords, spec.BooID)
        }
        
        if !f.checkKeywordsInRequest(keywords) {
            return fmt.Errorf("keywords not found in request")
        }
    }
    
    if f.authManager != nil {
        fmt.Println("[info] :: Authenticating...")
        if err := f.authManager.Authenticate(); err != nil {
            fmt.Printf("[error] :: Authentication failed: %v\n", err)
            return err
        }
        for _, cookie := range f.authManager.GetSessionCookies() {
            if f.config.Cookie != "" {
                f.config.Cookie += "; " + cookie
            } else {
                f.config.Cookie = cookie
            }
        }
    }
    
    if f.wafDetector != nil {
        fmt.Println("[info] :: Detecting WAF...")
        wafDetected := f.wafDetector.Detect(f.config.URL)
        if wafDetected {
            fmt.Println("[warning] :: WAF detected. Enabling evasion techniques.")
            f.config.Advanced.EvasionLevel = 3
        }
    }
    
    if err := f.loadWordlists(); err != nil {
        return err
    }

    assets.PrintBanner()

    // Imprimir información básica de configuración usando el printer
    f.printer.PrintConfigInfo(f.config, f.wordlists)

    f.startTime = time.Now()

    f.totalCombinations = 1
    for _, words := range f.wordlists {
        f.totalCombinations *= len(words)
    }

    if f.rateLimiter != nil {
        go f.rateLimiter.Run()
    }

    f.progressTicker = time.NewTicker(200 * time.Millisecond)
    go f.updateProgress()
    
    jobs := make(chan map[string]string, f.config.Threads*2)

    go f.printResults()

    for i := 0; i < f.config.Threads; i++ {
        f.wg.Add(1)
        go f.worker(i, jobs)
    }

    go func() {
        defer close(jobs)
        f.generatePayloads(jobs)
    }()
    
    f.wg.Wait()
    close(f.results)
    
    <-f.printerDone
    
    f.progressStop <- true
    f.progressTicker.Stop()
    
    if f.rateLimiter != nil {
        f.rateLimiter.Stop()
    }
    
    f.printer.Finish()
    
    return nil
}

func (f *Fuzzer) containsKeywordInHeaders(keyword string) bool {
    for _, header := range f.config.Headers {
        if strings.Contains(header, keyword) {
            return true
        }
    }
    return false
}

func (f *Fuzzer) checkKeywordsInRequest(keywords []string) bool {
    urlContainsKeyword := false
    dataContainsKeyword := false
    headersContainKeyword := false
    
    for _, keyword := range keywords {
        if strings.Contains(f.config.URL, keyword) {
            urlContainsKeyword = true
            break
        }
    }
    
    for _, keyword := range keywords {
        if strings.Contains(f.config.Data, keyword) {
            dataContainsKeyword = true
            break
        }
    }
    
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
    
    foundInRequest := urlContainsKeyword || dataContainsKeyword || headersContainKeyword
    
    if !foundInRequest {
        assets.PrintKeywordError(keywords, f.config.Colorize)
        return false
    }
    
    return true
}

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
            
            if f.rateLimiter != nil {
                f.rateLimiter.Wait()
            }
            
            f.makeRequest(payload)

            f.counterLock.Lock()
            f.counter++
            f.lastWord = formatPayload(payload) 
            f.counterLock.Unlock()
        }
    }
}

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
    
    if f.config.Advanced.EvasionLevel > 0 {
        f.applyEvasionTechniques(req)
    }
    
    var targetURL string
    targetURL = f.config.URL
    for booID, word := range payload {
        if f.config.Raw {
            targetURL = strings.ReplaceAll(targetURL, booID, word)
        } else {
            encodedWord := word
            if f.config.Advanced.EvasionLevel >= 2 {
                encodedWord = applyURLEncoding(encodedWord, f.config.Advanced.EvasionLevel)
            }
            targetURL = strings.ReplaceAll(targetURL, booID, url.QueryEscape(encodedWord))
        }
    }
    
    req.SetRequestURI(targetURL)
    req.Header.SetMethod(f.config.Method)
    
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
        result.Lines = len(strings.Split(bodyStr, "\n"))
        result.Words = len(strings.Fields(bodyStr))
        
        if f.wafDetector != nil {
            if f.wafDetector.IsBlocked(resp) {
                result.Body += "\n[WARNING: Request blocked by WAF/IPS]"
                if f.rateLimiter != nil {
                    f.rateLimiter.AdjustRate(-10)
                }
            }
        }
        
        if f.config.FollowRedirects && (result.Status >= 300 && result.Status < 400) {
            location := resp.Header.Peek("Location")
            if len(location) > 0 {
                result.Body += "\n[Redirect to: " + string(location) + "]"
            }
        }
    }
    
    select {
    case <-f.ctx.Done():
        return
    case f.results <- result:
    }
}

func formatPayload(payload map[string]string) string {
    var parts []string
    for _, v := range payload {
        parts = append(parts, v)
    }
    return strings.Join(parts, " | ")
}

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
            
            if f.config.Silent && result.Error == "" {
                continue
            }
            
            if !f.filter.ShouldShow(result) {
                continue
            }
            
            f.printer.Print(result)
        }
    }
}

func (f *Fuzzer) applyEvasionTechniques(req *fasthttp.Request) {
    if f.config.Advanced.RandomizeUA {
        req.Header.Set("User-Agent", getRandomUserAgent())
    }
    
    if f.config.Advanced.EvasionLevel >= 2 {
        req.Header.Set("X-Forwarded-For", generateRandomIP())
        req.Header.Set("X-Client-IP", generateRandomIP())
    }
    
    if f.config.Advanced.EvasionLevel >= 3 {
        time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
    }
    
    if f.config.Advanced.EvasionLevel >= 4 {
    }
}

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

func generateRandomIP() string {
    return fmt.Sprintf("%d.%d.%d.%d", 
        rand.Intn(255), rand.Intn(255), 
        rand.Intn(255), rand.Intn(255))
}

func applyURLEncoding(input string, level int) string {
    if level == 1 {
        return url.QueryEscape(input)
    }
    
    if level >= 2 {
        encoded := url.QueryEscape(input)
        return url.QueryEscape(encoded)
    }
    
    if level >= 3 {
        var result strings.Builder
        for _, r := range input {
            if rand.Intn(100) < 30 {
                result.WriteString(fmt.Sprintf("%%%02X", r))
            } else {
                result.WriteRune(r)
            }
        }
        return result.String()
    }
    
    return input
}

func applyHeaderEncoding(input string) string {
    if rand.Intn(100) < 20 {
        return base64.StdEncoding.EncodeToString([]byte(input))
    }
    return input
}

func applyDataEncoding(input string, level int) string {
    if level == 1 {
        return input
    }
    
    if level >= 2 {
        if rand.Intn(100) < 10 {
            return input + string([]byte{0})
        }
        
        if rand.Intn(100) < 10 {
            return input + "\u200b"
        }
    }
    
    return input
}