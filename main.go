package main

import (
    "context"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "boofuzz/fuzzer"
    "boofuzz/utils"
    "boofuzz/assets"
)

/*
The main package contains the entry point for the boofuzz application.
It is responsible for parsing command-line flags, setting up the configuration,
handling graceful shutdown via Ctrl+C (SIGINT/SIGTERM), and initializing
the core Fuzzer components before starting the scan.
*/

var wordlists fuzzer.WordlistSpecs

func main() {
    // Configure context for Ctrl+C handling
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    // Goroutine to handle graceful shutdown
    go func() {
        <-sigChan
        fmt.Println()
        fmt.Println()
        fmt.Println("[info] :: Lucky for you, you can always try again...")
        cancel()
        os.Exit(0)
    }()
    
    config := fuzzer.Config{}
    var headers utils.Headers
    
    var showStatus, hideStatus, showLines, hideLines, showWords, hideWords, showSize, hideSize, showRegex, hideRegex string
    var showBody, showHeaders, followRedirects, http2, raw, recursive, silent, verbose, colorize, jsonOutput bool
    var threads, recursionDepth int
    
    // New flags for advanced features
    var rps, maxRetries int
    var backoffStrategy, authType, username, password, loginURL, encoderChain string
    var detectWAF, randomizeUA bool
    var evasionLevel int
    
    // --- Basic Options ---
    flag.StringVar(&config.URL, "u", "", "Target URL")
    flag.StringVar(&config.RequestFile, "request", "", "File with raw HTTP request")
    flag.Var(&wordlists, "w", "Wordlist file (path:BOO, multiple allowed)")
    flag.StringVar(&config.Method, "X", "GET", "HTTP method to use")
    flag.StringVar(&config.Data, "d", "", "POST data")
    flag.StringVar(&config.Cookie, "b", "", "Cookie data")
    flag.StringVar(&config.Proxy, "x", "", "Proxy URL")
    
    flag.Var(&headers, "H", "Header \"Name: Value\", separated by colon")
    
    // --- Show Matcher Options ---
    flag.StringVar(&showStatus, "sc", "200-299,301,302,307,401,403,405,500", "Show HTTP status codes")
    flag.StringVar(&showLines, "sl", "", "Show amount of lines in response")
    flag.StringVar(&showWords, "sw", "", "Show amount of words in response")
    flag.StringVar(&showSize, "ss", "", "Show HTTP response size")
    flag.StringVar(&showRegex, "sr", "", "Show regexp")
    
    // --- Hide Filter Options ---
    flag.StringVar(&hideStatus, "hc", "", "Hide HTTP status codes")
    flag.StringVar(&hideLines, "hl", "", "Hide by amount of lines")
    flag.StringVar(&hideWords, "hw", "", "Hide by amount of words")
    flag.StringVar(&hideSize, "hs", "", "Hide HTTP response size")
    flag.StringVar(&hideRegex, "hr", "", "Hide regexp")
    
    // --- General Options ---
    flag.BoolVar(&showBody, "sb", false, "Show response body (default: false)")
    flag.BoolVar(&showHeaders, "sh", false, "Show response headers (default: false)")
    flag.BoolVar(&followRedirects, "L", false, "Follow redirects")
    flag.BoolVar(&http2, "http2", false, "Use HTTP2 protocol")
    flag.BoolVar(&raw, "raw", false, "Do not encode URI")
    flag.BoolVar(&recursive, "recursion", false, "Scan recursively")
    flag.IntVar(&recursionDepth, "recursion-depth", 0, "Maximum recursion depth")
    flag.IntVar(&threads, "t", 40, "Number of concurrent threads")
    flag.BoolVar(&silent, "s", false, "Silent mode")
    flag.BoolVar(&verbose, "v", false, "Verbose output")
    flag.BoolVar(&colorize, "c", false, "Colorize output")
    flag.BoolVar(&jsonOutput, "json", false, "JSON output")
    
    // --- New Advanced Flags: Rate Limiting ---
    flag.IntVar(&rps, "rate-limit", 0, "Requests per second (0 = no limit)")
    flag.IntVar(&maxRetries, "max-retries", 3, "Maximum retries for failed requests")
    flag.StringVar(&backoffStrategy, "backoff", "exponential", "Backoff strategy: linear, exponential, random")
    
    // --- New Advanced Flags: Authentication ---
    flag.StringVar(&authType, "auth-type", "", "Authentication type: basic, bearer, form, oauth2")
    flag.StringVar(&username, "auth-user", "", "Username for authentication")
    flag.StringVar(&password, "auth-pass", "", "Password for authentication")
    flag.StringVar(&loginURL, "auth-url", "", "Login URL for form authentication")
    
    // --- New Advanced Flags: Encoding ---
    flag.StringVar(&encoderChain, "encode", "", "Encoder chain (e.g., 'base64(md5(input))')")
    
    // --- New Advanced Flags: Evasion ---
    flag.BoolVar(&detectWAF, "detect-waf", false, "Detect WAF and adjust evasion")
    flag.BoolVar(&randomizeUA, "random-ua", true, "Randomize User-Agent")
    flag.IntVar(&evasionLevel, "evasion", 0, "Evasion level (0-5)")
    
    // --- Usage Output ---
    flag.Usage = func() {
        assets.PrintBanner()
        printUsage()
    }
    
    flag.Parse()
    
    // --- Basic Validations ---
    if config.URL == "" && config.RequestFile == "" {
        fmt.Println("[ERROR]: -u flag or -request flag is required")
        os.Exit(1)
    }
    
    if len(wordlists) == 0 {
        fmt.Println("[ERROR]: -w flag is required")
        os.Exit(1)
    }
    
    // --- Assign Parsed Flags to Config ---
    config.Headers = headers
    config.Wordlists = wordlists
    config.FollowRedirects = followRedirects
    config.HTTP2 = http2
    config.Raw = raw
    config.Recursive = recursive
    config.RecursionDepth = recursionDepth
    config.Threads = threads
    config.ShowBody = showBody
    config.ShowHeaders = showHeaders
    config.Silent = silent
    config.Verbose = verbose
    config.JSONOutput = jsonOutput
    config.Colorize = colorize
    
    // Matcher configuration
    config.Matchers = fuzzer.MatcherConfig{
        StatusCodes: showStatus,
        Lines:       showLines,
        Words:       showWords,
        Size:        showSize,
        Regex:       showRegex,
    }
    
    // Filter configuration
    config.Filters = fuzzer.FilterConfig{
        StatusCodes: hideStatus,
        Lines:       hideLines,
        Words:       hideWords,
        Size:        hideSize,
        Regex:       hideRegex,
    }
    
    // --- Configure Advanced Features ---
    config.RateLimiter = fuzzer.RateLimiterConfig{
        RequestsPerSecond: rps,
        MaxRetries:        maxRetries,
        BackoffStrategy:   backoffStrategy,
        Jitter:            true, // Defaulting Jitter and Adaptive to true for robustness
        Adaptive:          true,
    }
    
    config.Auth = fuzzer.AuthConfig{
        Type:     authType,
        Username: username,
        Password: password,
        LoginURL: loginURL,
    }
    
    // Parse encoder chain string
    if encoderChain != "" {
        config.Encoders = fuzzer.EncoderConfig{
            Chains: []string{encoderChain},
        }
    }
    
    config.Advanced = fuzzer.AdvancedConfig{
        DetectWAF:    detectWAF,
        EvasionLevel: evasionLevel,
        RandomizeUA:  randomizeUA,
    }
    
    // --- Execution ---
    utils.InitColors(colorize)
    
    printer := utils.NewPrinterWithHeaders(verbose, showBody, showHeaders, jsonOutput, colorize)
    
    fz := fuzzer.NewFuzzer(config, printer)
    if err := fz.Run(ctx); err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }
}

// printUsage displays detailed help information for the command-line flags.
func printUsage() {
    fmt.Println("[OPTIONS] HTTP OPTIONS:")
    fmt.Println("  -H                Header 'Name: Value', separated by colon. Multiple -H flags are accepted.")
    fmt.Println("  -X                HTTP method to use")
    fmt.Println("  -b                Cookie data 'Cookie=gab272j2n9a8a83j3'")
    fmt.Println("  -d                POST data")
    fmt.Println("  -http2            Use HTTP2 protocol (default: false)")
    fmt.Println("  -L                Follow redirects (default: false)")
    fmt.Println("  -raw              Do not encode URI (default: false)")
    fmt.Println("  -recursion        Scan recursively. Only BOO keyword is supported.")
    fmt.Println("  -recursion-depth  Maximum recursion depth. (default: 0)")
    fmt.Println("  -u                Target URL")
    fmt.Println("  -x                Proxy URL")
    fmt.Println()
    fmt.Println("[OPTIONS] GENERAL OPTIONS:")
    fmt.Println("  -c                Colorize output. (default: false)")
    fmt.Println("  -json             JSON output (default: false)")
    fmt.Println("  -sb               Show response body (default: false)")
    fmt.Println("  -sh               Show response headers (default: false)")
    fmt.Println("  -s                Silent mode (default: false)")
    fmt.Println("  -t                Number of concurrent threads. (default: 40)")
    fmt.Println("  -v                Verbose output (default: false)")
    fmt.Println()
    fmt.Println("[OPTIONS] RATE LIMITING:")
    fmt.Println("  -rate-limit       Requests per second (default: 0 = no limit)")
    fmt.Println("  -max-retries      Maximum retries for failed requests (default: 3)")
    fmt.Println("  -backoff          Backoff strategy: linear, exponential, random (default: exponential)")
    fmt.Println()
    fmt.Println("[OPTIONS] AUTHENTICATION:")
    fmt.Println("  -auth-type        Authentication type: basic, bearer, form, oauth2")
    fmt.Println("  -auth-user        Username for authentication")
    fmt.Println("  -auth-pass        Password for authentication")
    fmt.Println("  -auth-url         Login URL for form authentication")
    fmt.Println()
    fmt.Println("[OPTIONS] ENCODING:")
    fmt.Println("  -encode           Encoder chain (e.g., 'base64(md5(input))', 'urlencode(sha256(input))')")
    fmt.Println("  Available encoders: base64, md5, sha1, sha256, urlencode, htmlencode, hex, unicode, rot13")
    fmt.Println()
    fmt.Println("[OPTIONS] EVASION:")
    fmt.Println("  -detect-waf       Detect WAF and adjust evasion (default: false)")
    fmt.Println("  -random-ua        Randomize User-Agent (default: true)")
    fmt.Println("  -evasion          Evasion level (0-5, default: 0)")
    fmt.Println()
    fmt.Println("[OPTIONS] MATCHER OPTIONS (Show Results):")
    fmt.Println("  -sc               Show HTTP status codes (default: 200-299,301,302,307,401,403,405,500)")
    fmt.Println("  -sl               Show amount of lines in response")
    fmt.Println("  -sr               Show regexp")
    fmt.Println("  -ss               Show HTTP response size")
    fmt.Println("  -sw               Show amount of words in response")
    fmt.Println()
    fmt.Println("[OPTIONS] FILTER OPTIONS (Hide Results):")
    fmt.Println("  -hc               Hide HTTP status codes")
    fmt.Println("  -hl               Hide by amount of lines")
    fmt.Println("  -hr               Hide regexp")
    fmt.Println("  -hs               Hide HTTP response size")
    fmt.Println("  -hw               Hide by amount of words")
    fmt.Println()
    fmt.Println("[EXAMPLES]:")
    fmt.Println("  Basic fuzzing:        boofuzz -u http://example.com/FUZZ -w wordlist.txt")
    fmt.Println("  With authentication:  boofuzz -u http://example.com/admin -w wordlist.txt -auth-type form -auth-user admin -auth-pass password -auth-url http://example.com/login")
    fmt.Println("  With encoding:        boofuzz -u http://example.com/search?q=FUZZ -w wordlist.txt -encode 'base64(md5(input))'")
    fmt.Println("  With rate limiting:   boofuzz -u http://example.com/FUZZ -w wordlist.txt -rate-limit 10 -max-retries 5")
}