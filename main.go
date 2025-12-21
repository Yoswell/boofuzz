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
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    config := fuzzer.Config{}
    var headers utils.Headers
    
    var showStatus, hideStatus, showLines, hideLines, showWords, hideWords, showSize, hideSize, showRegex, hideRegex, showExtensions, hideExtensions string
    var showBody, showHeaders, followRedirects, http2, raw, silent, verbose, colorize, jsonOutput, noErrors bool
    var threads, recursionDepth int
    
    var excludeComments, excludeDots, excludeNumbers, excludeAllUpper, excludeAllLower, excludeFirstUpper, excludeFirstLower bool
    
    var rps int
    var authType, username, password, loginURL, encoderChain string
    var detectWAF, randomizeUA bool
    var evasionLevel int
    
    flag.StringVar(&config.URL, "u", "", "Target URL")
    flag.StringVar(&config.RequestFile, "request", "", "File with raw HTTP request")
    flag.Var(&wordlists, "w", "Wordlist file (path:FUZZ, multiple allowed)")
    flag.StringVar(&config.Method, "X", "GET", "HTTP method to use")
    flag.StringVar(&config.Data, "d", "", "POST data")
    flag.StringVar(&config.Cookie, "b", "", "Cookie data")
    flag.StringVar(&config.Proxy, "p", "", "Proxy URL")
    
    flag.Var(&headers, "H", "Header \"Name: Value\", separated by colon")
    
    flag.StringVar(&showStatus, "sc", "200-299,301,302,307,401,403,405,500", "Show HTTP status codes")
    flag.StringVar(&showLines, "sl", "", "Show amount of lines in response")
    flag.StringVar(&showWords, "sw", "", "Show amount of words in response")
    flag.StringVar(&showSize, "ss", "", "Show HTTP response size")
    flag.StringVar(&showRegex, "sr", "", "Show regexp")
    flag.StringVar(&showExtensions, "sx", "", "Show only URLs with specific extensions (comma-separated, e.g., .php,.html,.js)")
    
    flag.StringVar(&hideStatus, "hc", "", "Hide HTTP status codes")
    flag.StringVar(&hideLines, "hl", "", "Hide by amount of lines")
    flag.StringVar(&hideWords, "hw", "", "Hide by amount of words")
    flag.StringVar(&hideSize, "hs", "", "Hide HTTP response size")
    flag.StringVar(&hideRegex, "hr", "", "Hide regexp")
    flag.StringVar(&hideExtensions, "hx", "", "Hide URLs with specific extensions (comma-separated, e.g., .php,.html,.js)")
    
    flag.BoolVar(&showBody, "sb", false, "Show response body (default: false)")
    flag.BoolVar(&showHeaders, "sh", false, "Show response headers (default: false)")
    flag.BoolVar(&followRedirects, "L", false, "Follow redirects")
    flag.BoolVar(&http2, "http2", false, "Use HTTP2 protocol")
    flag.BoolVar(&raw, "raw", false, "Do not encode URI")
    flag.IntVar(&recursionDepth, "de", 0, "Maximum recursion depth")
    flag.IntVar(&threads, "t", 40, "Number of concurrent threads")
    flag.BoolVar(&silent, "s", false, "Silent mode")
    flag.BoolVar(&verbose, "v", false, "Verbose output")

    flag.BoolVar(&colorize, "c", false, "Colorize output")
    flag.BoolVar(&jsonOutput, "json", false, "JSON output")
    flag.BoolVar(&noErrors, "ne", false, "No error messages (default: false)")
    flag.StringVar(&config.Extensions, "x", "", "Add extensions (comma-separated, e.g., .php,.html,.js)")
    
    flag.BoolVar(&excludeComments, "xc-c", false, "Exclude lines starting with #, ~, or / from wordlist")
    flag.BoolVar(&excludeDots, "xc-d", false, "Exclude lines starting with . from wordlist")
    flag.BoolVar(&excludeNumbers, "xc-n", false, "Exclude lines starting with numbers from wordlist")
    flag.BoolVar(&excludeAllUpper, "xc-upper", false, "Exclude lines that are entirely uppercase")
    flag.BoolVar(&excludeAllLower, "xc-lower", false, "Exclude lines that are entirely lowercase")
    flag.BoolVar(&excludeFirstUpper, "xc-s-upper", false, "Exclude lines starting with uppercase letter")
    flag.BoolVar(&excludeFirstLower, "xc-s-lower", false, "Exclude lines starting with lowercase letter")
    
    flag.IntVar(&rps, "rate-limit", 0, "Requests per second (0 = no limit)")
    
    flag.StringVar(&authType, "auth-type", "", "Authentication type: basic, bearer, form, oauth2")
    flag.StringVar(&username, "auth-user", "", "Username for authentication")
    flag.StringVar(&password, "auth-pass", "", "Password for authentication")
    flag.StringVar(&loginURL, "auth-url", "", "Login URL for form authentication")
    
    flag.StringVar(&encoderChain, "encode", "", "Encoder chain (e.g., 'base64(md5(input))')")
    
    flag.BoolVar(&detectWAF, "detect-waf", false, "Detect WAF and adjust evasion")
    flag.BoolVar(&randomizeUA, "random-ua", true, "Randomize User-Agent")
    flag.IntVar(&evasionLevel, "evasion", 0, "Evasion level (0-5)")
    
    flag.Usage = func() {
        assets.PrintBanner()
        printUsage()
    }
    
    flag.Parse()
    
    // Goroutine para manejar Ctrl+C
    go func() {
        <-sigChan
        fmt.Println()
        fmt.Println()
        if colorize {
            fmt.Fprint(os.Stderr, "\033[33m[warning]\033[0m")
            fmt.Fprintln(os.Stderr, " :: Lucky for you, you can always try again...")
        } else {
            fmt.Println("[warning] :: Lucky for you, you can always try again...")
        }
        cancel()
        os.Exit(0)
    }()
    
    if config.URL == "" && config.RequestFile == "" {
        if colorize {
            fmt.Fprint(os.Stderr, "\033[31m[ERROR]\033[0m: -u flag or -request flag is required\n")
        } else {
            fmt.Println("[ERROR]: -u flag or -request flag is required")
        }
        os.Exit(1)
    }
    
    if len(wordlists) == 0 {
        if colorize {
            fmt.Fprint(os.Stderr, "\033[31m[ERROR]\033[0m: -w flag is required\n")
        } else {
            fmt.Println("[ERROR]: -w flag is required")
        }
        os.Exit(1)
    }
    
    config.Headers = headers
    config.Wordlists = wordlists
    config.FollowRedirects = followRedirects
    config.HTTP2 = http2
    config.Raw = raw
    config.Recursive = recursionDepth > 0
    config.RecursionDepth = recursionDepth
    config.Threads = threads
    config.ShowBody = showBody
    config.ShowHeaders = showHeaders
    config.Silent = silent
    config.Verbose = verbose
    config.JSONOutput = jsonOutput
    config.Colorize = colorize
    config.NoErrors = noErrors
    
    config.ExcludeComments = excludeComments
    config.ExcludeDots = excludeDots
    config.ExcludeNumbers = excludeNumbers
    config.ExcludeAllUpper = excludeAllUpper
    config.ExcludeAllLower = excludeAllLower
    config.ExcludeFirstUpper = excludeFirstUpper
    config.ExcludeFirstLower = excludeFirstLower
    
    config.Matchers = fuzzer.MatcherConfig{
        StatusCodes: showStatus,
        Lines:       showLines,
        Words:       showWords,
        Size:        showSize,
        Regex:       showRegex,
        Extensions:  showExtensions,
    }
    
    config.Filters = fuzzer.FilterConfig{
        StatusCodes: hideStatus,
        Lines:       hideLines,
        Words:       hideWords,
        Size:        hideSize,
        Regex:       hideRegex,
        Extensions:  hideExtensions,
    }
    
    config.RateLimiter = fuzzer.RateLimiterConfig{
        RequestsPerSecond: rps,
        Jitter:            true,
        Adaptive:          true,
    }
    
    config.Auth = fuzzer.AuthConfig{
        Type:     authType,
        Username: username,
        Password: password,
        LoginURL: loginURL,
    }
    
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
    
    utils.InitColors(colorize)
    
    printer := utils.NewPrinterWithHeaders(verbose, showBody, showHeaders, jsonOutput, colorize, noErrors)
    
    fz := fuzzer.NewFuzzer(config, printer)
    if err := fz.Run(ctx); err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }
}

func printUsage() {
    fmt.Println("[OPTIONS] HTTP OPTIONS:")
    fmt.Println("  -H                Header 'Name: Value', separated by colon. Multiple -H flags are accepted.")
    fmt.Println("  -X                HTTP method to use")
    fmt.Println("  -b                Cookie data 'Cookie=gab272j2n9a8a83j3'")
    fmt.Println("  -d                POST data")
    fmt.Println("  -de               Maximum recursion depth (default: 0)")
    fmt.Println("  -http2            Use HTTP2 protocol (default: false)")
    fmt.Println("  -L                Follow redirects (default: false)")
    fmt.Println("  -p                Proxy URL")
    fmt.Println("  -raw              Do not encode URI (default: false)")
    fmt.Println("  -u                Target URL")
    fmt.Println()
    fmt.Println("[OPTIONS] GENERAL OPTIONS:")
    fmt.Println("  -c                Colorize output. (default: false)")
    fmt.Println("  -json             JSON output (default: false)")
    fmt.Println("  -sb               Show response body (default: false)")
    fmt.Println("  -sh               Show response headers (default: false)")
    fmt.Println("  -s                Silent mode (default: false)")
    fmt.Println("  -t                Number of concurrent threads. (default: 40)")
    fmt.Println("  -v                Verbose output (default: false)")
    fmt.Println("  -x                Add extensions (comma-separated, e.g., .php,.html,.js)")
    fmt.Println("  -ne               No error messages (default: false)")
    fmt.Println()
    fmt.Println("[OPTIONS] WORDLIST FILTERING:")
    fmt.Println("  -xc-c             Exclude lines starting with #, ~, or / from wordlist")
    fmt.Println("  -xc-d             Exclude lines starting with . from wordlist")
    fmt.Println("  -xc-n             Exclude lines starting with numbers from wordlist")
    fmt.Println("  -xc-upper         Exclude lines that are entirely uppercase")
    fmt.Println("  -xc-lower         Exclude lines that are entirely lowercase")
    fmt.Println("  -xc-s-upper       Exclude lines starting with uppercase letter")
    fmt.Println("  -xc-s-lower       Exclude lines starting with lowercase letter")
    fmt.Println()
    fmt.Println("[OPTIONS] RATE LIMITING:")
    fmt.Println("  -rate-limit       Requests per second (default: 0 = no limit)")
    fmt.Println()
    fmt.Println("[OPTIONS] AUTHENTICATION:")
    fmt.Println("  -auth-type        Authentication type: basic, bearer, form, oauth2")
    fmt.Println("  -auth-user        Username for authentication")
    fmt.Println("  -auth-pass        Password for authentication")
    fmt.Println("  -auth-url         Login URL for form authentication")
    fmt.Println()
    fmt.Println("[OPTIONS] ENCODING:")
    fmt.Println("  -encode           Encoder chain (e.g., 'base64(md5(input))', 'urlencode(sha256(input))')")
    fmt.Println("                    MODES: base64, md5, sha1, sha256, urlencode, htmlencode, hex, unicode, rot13")
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
    fmt.Println("  -sx               Show only URLs with specific extensions (comma-separated, e.g., .php,.html,.js)")
    fmt.Println()
    fmt.Println("[OPTIONS] FILTER OPTIONS (Hide Results):")
    fmt.Println("  -hc               Hide HTTP status codes")
    fmt.Println("  -hl               Hide by amount of lines")
    fmt.Println("  -hr               Hide regexp")
    fmt.Println("  -hs               Hide HTTP response size")
    fmt.Println("  -hw               Hide by amount of words")
    fmt.Println("  -hx               Hide URLs with specific extensions (comma-separated, e.g., .php,.html,.js)")
    fmt.Println()
    fmt.Println("[EXAMPLES]:")
    fmt.Println("  Basic fuzzing:        boofuzz -u http://example.com/FUZZ -w wordlist.txt")
    fmt.Println("  With custom keyword:  boofuzz -u http://example.com/CUSTOM -w wordlist.txt:CUSTOM")
    fmt.Println("  With wordlist filter: boofuzz -u http://example.com/FUZZ -w wordlist.txt -xc-c -xc-d")
    fmt.Println("  Case filtering:       boofuzz -u http://example.com/FUZZ -w wordlist.txt -xc-upper -xc-s-lower")
    fmt.Println("  With authentication:  boofuzz -u http://example.com/admin -w wordlist.txt -auth-type form -auth-user admin -auth-pass password -auth-url http://example.com/login")
    fmt.Println("  With encoding:        boofuzz -u http://example.com/search?q=FUZZ -w wordlist.txt -encode 'base64(md5(input))'")
    fmt.Println("  With rate limiting:   boofuzz -u http://example.com/FUZZ -w wordlist.txt -rate-limit 10")
    fmt.Println("  With recursion:       boofuzz -u http://example.com/FUZZ -w wordlist.txt -de 2")
    fmt.Println()
    fmt.Println("[IMPORTANT]:")
    fmt.Println("  The default keyword is 'FUZZ'. Make sure to use 'FUZZ' in your URL, headers, or POST data.")
    fmt.Println("  If you want a custom keyword, use: -w wordlist.txt:CUSTOM and then use CUSTOM in your request.")
}