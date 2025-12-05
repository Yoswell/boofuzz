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

var wordlists fuzzer.WordlistSpecs

func main() {
    // Configurar contexto para manejar Ctrl+C
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
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
    var recursionDepth, threads int
    
    flag.StringVar(&config.URL, "u", "", "Target URL")
    flag.StringVar(&config.RequestFile, "request", "", "File with raw HTTP request")
    flag.Var(&wordlists, "w", "Wordlist file (path:BOO, multiple allowed)")
    flag.StringVar(&config.Method, "X", "GET", "HTTP method to use")
    flag.StringVar(&config.Data, "d", "", "POST data")
    flag.StringVar(&config.Cookie, "b", "", "Cookie data")
    flag.StringVar(&config.Proxy, "x", "", "Proxy URL")
    
    flag.Var(&headers, "H", "Header \"Name: Value\", separated by colon")
    
    // Show options
    flag.StringVar(&showStatus, "sc", "200-299,301,302,307,401,403,405,500", "Show HTTP status codes")
    flag.StringVar(&showLines, "sl", "", "Show amount of lines in response")
    flag.StringVar(&showWords, "sw", "", "Show amount of words in response")
    flag.StringVar(&showSize, "ss", "", "Show HTTP response size")
    flag.StringVar(&showRegex, "sr", "", "Show regexp")
    
    // Hide options
    flag.StringVar(&hideStatus, "hc", "", "Hide HTTP status codes")
    flag.StringVar(&hideLines, "hl", "", "Hide by amount of lines")
    flag.StringVar(&hideWords, "hw", "", "Hide by amount of words")
    flag.StringVar(&hideSize, "hs", "", "Hide HTTP response size")
    flag.StringVar(&hideRegex, "hr", "", "Hide regexp")
    
    // General options
    flag.BoolVar(&showBody, "sb", false, "Show response body (default: false)")
    flag.BoolVar(&showHeaders, "sh", false, "Show response headers (default: false)") // Añadido: faltaba esta opción
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
    
    flag.Usage = func() {
        assets.PrintBanner()
        printUsage()
    }
    
    flag.Parse()
    
    // Validaciones básicas
    if config.URL == "" && config.RequestFile == "" {
        fmt.Println("[ERROR]: -u flag or -request flag is required")
        os.Exit(1)
    }
    
    if len(wordlists) == 0 {
        fmt.Println("[ERROR]: -w flag is required")
        os.Exit(1)
    }
    
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
    
    config.Matchers = fuzzer.MatcherConfig{
        StatusCodes: showStatus,
        Lines:       showLines,
        Words:       showWords,
        Size:        showSize,
        Regex:       showRegex,
    }
    
    config.Filters = fuzzer.FilterConfig{
        StatusCodes: hideStatus,
        Lines:       hideLines,
        Words:       hideWords,
        Size:        hideSize,
        Regex:       hideRegex,
    }
    
    utils.InitColors(colorize)
    
    printer := utils.NewPrinterWithHeaders(verbose, showBody, showHeaders, jsonOutput, colorize)
    
    fz := fuzzer.NewFuzzer(config, printer)
    if err := fz.Run(ctx); err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }
}

func printUsage() {
    fmt.Println("[options] HTTP OPTIONS:")
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
    fmt.Println("[options] GENERAL OPTIONS:")
    fmt.Println("  -c                Colorize output. (default: false)")
    fmt.Println("  -json             JSON output (default: false)")
    fmt.Println("  -sb               Show response body (default: false)")
    fmt.Println("  -sh               Show response headers (default: false)") // Añadido
    fmt.Println("  -s                Silent mode (default: false)")
    fmt.Println("  -t                Number of concurrent threads. (default: 40)")
    fmt.Println("  -v                Verbose output (default: false)")
    fmt.Println()
    fmt.Println("[options] MATCHER OPTIONS:")
    fmt.Println("  -sc               Show HTTP status codes (default: 200-299,301,302,307,401,403,405,500)")
    fmt.Println("  -sl               Show amount of lines in response")
    fmt.Println("  -sr               Show regexp")
    fmt.Println("  -ss               Show HTTP response size")
    fmt.Println("  -sw               Show amount of words in response")
    fmt.Println()
    fmt.Println("[options] FILTER OPTIONS:")
    fmt.Println("  -hc               Hide HTTP status codes")
    fmt.Println("  -hl               Hide by amount of lines")
    fmt.Println("  -hr               Hide regexp")
    fmt.Println("  -hs               Hide HTTP response size")
    fmt.Println("  -hw               Hide by amount of words")
}