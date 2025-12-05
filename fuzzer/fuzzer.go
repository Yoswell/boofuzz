package fuzzer

import (
    "bufio"
    "context"
    "fmt"
    "net/url"
    "os"
    "strings"
    "sync"
    "time"
    "github.com/valyala/fasthttp"
    "boofuzz/assets"
)

type WordlistSpec struct {
    Path  string
    BooID string
}

type WordlistSpecs []WordlistSpec

func (w *WordlistSpecs) String() string {
    return fmt.Sprintf("%v", *w)
}

func (w *WordlistSpecs) Set(value string) error {
    // Permitir formato simple para wordlist única
    if !strings.Contains(value, ":") {
        // Para wordlist única, usar BOO como ID por defecto
        *w = append(*w, WordlistSpec{Path: value, BooID: "BOO"})
        return nil
    }
    
    parts := strings.SplitN(value, ":", 2)
    if len(parts) != 2 {
        return fmt.Errorf("[error] :: invalid wordlist format, expected path:KEYWORD")
    }
    
    // Convertir keyword a mayúsculas
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
    Matchers        MatcherConfig
    Filters         FilterConfig
}

type MatcherConfig struct {
    StatusCodes string
    Lines       string
    Words       string
    Size        string
    Regex       string
}

type FilterConfig struct {
    StatusCodes string
    Lines       string
    Words       string
    Size        string
    Regex       string
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
    totalCombinations int // Campo añadido
}

type ResultPrinter interface {
    Print(result Result)
    ShowProgress(currentWord string, completed, total int, elapsedSeconds float64, rate float64)
    HideProgress()
    Finish()
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
    
    return &Fuzzer{
        config:       config,
        client:       client,
        results:      make(chan Result, 1000),
        printer:      printer,
        filter:       filter,
        progressStop: make(chan bool, 1),
        printerDone:  make(chan bool, 1),
    }
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
            if word != "" {
                words = append(words, word)
            }
        }

        if err := scanner.Err(); err != nil {
            return fmt.Errorf("[error] :: error reading wordlist %s: %v", spec.Path, err)
        }

        f.wordlists[spec.BooID] = words
    }
    return nil
}

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

func (f *Fuzzer) Run(ctx context.Context) error {
    f.ctx, f.cancel = context.WithCancel(ctx)
    defer f.cancel()
    
    // Verificar que las palabras clave estén presentes en la URL, data o headers
    // Solo si hay múltiples wordlists
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
    
    if err := f.loadWordlists(); err != nil {
        return err
    }

    assets.PrintBanner()

    // Definir las etiquetas y sus valores con ancho fijo de columna
    infoLabels := []struct {
        label string
        value interface{}
    }{
        {"Method", f.config.Method},
        {"URL", f.config.URL},
        {"Follow redirects", f.config.FollowRedirects},
        {"Threads", f.config.Threads},
    }
    
    // Ancho fijo para la columna de etiquetas (igual que en el printer)
    const labelWidth = 21
    
    // Imprimir información básica
    for _, item := range infoLabels {
        displayLabel := item.label
        if len(displayLabel) > labelWidth {
            displayLabel = displayLabel[:labelWidth-3] + "..."
        }
        labelColumn := fmt.Sprintf("%-*s", labelWidth, displayLabel)
        fmt.Printf("[info] :: %s: %v\n", labelColumn, item.value)
    }
    
    // Imprimir wordlists con sus keywords
    for _, spec := range f.config.Wordlists {
        labelColumn := fmt.Sprintf("%-*s", labelWidth, "Wordlist")
        fmt.Printf("[info] :: %s: %s [Keyword: %s] (%d words)\n", 
            labelColumn, spec.Path, spec.BooID, len(f.wordlists[spec.BooID]))
    }

    fmt.Println(f.getMatcherDescription())
    
    fmt.Println()

    f.startTime = time.Now()

    // Calculate total combinations for progress
    f.totalCombinations = 1
    for _, words := range f.wordlists {
        f.totalCombinations *= len(words)
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
    
    f.printer.Finish()
    
    return nil
}

// Nueva función para verificar keywords en la request
func (f *Fuzzer) checkKeywordsInRequest(keywords []string) bool {
    // Verificar en URL
    urlContainsKeyword := false
    for _, keyword := range keywords {
        if strings.Contains(f.config.URL, keyword) {
            urlContainsKeyword = true
            break
        }
    }
    
    // Verificar en POST data
    dataContainsKeyword := false
    for _, keyword := range keywords {
        if strings.Contains(f.config.Data, keyword) {
            dataContainsKeyword = true
            break
        }
    }
    
    // Verificar en headers
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
    
    // Al menos una de las ubicaciones debe contener los keywords
    return urlContainsKeyword || dataContainsKeyword || headersContainKeyword
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

func (f *Fuzzer) getMatcherDescription() string {
    const labelWidth = 21
    const prefix = "[info] :: "
    
    var result strings.Builder
    firstLine := true
    
    // Matchers
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
    
    // Filters
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
            f.makeRequest(payload)

            f.counterLock.Lock()
            f.counter++
            f.lastWord = fmt.Sprintf("%v", payload)
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
    
    var targetURL string
    targetURL = f.config.URL
    for booID, word := range payload {
        if f.config.Raw {
            targetURL = strings.ReplaceAll(targetURL, booID, word)
        } else {
            targetURL = strings.ReplaceAll(targetURL, booID, url.QueryEscape(word))
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
                    value = strings.ReplaceAll(value, booID, word)
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
            data = strings.ReplaceAll(data, booID, word)
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
        Payload:  formatPayload(payload), // Convertir map a string
        Status:   0, // Inicializar
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