package utils

import (
    "encoding/json"
    "fmt"
    "io"
    "os"
    "strings"
    "sync"
    "time"
    "boofuzz/fuzzer"
    "github.com/fatih/color"
)

/*
The Printer package manages all output formatting for the fuzzer (boofuzz).

It handles:
- Printing structured results (normal or JSON format).
- Applying colorization based on HTTP status codes.
- Managing the progress bar display (ensuring the progress line is cleared before printing results and restored afterward).
- Formatting output for verbosity (including duration) and optional display of response body and headers.
*/

// Printer implements the fuzzer.ResultPrinter interface.
type Printer struct {
    verbose      bool
    showBody     bool
    showHeaders  bool  // Field added
    json         bool
    colorize     bool
    maxWordWidth int
    
    // For progress handling
    progressActive bool
    progressMutex  sync.Mutex
    progressShown  bool
    
    // Progress state
    currentWord    string
    completed      int
    total          int
    elapsedSeconds float64
    rate           float64
    
    // For controlling output streams
    out io.Writer // Standard output (for results)
    err io.Writer // Standard error (for progress and info/errors)
}

// NewPrinter is a convenience constructor for backwards compatibility (assumes showHeaders=false).
func NewPrinter(verbose, showBody, jsonOutput, colorize bool) *Printer {
    return NewPrinterWithHeaders(verbose, showBody, false, jsonOutput, colorize)
}

// NewPrinterWithHeaders creates a new Printer instance with full configuration.
func NewPrinterWithHeaders(verbose, showBody, showHeaders, jsonOutput, colorize bool) *Printer {
    return &Printer{
        verbose:      verbose,
        showBody:     showBody,
        showHeaders:  showHeaders,  // Store the parameter
        json:         jsonOutput,
        colorize:     colorize,
        maxWordWidth: 25,
        out:          os.Stdout,
        err:          os.Stderr,
    }
}

// Print processes and displays a single fuzzer result.
func (p *Printer) Print(result fuzzer.Result) {
    p.progressMutex.Lock()
    
    // If progress is visible, clear it first
    if p.progressShown {
        // Clear progress line using carriage return and ANSI erase to end of line
        fmt.Fprint(p.err, "\r\033[K")
        p.progressShown = false
    }
    
    p.progressMutex.Unlock()
    
    // Now print the result to stdout
    if p.json {
        p.printJSON(result)
    } else {
        if result.Error != "" {
            // Print error to stdout (or stderr depending on convention)
            if p.colorize {
                color.New(color.FgRed).Fprintf(p.out, "[error] :: %s: %s\n", result.URL, result.Error)
            } else {
                fmt.Fprintf(p.out, "[error] :: %s: %s\n", result.URL, result.Error)
            }
        } else {
            // Format word for fixed columns
            displayWord := fmt.Sprintf("%v", result.Payload)
            if len(displayWord) > p.maxWordWidth {
                displayWord = displayWord[:p.maxWordWidth-3] + "..."
            }

            // Aligned column format
            wordColumn := fmt.Sprintf("%-*s", p.maxWordWidth, displayWord)

            // Determine output based on verbosity
            if p.verbose {
                if p.colorize {
                    statusColor := p.getStatusColor(result.Status)
                    statusColor.Fprintf(p.out, "%s [Status: %d, Size: %d, Words: %d, Lines: %d, Duration: %v]\n",
                        wordColumn,
                        result.Status, result.Size, result.Words, result.Lines, result.Duration)
                } else {
                    fmt.Fprintf(p.out, "%s [Status: %d, Size: %d, Words: %d, Lines: %d, Duration: %v]\n",
                        wordColumn,
                        result.Status, result.Size, result.Words, result.Lines, result.Duration)
                }
            } else {
                if p.colorize {
                    statusColor := p.getStatusColor(result.Status)
                    statusColor.Fprintf(p.out, "%s [Status: %d, Size: %d, Words: %d, Lines: %d]\n",
                        wordColumn,
                        result.Status, result.Size, result.Words, result.Lines)
                } else {
                    fmt.Fprintf(p.out, "%s [Status: %d, Size: %d, Words: %d, Lines: %d]\n",
                        wordColumn,
                        result.Status, result.Size, result.Words, result.Lines)
                }
            }

            // Show body if enabled
            if p.showBody && len(result.Body) > 0 {
                if p.colorize {
                    color.New(color.FgCyan).Fprintln(p.out, "[body]")
                } else {
                    fmt.Fprintln(p.out, "[body]")
                }
                fmt.Fprintln(p.out, strings.TrimSpace(result.Body))
                fmt.Fprintln(p.out)
            }

            // Show headers if enabled
            if p.showHeaders && len(result.Headers) > 0 {
                if p.colorize {
                    color.New(color.FgYellow).Fprintln(p.out, "[header]")
                } else {
                    fmt.Fprintln(p.out, "[header]")
                }
                fmt.Fprintln(p.out, strings.TrimSpace(result.Headers))
                fmt.Fprintln(p.out)
            }
        }
    }
    
    // Restore progress display
    p.progressMutex.Lock()
    if p.progressActive {
        p.showProgress()
        p.progressShown = true
    }
    p.progressMutex.Unlock()
}

// ShowProgress updates the internal state and calls the display function.
func (p *Printer) ShowProgress(currentWord string, completed, total int, elapsedSeconds float64, rate float64) {
    if p.json {
        return
    }
    
    p.progressMutex.Lock()
    defer p.progressMutex.Unlock()
    
    p.progressActive = true
    p.currentWord = currentWord
    p.completed = completed
    p.total = total
    p.elapsedSeconds = elapsedSeconds
    p.rate = rate
    
    p.showProgress()
    p.progressShown = true
}

// showProgress displays the current progress line to stderr. Must be called under progressMutex lock.
func (p *Printer) showProgress() {
    if !p.progressActive {
        return
    }
    
    // Clear the current line completely before writing
    fmt.Fprint(p.err, "\r\033[K")
    
    // Truncate word if too long
    displayWord := p.currentWord
    if len(displayWord) > 15 {
        displayWord = displayWord[:12] + "..."
    }
    
    // Only show percentage, no rate or time in the continuous display
    percent := 0.0
    if p.total > 0 {
        percent = float64(p.completed) / float64(p.total) * 100
    }
    
    // Build the simplified progress line
    progressLine := fmt.Sprintf("\r[progress] :: %s :: %d/%d (%.2f%%)",
        displayWord,
        p.completed,
        p.total,
        percent)
    
    // Display on stderr
    fmt.Fprint(p.err, progressLine)
    
    // Force flush the output (important for continuous progress display)
    if f, ok := p.err.(interface{ Flush() error }); ok {
        f.Flush()
    }
}

// HideProgress clears the progress line from the terminal.
func (p *Printer) HideProgress() {
    p.progressMutex.Lock()
    defer p.progressMutex.Unlock()
    
    if p.progressShown {
        fmt.Fprint(p.err, "\r\033[K")
        p.progressShown = false
    }
}

// Finish stops the progress bar and prints final statistics.
func (p *Printer) Finish() {
    p.progressMutex.Lock()
    defer p.progressMutex.Unlock()
    
    // Clear final progress line if it was shown
    if p.progressShown {
        fmt.Fprint(p.err, "\r\033[K")
        p.progressShown = false
    }
    
    if p.progressActive {
        // Calculate final statistics
        durationStr := p.formatDuration(p.elapsedSeconds)
        
        // Display final completion message to stderr with full stats
        if p.colorize {
            color.New(color.FgGreen).Fprintf(p.err, "[finished] :: Completed %d requests in %s (%.1f req/sec)\n", 
                p.completed, durationStr, p.rate)
        } else {
            fmt.Fprintf(p.err, "[finished] :: Completed %d requests in %s (%.1f req/sec)\n", 
                p.completed, durationStr, p.rate)
        }
        
        p.progressActive = false
    }
}

// formatDuration converts seconds into a human-readable duration string (e.g., 1h5m, 30m10s, 45s).
func (p *Printer) formatDuration(seconds float64) string {
    dur := time.Duration(seconds * float64(time.Second))
    
    if dur < time.Minute {
        return fmt.Sprintf("%.0fs", dur.Seconds())
    } else if dur < time.Hour {
        minutes := int(dur.Minutes())
        seconds := int(dur.Seconds()) % 60
        return fmt.Sprintf("%dm%ds", minutes, seconds)
    } else {
        hours := int(dur.Hours())
        minutes := int(dur.Minutes()) % 60
        return fmt.Sprintf("%dh%dm", hours, minutes)
    }
}

// getStatusColor returns the appropriate color object based on the HTTP status code range.
func (p *Printer) getStatusColor(status int) *color.Color {
    if !p.colorize {
        return color.New() // Return a non-coloring object if colorization is off
    }
    
    switch {
    case status >= 200 && status < 300:
        return color.New(color.FgGreen) // Success
    case status >= 300 && status < 400:
        return color.New(color.FgYellow) // Redirect
    case status >= 400 && status < 500:
        return color.New(color.FgRed) // Client Error
    case status >= 500:
        return color.New(color.FgRed, color.Bold) // Server Error (Bold)
    default:
        return color.New(color.FgWhite) // Other/Unknown
    }
}

// printJSON formats the result as a JSON object and prints it.
func (p *Printer) printJSON(result fuzzer.Result) {
    jsonResult := map[string]interface{}{
        "url":      result.URL,
        "payload":  result.Payload,
        "status":   result.Status,
        "size":     result.Size,
        "lines":    result.Lines,
        "words":    result.Words,
        "duration_ms": result.Duration.Milliseconds(),
    }
    
    if result.Error != "" {
        jsonResult["error"] = result.Error
    }
    
    if p.showHeaders && len(result.Headers) > 0 {
        jsonResult["headers"] = strings.TrimSpace(result.Headers)
    }

    if p.showBody && len(result.Body) > 0 {
        jsonResult["body"] = strings.TrimSpace(result.Body)
    }
    
    // Ignore error, assume data is serializable
    data, _ := json.Marshal(jsonResult)
    fmt.Fprintln(p.out, string(data))
}