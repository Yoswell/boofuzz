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

type Printer struct {
    verbose      bool
    showBody     bool
    showHeaders  bool  // Campo añadido
    json         bool
    colorize     bool
    maxWordWidth int
    
    // Para manejo del progreso
    progressActive bool
    progressMutex  sync.Mutex
    progressShown  bool
    
    // Estado del progreso
    currentWord    string
    completed      int
    total          int
    elapsedSeconds float64
    rate           float64
    
    // Para controlar la salida
    out io.Writer
    err io.Writer
}

func NewPrinter(verbose, showBody, jsonOutput, colorize bool) *Printer {
    return NewPrinterWithHeaders(verbose, showBody, false, jsonOutput, colorize)
}

func NewPrinterWithHeaders(verbose, showBody, showHeaders, jsonOutput, colorize bool) *Printer {
    return &Printer{
        verbose:      verbose,
        showBody:     showBody,
        showHeaders:  showHeaders,  // Almacenar el parámetro
        json:         jsonOutput,
        colorize:     colorize,
        maxWordWidth: 25,
        out:          os.Stdout,
        err:          os.Stderr,
    }
}

func (p *Printer) Print(result fuzzer.Result) {
    p.progressMutex.Lock()
    
    // Si el progreso está visible, limpiarlo primero
    if p.progressShown {
        // Limpiar línea de progreso
        fmt.Fprint(p.err, "\r\033[K")
        p.progressShown = false
    }
    
    p.progressMutex.Unlock()
    
    // Ahora imprimir el resultado en stdout
    if p.json {
        p.printJSON(result)
    } else {
        if result.Error != "" {
            if p.colorize {
                color.New(color.FgRed).Fprintf(p.out, "[error] :: %s: %s\n", result.URL, result.Error)
            } else {
                fmt.Fprintf(p.out, "[error] :: %s: %s\n", result.URL, result.Error)
            }
            } else {
                // Formatear palabra para columnas fijas
                displayWord := fmt.Sprintf("%v", result.Payload)
                if len(displayWord) > p.maxWordWidth {
                    displayWord = displayWord[:p.maxWordWidth-3] + "..."
                }

                // Formato con columnas alineadas
                wordColumn := fmt.Sprintf("%-*s", p.maxWordWidth, displayWord)

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

                // Mostrar cuerpo si está habilitado
                if p.showBody && len(result.Body) > 0 {
                    if p.colorize {
                        color.New(color.FgCyan).Fprintln(p.out, "[body]")
                    } else {
                        fmt.Fprintln(p.out, "[body]")
                    }
                    fmt.Fprintln(p.out, strings.TrimSpace(result.Body))
                    fmt.Fprintln(p.out)
                }

                // Mostrar headers si está habilitado
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
    
    // Volver a mostrar el progreso
    p.progressMutex.Lock()
    if p.progressActive {
        p.showProgress()
        p.progressShown = true
    }
    p.progressMutex.Unlock()
}

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

func (p *Printer) showProgress() {
    if !p.progressActive {
        return
    }
    
    // Limpiar completamente la línea actual antes de escribir
    fmt.Fprint(p.err, "\r\033[K")
    
    // Truncar palabra si es muy larga
    displayWord := p.currentWord
    if len(displayWord) > 15 {
        displayWord = displayWord[:12] + "..."
    }
    
    // Solo mostrar porcentaje, sin rate ni tiempo
    percent := 0.0
    if p.total > 0 {
        percent = float64(p.completed) / float64(p.total) * 100
    }
    
    // Construir la línea de progreso simplificada
    progressLine := fmt.Sprintf("\r[progress] :: %s :: %d/%d (%.2f%%)",
        displayWord,
        p.completed,
        p.total,
        percent)
    
    // Mostrar en stderr
    fmt.Fprint(p.err, progressLine)
    
    // Forzar flush de la salida
    if f, ok := p.err.(interface{ Flush() error }); ok {
        f.Flush()
    }
}

func (p *Printer) HideProgress() {
    p.progressMutex.Lock()
    defer p.progressMutex.Unlock()
    
    if p.progressShown {
        fmt.Fprint(p.err, "\r\033[K")
        p.progressShown = false
    }
}

func (p *Printer) Finish() {
    p.progressMutex.Lock()
    defer p.progressMutex.Unlock()
    
    if p.progressShown {
        fmt.Fprint(p.err, "\r\033[K")
        p.progressShown = false
    }
    
    if p.progressActive {
        // Calcular estadísticas finales
        durationStr := p.formatDuration(p.elapsedSeconds)
        
        // Mostrar mensaje de finalización en stderr con estadísticas completas
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

func (p *Printer) getStatusColor(status int) *color.Color {
    if !p.colorize {
        return color.New()
    }
    
    switch {
    case status >= 200 && status < 300:
        return color.New(color.FgGreen)
    case status >= 300 && status < 400:
        return color.New(color.FgYellow)
    case status >= 400 && status < 500:
        return color.New(color.FgRed)
    case status >= 500:
        return color.New(color.FgRed, color.Bold)
    default:
        return color.New(color.FgWhite)
    }
}

func (p *Printer) printJSON(result fuzzer.Result) {
    jsonResult := map[string]interface{}{
        "url":      result.URL,
        "payload":  result.Payload,
        "status":   result.Status,
        "size":     result.Size,
        "lines":    result.Lines,
        "words":    result.Words,
        "duration": result.Duration.Milliseconds(),
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
    
    data, _ := json.Marshal(jsonResult)
    fmt.Fprintln(p.out, string(data))
}