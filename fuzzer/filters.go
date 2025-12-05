package fuzzer

import (
    "regexp"
    "strconv"
    "strings"
)

// Range representa un rango de valores (ej: 200-299, 100-200)
type Range struct {
    Min int
    Max int
}

// Filter evalua si un resultado debe mostrarse o no
type Filter struct {
    statusCodes []Range
    hideStatusCodes []Range
    lines        []Range
    hideLines    []Range
    words        []Range
    hideWords    []Range
    sizes        []Range
    hideSizes    []Range
    showRegex    *regexp.Regexp
    hideRegex    *regexp.Regexp
    hasMatchers  bool // Indica si hay algún matcher configurado
}

// NewFilter crea un nuevo filtro con la configuración
func NewFilter(matcher MatcherConfig, filter FilterConfig) *Filter {
    f := &Filter{}
    
    // Parsear configuraciones
    f.statusCodes = parseRanges(matcher.StatusCodes)
    f.hideStatusCodes = parseRanges(filter.StatusCodes)
    f.lines = parseRanges(matcher.Lines)
    f.hideLines = parseRanges(filter.Lines)
    f.words = parseRanges(matcher.Words)
    f.hideWords = parseRanges(filter.Words)
    f.sizes = parseRanges(matcher.Size)
    f.hideSizes = parseRanges(filter.Size)
    
    // Compilar regex si se proporciona
    if matcher.Regex != "" {
        f.showRegex = regexp.MustCompile(matcher.Regex)
    }
    if filter.Regex != "" {
        f.hideRegex = regexp.MustCompile(filter.Regex)
    }
    
    // Determinar si hay matchers activos
    f.hasMatchers = matcher.StatusCodes != "" || matcher.Lines != "" || 
                    matcher.Words != "" || matcher.Size != "" || matcher.Regex != ""
    
    return f
}

// ShouldShow determina si un resultado debe mostrarse
func (f *Filter) ShouldShow(result Result) bool {
    // Si hay error, mostrar siempre
    if result.Error != "" {
        return true
    }
    
    // Aplicar filtros de ocultación primero
    if f.shouldHide(result) {
        return false
    }
    
    // Si no hay matchers configurados, mostrar todo
    if !f.hasMatchers {
        return true
    }
    
    // Aplicar matchers - TODOS los matchers especificados deben coincidir
    return f.shouldMatch(result)
}

// shouldHide verifica si el resultado debe ser ocultado
func (f *Filter) shouldHide(result Result) bool {
    // Verificar códigos de estado a ocultar
    if len(f.hideStatusCodes) > 0 && inRanges(result.Status, f.hideStatusCodes) {
        return true
    }
    
    // Verificar líneas a ocultar
    if len(f.hideLines) > 0 && inRanges(result.Lines, f.hideLines) {
        return true
    }
    
    // Verificar palabras a ocultar
    if len(f.hideWords) > 0 && inRanges(result.Words, f.hideWords) {
        return true
    }
    
    // Verificar tamaños a ocultar
    if len(f.hideSizes) > 0 && inRanges(result.Size, f.hideSizes) {
        return true
    }
    
    // Verificar regex a ocultar
    if f.hideRegex != nil && f.hideRegex.MatchString(result.Body) {
        return true
    }
    
    return false
}

// shouldMatch verifica si el resultado coincide con los matchers
func (f *Filter) shouldMatch(result Result) bool {
    // Si no hay matchers, mostrar todo
    if !f.hasMatchers {
        return true
    }
    
    // Para los matchers: SOLO los que están configurados deben coincidir
    // Si un matcher está configurado pero no coincide, devolver false
    
    // Verificar códigos de estado (si está configurado)
    if len(f.statusCodes) > 0 {
        if !inRanges(result.Status, f.statusCodes) {
            return false
        }
    }
    
    // Verificar líneas (si está configurado)
    if len(f.lines) > 0 {
        if !inRanges(result.Lines, f.lines) {
            return false
        }
    }
    
    // Verificar palabras (si está configurado)
    if len(f.words) > 0 {
        if !inRanges(result.Words, f.words) {
            return false
        }
    }
    
    // Verificar tamaños (si está configurado)
    if len(f.sizes) > 0 {
        if !inRanges(result.Size, f.sizes) {
            return false
        }
    }
    
    // Verificar regex (si está configurado)
    if f.showRegex != nil {
        if !f.showRegex.MatchString(result.Body) {
            return false
        }
    }
    
    // Todos los matchers configurados coinciden
    return true
}

// parseRanges parsea una cadena de rangos como "200-299,404,500-599"
func parseRanges(input string) []Range {
    if input == "" {
        return []Range{}
    }
    
    var ranges []Range
    parts := strings.Split(input, ",")
    
    for _, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }
        
        // Verificar si es un rango
        if strings.Contains(part, "-") {
            rangeParts := strings.Split(part, "-")
            if len(rangeParts) == 2 {
                min, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
                max, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
                if err1 == nil && err2 == nil {
                    ranges = append(ranges, Range{Min: min, Max: max})
                }
            }
        } else {
            // Es un valor único
            val, err := strconv.Atoi(part)
            if err == nil {
                ranges = append(ranges, Range{Min: val, Max: val})
            }
        }
    }
    
    return ranges
}

// inRanges verifica si un valor está dentro de alguno de los rangos
func inRanges(value int, ranges []Range) bool {
    for _, r := range ranges {
        if value >= r.Min && value <= r.Max {
            return true
        }
    }
    return false
}

// parseStatusCodeRanges parsea códigos de estado con formato especial como "2xx,3xx"
func parseStatusCodeRanges(input string) []Range {
    if input == "" {
        return []Range{}
    }
    
    var ranges []Range
    parts := strings.Split(input, ",")
    
    for _, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }
        
        // Verificar si es un rango con xx
        if strings.HasSuffix(part, "xx") {
            prefix := strings.TrimSuffix(part, "xx")
            if len(prefix) == 1 {
                num, err := strconv.Atoi(prefix)
                if err == nil {
                    ranges = append(ranges, Range{
                        Min: num * 100,
                        Max: (num * 100) + 99,
                    })
                }
            }
        } else if strings.Contains(part, "-") {
            // Rango normal
            rangeParts := strings.Split(part, "-")
            if len(rangeParts) == 2 {
                min, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
                max, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
                if err1 == nil && err2 == nil {
                    ranges = append(ranges, Range{Min: min, Max: max})
                }
            }
        } else {
            // Valor único
            val, err := strconv.Atoi(part)
            if err == nil {
                ranges = append(ranges, Range{Min: val, Max: val})
            }
        }
    }
    
    return ranges
}