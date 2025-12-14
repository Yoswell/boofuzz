package fuzzer

import (
    "regexp"
    "strconv"
    "strings"
)

/*
This package implements the filtering logic for fuzzer results.
It uses "Matchers" to define which results should be **shown** (e.g., status 200, 403)
and "Filters" to define which results should be **hidden** (e.g., status 404, size 123).
Results are shown if they pass all configured filters AND match all configured matchers.
*/

// Range represents a range of values (e.g., 200-299, 100-200)
type Range struct {
    Min int
    Max int
}

// Filter evaluates whether a result should be displayed or not
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
    showExtensions []string
    hideExtensions []string
    hasMatchers  bool // Indicates if there are any matchers configured
}

// NewFilter creates a new filter with the configuration
func NewFilter(matcher MatcherConfig, filter FilterConfig) *Filter {
    f := &Filter{}
    
    // Parse configurations
    f.statusCodes = parseRanges(matcher.StatusCodes)
    f.hideStatusCodes = parseRanges(filter.StatusCodes)
    f.lines = parseRanges(matcher.Lines)
    f.hideLines = parseRanges(filter.Lines)
    f.words = parseRanges(matcher.Words)
    f.hideWords = parseRanges(filter.Words)
    f.sizes = parseRanges(matcher.Size)
    f.hideSizes = parseRanges(filter.Size)
    f.showExtensions = parseExtensions(matcher.Extensions)
    f.hideExtensions = parseExtensions(filter.Extensions)

    // Compile regex if provided
    if matcher.Regex != "" {
        f.showRegex = regexp.MustCompile(matcher.Regex)
    }
    if filter.Regex != "" {
        f.hideRegex = regexp.MustCompile(filter.Regex)
    }
    
    // Determine if there are active matchers
    f.hasMatchers = matcher.StatusCodes != "" || matcher.Lines != "" ||
                    matcher.Words != "" || matcher.Size != "" || matcher.Regex != "" || matcher.Extensions != ""
    
    return f
}

// ShouldShow determines if a result should be displayed
func (f *Filter) ShouldShow(result Result) bool {
    // If there is an error, always show
    if result.Error != "" {
        return true
    }
    
    // Apply filters first
    if f.shouldHide(result) {
        return false
    }
    
    // If no matchers are configured, show everything
    if !f.hasMatchers {
        return true
    }
    
    // Apply matchers - ALL specified matchers must match
    return f.shouldMatch(result)
}

// shouldHide checks if the result should be hidden
func (f *Filter) shouldHide(result Result) bool {
    // Check status codes to hide
    if len(f.hideStatusCodes) > 0 && inRanges(result.Status, f.hideStatusCodes) {
        return true
    }
    
    // Check lines to hide
    if len(f.hideLines) > 0 && inRanges(result.Lines, f.hideLines) {
        return true
    }
    
    // Verify words to hide
    if len(f.hideWords) > 0 && inRanges(result.Words, f.hideWords) {
        return true
    }
    
    // Check sizes to hide
    if len(f.hideSizes) > 0 && inRanges(result.Size, f.hideSizes) {
        return true
    }
    
    // Verify regex to hide
    if f.hideRegex != nil && f.hideRegex.MatchString(result.Body) {
        return true
    }
    
    return false
}

// shouldMatch verifies if the result matches the matchers
func (f *Filter) shouldMatch(result Result) bool {
    // If there are no matchers, show everything
    if !f.hasMatchers {
        return true
    }

    // For matchers: ONLY those that are configured must match
    // If a matcher is configured but doesn't match, return false

    // Check status codes (if configured)
    if len(f.statusCodes) > 0 {
        if !inRanges(result.Status, f.statusCodes) {
            return false
        }
    }

    // Check lines (if configured)
    if len(f.lines) > 0 {
        if !inRanges(result.Lines, f.lines) {
            return false
        }
    }

    // Check words (if configured)
    if len(f.words) > 0 {
        if !inRanges(result.Words, f.words) {
            return false
        }
    }

    // Check sizes (if configured)
    if len(f.sizes) > 0 {
        if !inRanges(result.Size, f.sizes) {
            return false
        }
    }

    // Check regex (if configured)
    if f.showRegex != nil {
        if !f.showRegex.MatchString(result.Body) {
            return false
        }
    }

    // Check extensions (if configured)
    if len(f.showExtensions) > 0 {
        if !hasExtension(result.URL, f.showExtensions) {
            return false
        }
    }

    // All configured matchers match
    return true
}

// parseRanges parses a string of ranges like "200-299,404,500-599"
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
        
        // Check if it's a range
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
            // It's a single value
            val, err := strconv.Atoi(part)
            if err == nil {
                ranges = append(ranges, Range{Min: val, Max: val})
            }
        }
    }
    
    return ranges
}

// inRanges checks if a value is within any of the ranges
func inRanges(value int, ranges []Range) bool {
    for _, r := range ranges {
        if value >= r.Min && value <= r.Max {
            return true
        }
    }
    return false
}

// parseExtensions parses a comma-separated list of extensions (e.g., ".php,.html,.js")
func parseExtensions(input string) []string {
    if input == "" {
        return []string{}
    }

    var extensions []string
    parts := strings.Split(input, ",")

    for _, part := range parts {
        part = strings.TrimSpace(part)
        if part != "" {
            // Ensure extension starts with a dot
            if !strings.HasPrefix(part, ".") {
                part = "." + part
            }
            extensions = append(extensions, strings.ToLower(part))
        }
    }

    return extensions
}

// hasExtension checks if the URL ends with any of the specified extensions
func hasExtension(url string, extensions []string) bool {
    if len(extensions) == 0 {
        return true // No extensions specified means no filtering
    }

    urlLower := strings.ToLower(url)
    for _, ext := range extensions {
        if strings.HasSuffix(urlLower, ext) {
            return true
        }
    }
    return false
}

// parseStatusCodeRanges parses status codes with special format like "2xx,3xx"
// NOTE: This function is not currently used in NewFilter, which uses parseRanges.
// It is left here as it was in the original snippet, but should be checked if needed.
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
        
        // Check if it's a range with xx
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
            // Normal range
            rangeParts := strings.Split(part, "-")
            if len(rangeParts) == 2 {
                min, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
                max, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
                if err1 == nil && err2 == nil {
                    ranges = append(ranges, Range{Min: min, Max: max})
                }
            }
        } else {
            // Single value
            val, err := strconv.Atoi(part)
            if err == nil {
                ranges = append(ranges, Range{Min: val, Max: val})
            }
        }
    }
    
    return ranges
}