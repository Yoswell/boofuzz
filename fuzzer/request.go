package fuzzer

import (
    "strings"
)

/*
parses a raw HTTP request string and extracts the method, URL, headers, and body.
It assumes the raw request follows the standard HTTP format:
1. Request-Line (Method URL Version)
2. Headers
3. Blank Line
4. Body (Optional)
*/

func parseRawRequest(raw string) (method, url string, headers []string, body string) {
    // Split the raw request into lines
    lines := strings.Split(raw, "\n")
    
    // Parse the first line (Request-Line)
    if len(lines) > 0 {
        parts := strings.Fields(lines[0])
        if len(parts) >= 2 {
            // The method is the first part, URL is the second
            method = parts[0]
            url = parts[1]
        }
    }
    
    // Parse headers and body
    inBody := false
    for i := 1; i < len(lines); i++ {
        line := strings.TrimSpace(lines[i])
        
        // The blank line separates headers from the body
        if line == "" {
            inBody = true
            continue
        }
        
        if !inBody {
            // Line belongs to headers
            headers = append(headers, line)
        } else {
            // Line belongs to the body. Keep the newline for multi-line bodies.
            body += line + "\n"
        }
    }
    
    // Remove any trailing whitespace from the body
    body = strings.TrimSpace(body)
    return
}