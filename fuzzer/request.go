package fuzzer

import (
    "strings"
)

func parseRawRequest(raw string) (method, url string, headers []string, body string) {
    lines := strings.Split(raw, "\n")
    
    // Parse first line
    if len(lines) > 0 {
        parts := strings.Fields(lines[0])
        if len(parts) >= 2 {
            method = parts[0]
            url = parts[1]
        }
    }
    
    // Parse headers and body
    inBody := false
    for i := 1; i < len(lines); i++ {
        line := strings.TrimSpace(lines[i])
        
        if line == "" {
            inBody = true
            continue
        }
        
        if !inBody {
            headers = append(headers, line)
        } else {
            body += line + "\n"
        }
    }
    
    body = strings.TrimSpace(body)
    return
}