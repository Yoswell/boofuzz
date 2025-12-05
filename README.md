<div align="center">

### Boofuzz - Advanced HTTP Web Fuzzer
#### Fast and flexible HTTP fuzzer with multiple wordlist support and advanced filtering capabilities | Directory busting | Parameter fuzzing | Custom payloads

[![Go](https://img.shields.io/badge/Go-1.21+-black)]()
[![HTTP](https://img.shields.io/badge/HTTP-Fuzzer-black)]()
[![Wordlists](https://img.shields.io/badge/Multiple-Wordlists-black)]()
[![Filtering](https://img.shields.io/badge/Advanced-Filtering-black)]()
[![v1.0](https://img.shields.io/badge/v1.0-black)]()

</div>

-----

### What is Boofuzz?

  Boofuzz is a high-performance HTTP web fuzzer written in Go, designed for directory busting, parameter fuzzing, and vulnerability discovery. It supports multiple wordlists with custom placeholders, advanced filtering options, and provides detailed response analysis including body and header inspection.

  > [!IMPORTANT]
  > **Legal and Ethical Notice**: This tool is strictly for educational purposes and authorized security testing. Do **not** use it against systems or networks you do not own or for which you lack explicit authorization to test.

  > [!TIP]
  > **Performance**: Boofuzz can process thousands of requests per second with concurrent threading and efficient HTTP handling using fasthttp.

  * **Multiple Wordlist Support**: Use different wordlists with custom BOO placeholders for complex fuzzing scenarios
  * **Advanced Filtering**: Filter responses by status codes, size, lines, words, or regex patterns
  * **Response Analysis**: Inspect response bodies and headers with dedicated display options
  * **High Performance**: Concurrent request processing with configurable thread counts
  * **Flexible Output**: JSON output support and colored terminal output
  * **Proxy Support**: HTTP proxy integration for testing through intercepting proxies

### Core Features

#### Fuzzing Engine
  * **Multiple Wordlists**: Support for multiple wordlists with custom identifiers (e.g., `wordlist.txt:BOO`)
  * **Placeholder System**: Replace BOO (and custom) placeholders in URLs, headers, and POST data
  * **Concurrent Processing**: Configurable thread count for high-speed fuzzing
  * **Request Customization**: Support for custom headers, methods, cookies, and POST data

#### Response Analysis
  * **Status Code Matching**: Show/hide responses based on HTTP status codes
  * **Content Filtering**: Filter by response size, line count, word count, or regex patterns
  * **Body Inspection**: Display response bodies with `-sb` flag
  * **Header Inspection**: Display response headers with `-sh` flag

#### Output Options
  * **Verbose Mode**: Detailed output with timing and response statistics
  * **JSON Output**: Machine-readable JSON format for integration
  * **Colored Output**: Colorized terminal output for better readability
  * **Progress Tracking**: Real-time progress display with completion percentage

-----

### Quick Start

#### Prerequisites
  * **Go 1.21+**: Required for building and running the application
  * **Git**: For cloning the repository

#### Installation & Setup

```bash
# Clone the repository
git clone <repository-url>
cd boofuzz

# Build the application
go build -o boofuzz
```

#### Basic Usage

```bash
# Simple directory busting
./boofuzz -u https://example.com/BOO -w wordlist.txt

# Multiple wordlists with custom placeholders
./boofuzz -u https://example.com/BOO1/BOO2 -w wordlist1.txt:BOO1 -w wordlist2.txt:BOO2

# POST request fuzzing
./boofuzz -u https://example.com/api -X POST -d "param=BOO" -w wordlist.txt

# Show response bodies and headers
./boofuzz -u https://example.com/BOO -w wordlist.txt -sb -sh

# Filter responses (show only 200-299 status codes)
./boofuzz -u https://example.com/BOO -w wordlist.txt -sc 200-299
```

---

### How It Works

```
Wordlist(s) → Payload Generation → HTTP Request → Response Analysis → Filtered Output
```

#### Payload Generation

Boofuzz supports cartesian product generation for multiple wordlists:

```bash
# Single wordlist
./boofuzz -u https://example.com/BOO -w paths.txt

# Multiple wordlists
./boofuzz -u https://example.com/BOO1/BOO2 -w users.txt:BOO1 -w paths.txt:BOO2
```

#### Request Processing

Each payload generates an HTTP request with placeholders replaced:

```go
// URL: https://example.com/admin/BOO
// Payload: BOO=secret
// Result: https://example.com/admin/secret
```

#### Response Filtering

Apply multiple filters to focus on interesting responses:

```bash
# Show only 200 responses with more than 1000 characters
./boofuzz -u https://example.com/BOO -w wordlist.txt -sc 200 -ss 1000

# Hide common error responses
./boofuzz -u https://example.com/BOO -w wordlist.txt -hc 404,500
```

-----

### Command Line Options

#### Target Options

  * `-u`: Target URL (required)
  * `-X`: HTTP method (default: GET)
  * `-d`: POST data
  * `-b`: Cookie data
  * `-H`: Custom headers (multiple allowed)

#### Wordlist Options

  * `-w`: Wordlist file with optional custom placeholder (e.g., `file.txt:BOO`)

#### Display Options

  * `-sb`: Show response body
  * `-sh`: Show response headers
  * `-v`: Verbose output
  * `-c`: Colorize output
  * `-json`: JSON output format

#### Filter Options

  * `-sc`: Show status codes (default: 200-299,301,302,307,401,403,405,500)
  * `-hc`: Hide status codes
  * `-sl`: Show by line count
  * `-hl`: Hide by line count
  * `-sw`: Show by word count
  * `-hw`: Hide by word count
  * `-ss`: Show by response size
  * `-hs`: Hide by response size
  * `-sr`: Show by regex
  * `-hr`: Hide by regex

#### General Options

  * `-t`: Number of threads (default: 40)
  * `-x`: Proxy URL
  * `-L`: Follow redirects
  * `-http2`: Use HTTP2
  * `-raw`: Don't encode URI
  * `-s`: Silent mode
  * `-recursion`: Recursive scanning
  * `-recursion-depth`: Maximum recursion depth

-----

### Advanced Usage

#### Custom Headers

```bash
./boofuzz -u https://example.com/BOO -w wordlist.txt -H "User-Agent: CustomAgent" -H "Authorization: Bearer TOKEN"
```

#### JSON Output for Integration

```bash
./boofuzz -u https://example.com/BOO -w wordlist.txt -json | jq '.[] | select(.status == 200)'
```

#### Proxy Testing

```bash
./boofuzz -u https://example.com/BOO -w wordlist.txt -x http://127.0.0.1:8080
```

#### Recursive Fuzzing

```bash
./boofuzz -u https://example.com/BOO -w directories.txt -recursion -recursion-depth 2
```

-----

### Repository Structure

```
boofuzz/
├── main.go                          # Main application entry point
├── fuzzer/
│   ├── fuzzer.go                    # Core fuzzing logic and request handling
│   ├── request.go                   # HTTP request utilities
│   ├── results.go                   # Result structures and types
│   └── filters.go                   # Response filtering logic
├── utils/
│   ├── printer.go                   # Output formatting and display
│   ├── headers.go                   # Header parsing utilities
│   └── colors.go                    # Color output utilities
├── assets/
│   └── banner.go                    # ASCII banner generation
├── go.mod                           # Go module dependencies
├── go.sum                           # Dependency checksums
└── README.md                        # This file
```

-----

### Development

#### Building from Source

```bash
# Clone and build
git clone <repository-url>
cd boofuzz
go build -o boofuzz main.go
```

#### Running Tests

```bash
go test ./...
```

#### Code Formatting

```bash
go fmt ./...
```

---

### Troubleshooting

#### Common Issues

  * **Wordlist Not Found**: Ensure wordlist files exist and have correct permissions
  * **No Responses**: Check network connectivity and target URL accessibility
  * **High Memory Usage**: Reduce thread count with `-t` flag for large wordlists
  * **Slow Performance**: Increase thread count or check proxy configuration

#### Debug Tips

  * Use `-v` for verbose output to see request details
  * Use `-s` for silent mode when redirecting output
  * Check wordlist encoding (should be UTF-8)
  * Verify placeholder usage in URLs/headers/data

> [!TIP]
> **Performance Tuning**: For large wordlists, start with lower thread counts and gradually increase based on target server capacity.

-----

### Examples

#### Directory Discovery

```bash
./boofuzz -u https://example.com/BOO -w common-directories.txt -sc 200,403 -t 50
```

#### API Parameter Fuzzing

```bash
./boofuzz -u https://api.example.com/search?q=BOO -w parameters.txt -H "Authorization: Bearer TOKEN"
```

#### Login Bypass Testing

```bash
./boofuzz -u https://example.com/login -X POST -d "username=admin&password=BOO" -w passwords.txt -sc 302
```

#### Header Injection

```bash
./boofuzz -u https://example.com/api -H "X-Custom: BOO" -w payloads.txt -sh
```

-----

### License

This project is licensed under the MIT License - see the LICENSE file for details.

-----

**Made with love by Vishok**

_HTTP fuzzing made fast and flexible_
