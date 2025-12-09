<div align="center">

### Boofuzz - Advanced HTTP Web Fuzzer
#### Fast and flexible HTTP fuzzer with multiple wordlist support, advanced filtering, and security testing capabilities | Directory busting | Parameter fuzzing | Custom payloads | WAF Evasion

[![Go](https://img.shields.io/badge/Go%201.21+-black)]()
[![HTTP](https://img.shields.io/badge/HTTP%20Fuzzer-black)]()
[![Wordlists](https://img.shields.io/badge/Multiple%20Wordlists-black)]()
[![Filtering](https://img.shields.io/badge/Advanced%20Filtering-black)]()
[![v1.0](https://img.shields.io/badge/v1.0-black)]()

</div>

-----

### What is Boofuzz?

Boofuzz is a high-performance HTTP web fuzzer written in Go, designed for directory busting, parameter fuzzing, and vulnerability discovery. It supports multiple wordlists with custom placeholders, advanced filtering options, and provides detailed response analysis including body and header inspection.

> [!IMPORTANT]
> **Legal and Ethical Notice**: This tool is strictly for educational purposes and authorized security testing. Do **not** use it against systems or networks you do not own or for which you lack explicit authorization to test.

> [!TIP]
> **Performance**: Boofuzz can process thousands of requests per second with concurrent threading, efficient HTTP handling using fasthttp, and smart rate limiting to avoid detection.

  * **Multiple Wordlist Support**: Use different wordlists with custom BOO placeholders for complex fuzzing scenarios
  * **Advanced Filtering**: Filter responses by status codes, size, lines, words, or regex patterns
  * **WAF Evasion Techniques**: Built-in evasion methods to bypass common WAF/IPS systems
  * **Rate Limiting & Backoff**: Configurable rate limiting with adaptive backoff strategies
  * **Authentication Support**: Built-in support for various authentication methods (Basic, Bearer, Form-based, OAuth2)
  * **Payload Encoding**: Multiple encoding options for fuzzing payloads (Base64, URL, Hex, etc.)
  * **Concurrent Processing**: High-performance concurrent request handling
  * **Detailed Results**: Comprehensive response analysis with status codes, sizes, and timing
  * **Response Analysis**: Inspect response bodies and headers with dedicated display options
  * **High Performance**: Concurrent request processing with configurable thread counts
  * **Flexible Output**: JSON output support and colored terminal output
  * **Proxy Support**: HTTP proxy integration for testing through intercepting proxies

-----

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

-----

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

-----

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
./boofuzz -u "https://api.example.com/v1/users?id=BOO" -w parameters.txt -sc 200,400,500
```

#### WAF Evasion with Rate Limiting

```bash
# Enable WAF detection and evasion with rate limiting
./boofuzz -u "https://example.com/search?q=BOO" -w xss-payloads.txt \
  --detect-waf --evasion 3 --rate-limit 10 --backoff exponential
```

#### Authentication and Session Handling

```bash
# Using form-based authentication
./boofuzz -u "https://example.com/admin/BOO" -w admin-paths.txt \
  --auth-type form --auth-user admin --auth-pass password --auth-url https://example.com/login

# Using Bearer token
./boofuzz -u "https://api.example.com/v1/data" -H "Authorization: Bearer YOUR_TOKEN"
```

#### Advanced Payload Encoding

```bash
# Using multiple encoding chains for payloads
./boofuzz -u "https://example.com/search?q=BOO" -w xss-payloads.txt \
  --encode "base64(md5(input))"

# Using URL encoding with special characters
./boofuzz -u "https://example.com/search?q=BOO" -w sqli-payloads.txt \
  --encode "urlencode(input)" --evasion 2
```

#### Concurrent Fuzzing with Proxies

```bash
# Using multiple wordlists with proxy
./boofuzz -u "https://example.com/BOO1/BOO2" \
  -w1 directories.txt -w2 extensions.txt \
  -x http://127.0.0.1:8080 -t 20
```

#### Filtering and Output

```bash
# Filter responses by size and output to JSON
./boofuzz -u "https://example.com/BOO" -w wordlist.txt \
  --size "!0,1000-2000" --json -o results.json

# Show response headers and body for successful requests
./boofuzz -u "https://example.com/BOO" -w wordlist.txt -sh -sb
```
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