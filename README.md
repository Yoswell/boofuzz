<div align="center">

### Boofuzz - Advanced HTTP Web Fuzzer

#### Fast and flexible HTTP fuzzer with multiple wordlist support, advanced filtering, authentication, WAF evasion, and security testing capabilities | Directory busting | Parameter fuzzing | Custom payloads | WAF Detection | Rate Limiting | Authentication

[![Go](https://img.shields.io/badge/Go%201.21+-black)]()
[![HTTP](https://img.shields.io/badge/HTTP%20Fuzzer-black)]()
[![Wordlists](https://img.shields.io/badge/Multiple%20Wordlists-black)]()
[![Filtering](https://img.shields.io/badge/Advanced%20Filtering-black)]()
[![WAF](https://img.shields.io/badge/WAF%20Evasion-black)]()
[![Auth](https://img.shields.io/badge/Authentication-black)]()
[![v2.0](https://img.shields.io/badge/v2.0-black)]()

</div>

-----

### What is Boofuzz?

Boofuzz is a high-performance HTTP web fuzzer written in Go, designed for directory busting, parameter fuzzing, and vulnerability discovery. It supports multiple wordlists with custom placeholders, advanced filtering options, rate limiting, authentication methods, WAF evasion techniques, and provides detailed response analysis including body and header inspection.

> [!IMPORTANT]
> **Legal and Ethical Notice**: This tool is strictly for educational purposes and authorized security testing. Do **not** use it against systems or networks you do not own or for which you lack explicit authorization to test.

> [!TIP]
> **Performance**: Boofuzz can process thousands of requests per second with concurrent threading, efficient HTTP handling using fasthttp, smart rate limiting to avoid detection, and adaptive backoff strategies.

  * **Multiple Wordlist Support**: Use different wordlists with custom FUZZ placeholders for complex fuzzing scenarios
  * **Advanced Filtering**: Filter responses by status codes, size, lines, words, regex patterns, or file extensions
  * **WAF Evasion Techniques**: Built-in evasion methods with automatic WAF detection to bypass common WAF/IPS systems
  * **Rate Limiting & Backoff**: Configurable rate limiting with adaptive backoff strategies (linear, exponential, random)
  * **Authentication Support**: Built-in support for various authentication methods (Basic, Bearer, Form-based, OAuth2)
  * **Payload Encoding**: Multiple encoding options for fuzzing payloads (Base64, MD5, SHA1, SHA256, URL, HTML, Hex, Unicode, ROT13)
  * **Concurrent Processing**: High-performance concurrent request handling with configurable thread counts
  * **Detailed Results**: Comprehensive response analysis with status codes, sizes, and timing
  * **Response Analysis**: Inspect response bodies and headers with dedicated display options


  * **Extension Filtering**: Show/hide results based on file extensions (.php, .html, .js, etc.)
  * **Flexible Output**: JSON output support and colored terminal output
  * **Proxy Support**: HTTP proxy integration for testing through intercepting proxies

-----

### Core Features

#### Fuzzing Engine

  * **Multiple Wordlists**: Support for multiple wordlists with custom identifiers (e.g., `wordlist.txt:FUZZ`)
  * **Placeholder System**: Replace FUZZ (and custom) placeholders in URLs, headers, and POST data
  * **Cartesian Product Generation**: Generate combinations from multiple wordlists for comprehensive testing
  * **Concurrent Processing**: Configurable thread count for high-speed fuzzing
  * **Request Customization**: Support for custom headers, methods, cookies, and POST data

#### Rate Limiting & Performance

  * **Requests Per Second (RPS)**: Control the rate of requests to avoid detection
  * **Adaptive Rate Limiting**: Automatically adjust rates based on server response
  * **Backoff Strategies**: Linear, exponential, and random backoff strategies
  * **Retry Mechanism**: Configurable retry attempts for failed requests
  * **Jitter Support**: Add random delays to avoid pattern detection

#### Authentication System

  * **Basic Authentication**: Username/password authentication
  * **Bearer Token**: JWT and API token authentication
  * **Form-based Authentication**: Automatic login and session handling
  * **OAuth2 Support**: OAuth2 flow support for modern applications
  * **Session Management**: Automatic session cookie handling

#### WAF Detection & Evasion

  * **Automatic WAF Detection**: Detect and identify WAF/IPS systems
  * **Evasion Levels**: 5 levels of evasion techniques (0-5)
  * **User-Agent Randomization**: Random User-Agent strings
  * **Header Obfuscation**: Random headers and IP spoofing
  * **Payload Encoding**: Multiple encoding strategies to bypass filters
  * **Adaptive Evasion**: Automatically adjust evasion based on detected WAF

#### Payload Encoding & Manipulation

  * **Encoding Chains**: Combine multiple encoders in sequence
  * **Supported Encoders**: Base64, MD5, SHA1, SHA256, URL, HTML, Hex, Unicode, ROT13
  * **Custom Chains**: Create complex encoding pipelines
  * **Evasion Encoding**: Automatic encoding for WAF bypass

#### Response Analysis

  * **Status Code Matching**: Show/hide responses based on HTTP status codes
  * **Content Filtering**: Filter by response size, line count, word count, or regex patterns
  * **Extension Filtering**: Show/hide results based on file extensions
  * **Body Inspection**: Display response bodies with `-sb` flag
  * **Header Inspection**: Display response headers with `-sh` flag
  * **Regex Matching**: Advanced pattern matching in response content

#### Output Options

  * **Verbose Mode**: Detailed output with timing and response statistics
  * **JSON Output**: Machine-readable JSON format for integration
  * **Colored Output**: Colorized terminal output for better readability
  * **Progress Tracking**: Real-time progress display with completion percentage
  * **Silent Mode**: Suppress output for background processing

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
./boofuzz -u https://example.com/FUZZ -w wordlist.txt

# Multiple wordlists with custom placeholders
./boofuzz -u https://example.com/FUZZ1/FUZZ2 -w wordlist1.txt:FUZZ1 -w wordlist2.txt:FUZZ2

# POST request fuzzing
./boofuzz -u https://example.com/api -X POST -d "param=FUZZ" -w wordlist.txt

# Show response bodies and headers
./boofuzz -u https://example.com/FUZZ -w wordlist.txt -sb -sh

# Filter responses (show only 200-299 status codes)
./boofuzz -u https://example.com/FUZZ -w wordlist.txt -sc 200-299

# Rate limited fuzzing
./boofuzz -u https://example.com/FUZZ -w wordlist.txt -rate-limit 10 -t 5


# Authentication and WAF evasion
./boofuzz -u https://example.com/admin/FUZZ -w admin.txt \
  -auth-type form -auth-user admin -auth-pass password \
  -auth-url https://example.com/login -detect-waf -evasion 3
```

-----

### Command Line Options

#### Target Options

  * `-u`: Target URL (required)
  * `-X`: HTTP method (default: GET)
  * `-d`: POST data
  * `-b`: Cookie data
  * `-H`: Custom headers (multiple allowed)
  * `-x`: Proxy URL

#### Wordlist Options

  * `-w`: Wordlist file with optional custom placeholder (e.g., `file.txt:FUZZ`)

#### Display Options

  * `-sb`: Show response body
  * `-sh`: Show response headers
  * `-v`: Verbose output
  * `-c`: Colorize output
  * `-json`: JSON output format
  * `-ne`: No error messages

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
  * `-sx`: Show only URLs with specific extensions (comma-separated, e.g., .php,.html,.js)
  * `-hx`: Hide URLs with specific extensions (comma-separated, e.g., .php,.html,.js)

#### General Options

  * `-t`: Number of threads (default: 40)
  * `-L`: Follow redirects
  * `-http2`: Use HTTP2
  * `-raw`: Don't encode URI
  * `-s`: Silent mode
  * `-recursion`: Recursive scanning
  * `-recursion-depth`: Maximum recursion depth
  * `-ex`: Add extensions (comma-separated, e.g., .php,.html,.js)

#### Rate Limiting Options

  * `-rate-limit`: Requests per second (0 = no limit)
  * `-max-retries`: Maximum retries for failed requests (default: 3)
  * `-backoff`: Backoff strategy: linear, exponential, random (default: exponential)

#### Authentication Options

  * `-auth-type`: Authentication type: basic, bearer, form, oauth2
  * `-auth-user`: Username for authentication
  * `-auth-pass`: Password for authentication
  * `-auth-url`: Login URL for form authentication

#### Encoding Options

  * `-encode`: Encoder chain (e.g., 'base64(md5(input))')
  * **Supported Encoders**: base64, md5, sha1, sha256, urlencode, htmlencode, hex, unicode, rot13

#### WAF Evasion Options

  * `-detect-waf`: Detect WAF and adjust evasion
  * `-random-ua`: Randomize User-Agent (default: true)
  * `-evasion`: Evasion level (0-5, default: 0)

#### Evasion Levels

  * **Level 0**: No evasion (default)
  * **Level 1**: Basic URL encoding
  * **Level 2**: Double encoding + header randomization
  * **Level 3**: Partial hex encoding + random delays
  * **Level 4**: Advanced character encoding + Unicode obfuscation
  * **Level 5**: Maximum evasion with all techniques

-----

### Advanced Usage

#### Authentication with Multiple Methods

```bash

# Basic authentication
./boofuzz -u https://example.com/admin -w admin-paths.txt \
  -auth-type basic -auth-user admin -auth-pass password

# Bearer token authentication
./boofuzz -u https://api.example.com/data -w endpoints.txt \
  -auth-type bearer -auth-pass YOUR_JWT_TOKEN

# Form-based with session handling
./boofuzz -u https://example.com/dashboard/FUZZ -w pages.txt \
  -auth-type form -auth-user admin -auth-pass password \
  -auth-url https://example.com/login
```

#### Advanced Payload Encoding

```bash

# Single encoding
./boofuzz -u "https://example.com/search?q=FUZZ" -w xss-payloads.txt \
  -encode "base64(input)"

# Complex encoding chain
./boofuzz -u "https://example.com/search?q=FUZZ" -w payloads.txt \
  -encode "base64(md5(sha256(input)))"

# URL encoding with evasion
./boofuzz -u "https://example.com/search?q=FUZZ" -w payloads.txt \
  -encode "urlencode(input)" -evasion 2
```

#### WAF Detection and Adaptive Evasion

```bash

# Detect WAF and enable automatic evasion
./boofuzz -u "https://example.com/FUZZ" -w wordlist.txt \
  -detect-waf -evasion 3

# Manual evasion with specific techniques
./boofuzz -u "https://example.com/FUZZ" -w wordlist.txt \
  -evasion 4 -random-ua -backoff exponential
```

#### Rate Limited Scanning with Backoff

```bash

# Conservative rate limiting
./boofuzz -u https://example.com/FUZZ -w wordlist.txt \
  -rate-limit 5 -backoff linear -max-retries 10

# Aggressive with exponential backoff
./boofuzz -u https://example.com/FUZZ -w wordlist.txt \
  -rate-limit 50 -backoff exponential -max-retries 3
```

#### Extension-Based Filtering

```bash
# Show only PHP and HTML files
./boofuzz -u https://example.com/FUZZ -w wordlist.txt -sx ".php,.html"

# Hide common file types
./boofuzz -u https://example.com/FUZZ -w wordlist.txt -hx ".css,.js,.png,.jpg"

# Add extensions to wordlist
./boofuzz -u https://example.com/FUZZ -w wordlist.txt -ex ".php,.html,.asp"
```

#### JSON Output for Integration

```bash
# Machine-readable output
./boofuzz -u https://example.com/FUZZ -w wordlist.txt -json | jq '.[] | select(.status == 200)'

# Filter and process results
./boofuzz -u https://example.com/FUZZ -w wordlist.txt -json -sc 200,403 \
  | jq -r '.[] | select(.size > 1000) | .url'
```

#### Proxy Testing with Authentication

```bash
# Using authenticated proxy
./boofuzz -u https://example.com/FUZZ -w wordlist.txt \
  -x http://user:pass@127.0.0.1:8080 -rate-limit 10


# Multiple proxies in rotation (configure via proxy chain)
./boofuzz -u https://example.com/FUZZ -w wordlist.txt \
  -x http://127.0.0.1:8080 -evasion 2
```

#### Recursive Fuzzing with Rate Limiting

```bash
# Conservative recursive scan
./boofuzz -u https://example.com/FUZZ -w directories.txt \
  -recursion -recursion-depth 2 -rate-limit 3


# Deep recursive with evasion
./boofuzz -u https://example.com/FUZZ -w directories.txt \
  -recursion -recursion-depth 5 -rate-limit 10 -evasion 3
```

-----

### Complex Examples

#### Multi-Stage Attack Simulation

```bash

# Stage 1: Discovery with WAF detection
./boofuzz -u https://example.com/FUZZ -w discovery.txt \
  -detect-waf -evasion 2 -rate-limit 5

# Stage 2: Authenticated enumeration
./boofuzz -u https://example.com/admin/FUZZ -w admin-paths.txt \
  -auth-type form -auth-user admin -auth-pass password \
  -auth-url https://example.com/login -evasion 3

# Stage 3: Parameter fuzzing with encoding
./boofuzz -u "https://example.com/api/v1/users?id=FUZZ" -w parameters.txt \
  -encode "base64(input)" -sc 200,400,500 -json
```

#### API Security Testing

```bash
# API endpoint discovery with authentication
./boofuzz -u "https://api.example.com/v1/FUZZ" -w api-endpoints.txt \
  -H "Authorization: Bearer TOKEN" -evasion 2

# Parameter fuzzing with multiple encoders
./boofuzz -u "https://api.example.com/v1/users?filter=FUZZ" -w filters.txt \
  -encode "urlencode(base64(input))" -json -sc 200,400,422

# Rate limited sensitive data enumeration
./boofuzz -u "https://api.example.com/v1/users/FUZZ/profile" -w user-ids.txt \
  -auth-type bearer -auth-pass JWT_TOKEN -rate-limit 2 -evasion 3
```

#### Web Application Security Assessment

```bash
# Comprehensive directory discovery
./boofuzz -u https://example.com/FUZZ -w comprehensive.txt \
  -sc 200,301,302,403 -sx ".php,.asp,.jsp,.html" -rate-limit 10

# Login bypass testing with session handling
./boofuzz -u https://example.com/login -X POST \
  -d "username=admin&password=FUZZ" -w passwords.txt \
  -auth-type form -auth-user admin -auth-pass wrongpass \
  -auth-url https://example.com/login -sc 302,200

# File upload fuzzing with content-type evasion
./boofuzz -u https://example.com/upload -X POST \
  -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary" \
  -d "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"FUZZ\"\r\n\r\npayload\r\n------WebKitFormBoundary--" \
  -w payloads.txt -evasion 2
```

#### WAF Bypass Techniques

```bash
# Automatic WAF detection and bypass
./boofuzz -u https://example.com/search?q=FUZZ -w xss-payloads.txt \
  -detect-waf -evasion 4 -random-ua -rate-limit 3

# SQL injection with encoding bypass
./boofuzz -u https://example.com/product.php?id=FUZZ -w sqli-payloads.txt \
  -encode "base64(input)" -evasion 3 -backoff exponential

# Header injection with IP spoofing
./boofuzz -u https://example.com/admin -w admin-paths.txt \
  -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" \
  --evasion 2 --detect-waf
```

#### Performance Testing and Stress

```bash
# High-volume discovery with adaptive rate limiting
./boofuzz -u https://example.com/FUZZ -w large-wordlist.txt \
  -t 100 -rate-limit 100 -backoff random

# Concurrent endpoint testing
./boofuzz -u https://example.com/api/v1/FUZZ -w endpoints.txt \
  -t 50 -rate-limit 50 -evasion 1

# Long-running monitoring with exponential backoff
./boofuzz -u https://example.com/FUZZ -w monitor.txt \
  -rate-limit 1 -backoff exponential -max-retries 20 -s
```

-----

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

#### Adding New Features

  1. Fork the repository
  2. Create a feature branch
  3. Implement your feature
  4. Add tests
  5. Submit a pull request

#### Code Standards

  * Follow Go best practices
  * Add comprehensive tests
  * Update documentation
  * Ensure backwards compatibility

-----

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

-----

**Made with love by Vishok**

_HTTP fuzzing made fast, flexible, and secure_
