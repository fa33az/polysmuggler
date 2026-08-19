# Polysmuggler

Polysmuggler is a local polymorphic HTTP mutation proxy designed for auditing Web Application Firewalls (WAFs), Content Delivery Networks (CDNs), and load balancers during authorized security assessments. It dynamically intercepts client request bytes and applies real-time mutations at the TCP socket layer to evaluate backend parser robustness against HTTP smuggling and header parsing discrepancies.

## Disclaimer & Legal Warning

**IMPORTANT: This software is designed solely for authorized security audits, penetration testing, and defensive engineering. Running this tool against target infrastructures without explicit, written authorization from the system owners is illegal. The creator and contributors assume no liability for misuse, damages, or legal actions resulting from the use of this software. By cloning or utilizing this repository, you agree to use it in strict accordance with local laws and security assessment ethics.**

---

## Features

- **Dynamic Header Case Mutation:** Randomizes the casing of HTTP header keys (e.g., `Content-Type` to `cONteNt-TyPe`) to evaluate how parser normalization affects WAF rules.
- **Obfuscated Chunked Delivery:** Structures request bodies using customized `Transfer-Encoding: chunked` headers with strategies including:
  - Spacing and tab obfuscation (e.g., `Transfer-Encoding: \tchunked`).
  - Casing mutations (`ChUnKeD`).
  - Multi-value injection (`chunked, chunked`).
- **HTTP Smuggling Optimization:** Supports customizable header ordering templates to analyze CL.TE and TE.CL vulnerabilities.
- **Delay-Based Chunking:** Introduces a configurable delay between chunk deliveries to test stream-based inspection limits.
- **Unicode Homoglyph Translation:** Swaps query parameters with Unicode homoglyph equivalents to analyze regex normalization boundaries.
- **Dual Mode Operation:** Supports standard HTTP proxy forwarding and Reverse Proxy targeting for direct host evaluation.

## Installation

Ensure Go is installed (version 1.20+ recommended), then compile locally:

```bash
git clone https://github.com/fa33az/polysmuggler.git
cd polysmuggler
go build -o polysmuggler main.go
```

## Usage

### 1. Reverse Proxy Mode (Recommended for Target Auditing)
Start Polysmuggler locally, forwarding mutated traffic to your authorized target:
```bash
./polysmuggler -listen 127.0.0.1:8080 -target https://your-authorized-target.com -v
```

Route your scanner or development tool through the proxy listener:
```bash
curl -i -X POST http://127.0.0.1:8080/api/endpoint -d "data=test"
```

### 2. Command Line Options
```bash
Usage of polysmuggler:
  -listen string
        Local address to bind proxy listener (default "127.0.0.1:8080")
  -target string
        Target URL to reverse proxy and mutate requests for
  -case
        Enable polymorphic header casing strategy (default true)
  -obfuscate
        Enable chunked Transfer-Encoding obfuscation strategy (default true)
  -homoglyph
        Enable unicode homoglyph translation for query params (default false)
  -clte
        Enable Content-Length / Transfer-Encoding (CL.TE) smuggling header order (default false)
  -tecl
        Enable Transfer-Encoding / Content-Length (TE.CL) smuggling header order (default false)
  -delay int
        Delay in milliseconds between chunk delivery (0 for none)
  -v
        Enable verbose output logging
```
