# 🚀 Polysmuggler

[![Go Version](https://img.shields.io/github/go-mod/go-version/fa33az/polysmuggler?color=00ADD8)](https://golang.org)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Offensive Security](https://img.shields.io/badge/Focus-Offensive%20Security-red.svg)](#)

Polysmuggler is a local polymorphic HTTP mutation proxy designed for auditing Web Application Firewalls (WAFs), Content Delivery Networks (CDNs), and load balancers during authorized security assessments. It dynamically intercepts client request bytes and applies real-time mutations at the TCP socket layer to evaluate backend parser robustness against HTTP smuggling and header parsing discrepancies.

---

## 🛡️ Disclaimer & Legal Warning

> [!WARNING]
> **This software is designed solely for authorized security audits, penetration testing, and defensive engineering evaluation. Running this tool against target infrastructures without explicit, written authorization from the system owners is illegal. The creator and contributors assume no liability for misuse, damages, or legal actions resulting from the use of this software. By cloning or utilizing this repository, you agree to use it in strict accordance with local laws and security assessment ethics.**

---

## 📦 Key Capabilities

* **`Dynamic Header Case Mutation`**: Randomizes the casing of HTTP header keys (e.g., `Content-Type` $\to$ `cONteNt-TyPe`) to evaluate how parser normalization affects WAF rules.
* **`Obfuscated Chunked Delivery`**: Structures request bodies using customized `Transfer-Encoding: chunked` headers with strategies including:
  * Spacing and tab obfuscation (e.g., `Transfer-Encoding: \tchunked`).
  * Casing mutations (`ChUnKeD`).
  * Multi-value injection (`chunked, chunked`).
* **`HTTP Smuggling Optimization`**: Supports customizable header ordering templates to analyze CL.TE and TE.CL vulnerabilities.
* **`Delay-Based Chunking`**: Introduces a configurable delay between chunk deliveries to test stream-based inspection limits.
* **`Unicode Homoglyph Translation`**: Swaps query parameters with Unicode homoglyph equivalents to analyze regex normalization boundaries.
* **`Dual Mode Operation`**: Supports standard HTTP proxy forwarding and Reverse Proxy targeting for direct host evaluation.

---

## 💻 Installation

Ensure Go is installed (version 1.20+ recommended), then compile locally:

```bash
# Clone the repository
git clone https://github.com/fa33az/polysmuggler.git

# Move into the project directory
cd polysmuggler

# Compile into a local binary
go build -o polysmuggler main.go
```

---

## ⚙️ Usage Guide

### 1. Reverse Proxy Mode (Recommended for Target Auditing)
Start Polysmuggler locally, forwarding mutated traffic to your authorized target:
```bash
./polysmuggler -listen 127.0.0.1:8080 -target https://your-authorized-target.com -v
```

Route your scanner or development tool through the proxy listener:
```bash
curl -i -X POST http://127.0.0.1:8080/api/endpoint -d "data=test"
```

### 2. Command Line Arguments Reference

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-listen` | `string` | `127.0.0.1:8080` | Local address to bind proxy listener |
| `-target` | `string` | `""` | Target URL to reverse proxy and mutate requests for |
| `-case` | `bool` | `true` | Enable polymorphic header casing strategy |
| `-obfuscate` | `bool` | `true` | Enable chunked Transfer-Encoding obfuscation strategy |
| `-homoglyph` | `bool` | `false` | Enable unicode homoglyph translation for query params |
| `-clte` | `bool` | `false` | Enable Content-Length / Transfer-Encoding (CL.TE) smuggling |
| `-tecl` | `bool` | `false` | Enable Transfer-Encoding / Content-Length (TE.CL) smuggling |
| `-delay` | `int` | `0` | Delay in milliseconds between chunk delivery |
| `-v` | `bool` | `false` | Enable verbose output logging |
