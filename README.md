# Advanced Proxy Logger

**Author:** w01f  
**License:** For Educational and Authorized Security Testing Use Only

## Overview

**Advanced Proxy Logger** is a professional-grade HTTP/HTTPS proxy traffic logger built on [mitmproxy](https://mitmproxy.org/).  
It is designed for mobile app/API/web pentesting, auditing, and research, with support for modern encrypted traffic, robust filtering, daily log rotation, real-time summaries, and sensitive data redaction.

---

## Features

- **Full HTTP/HTTPS interception** for Android, iOS, web, and any client supporting a proxy
- **Daily rotating logs** with automatic file name increments
- **Logs** in both human-readable (`.log`) and structured JSON (`.json`) formats
- **Real-time colored console summary** for quick monitoring
- **Sensitive data redaction** (headers & body patterns)
- **Request/response filtering** by host, HTTP method, content type, or keywords
- **Automatic log file compression** after N days
- **Thread-safe, production-ready logging**
- **Easy CLI configuration**

---

## Quick Start

### 1. **Install Dependencies**

```bash
pip install mitmproxy click termcolor
```

### 2. **Save Script**

Save as `advanced_proxy_logger.py`.

### 3. **Run the Proxy Logger**

```bash
mitmdump -s advanced_proxy_logger.py --listen-port 8080
```

#### **With Custom Options:**

```bash
mitmdump -s advanced_proxy_logger.py --listen-port 8888 --logdir ./mylogs --filter-host myapi.com --filter-method POST
```

| Option                | Description                                         |
| --------------------- | --------------------------------------------------- |
| --listen-port         | Proxy port (default: 8080)                          |
| --logdir              | Directory to save log files (default: ./logs)       |
| --filter-host         | Only log traffic to/from hosts matching this string |
| --filter-method       | Only log traffic with this HTTP method (e.g., POST) |
| --filter-keyword      | Only log traffic containing this keyword            |
| --filter-content-type | Only log matching content type (e.g., json)         |

---

### 4. **Set Up Your Device**

* On your Android/iOS device (or other client), set the HTTP/HTTPS proxy to your PC’s IP and chosen port.
* To intercept HTTPS, open `http://mitm.it` on your device while connected to the proxy and install the mitmproxy CA certificate.

---

### 5. **View Logs**

* Logs are saved as `{dd-mm-yy}.log` (human-readable) and `{dd-mm-yy}.json` (structured) in the log directory.
* Duplicate filenames are auto-incremented: `12-07-25.log`, `12-07-25_1.log`, etc.
* Old logs are compressed as `.zip` files automatically after the rotation period.

---

## **Feature Highlights**

* **Redaction:** Sensitive headers (Authorization, Cookie, etc.) and body patterns (e.g., passwords, tokens) are masked in logs.
* **Filtering:** Only log what matters—by host, method, content type, or keywords.
* **Live Monitoring:** See real-time, color-coded summaries of requests and responses in your terminal.
* **Scalability:** Thread-safe logging for high-volume environments.
* **Audit-Ready:** JSON logs are easy to analyze with scripts or SIEM tools.

---

## Example Usage

```bash
mitmdump -s advanced_proxy_logger.py --listen-port 8080 --logdir ./traffic --filter-host api.example.com --filter-method POST
```

---

## **For Educational & Authorized Use Only**

This tool is intended for use in lab environments, authorized penetration testing, and research.
**Do not use on networks or systems without proper authorization.**
The author assumes no liability for misuse.

---

## References

* [mitmproxy Documentation](https://docs.mitmproxy.org/)
* [OWASP Mobile Security Testing Guide (MASTG)](https://owasp.org/www-project-mobile-security-testing-guide/)
