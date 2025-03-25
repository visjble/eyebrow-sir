

![image](https://github.com/user-attachments/assets/8bae7aa1-403f-4f9b-9a2f-4a2337abc134)

# EyeBrow-sir

A lightweight, security-focused web browser built with PyQt6 that minimizes resource usage while maintaining essential functionality.

## Features

### Security
* **HTTPS Enforcement**: Automatically upgrades connections to HTTPS
* **Content Security Policy**: Built-in CSP headers protect against XSS attacks
* **Certificate Validation**: Warns users about invalid SSL certificates
* **Anti-Phishing Protection**: Detects suspicious URLs and domain spoofing
* **Request Filtering**: Blocks known ad/tracking domains and malicious patterns
* **HSTS Support**: Enforces strict transport security for major domains
* **URL Sanitization**: Prevents script injection and other URL-based attacks

### Privacy
* **No Persistent Cookies**: Session-only cookies that clear on exit
* **Tracker Blocking**: Built-in blocklist for common tracking services
* **No Local Storage**: Disables persistent client-side storage
* **In-Memory Cache**: No disk caching of browsing data

### Performance
* **Tab Hibernation**: Automatically hibernates inactive tabs to save memory
* **Resource Control**: Optional blocking of resource-heavy content types
* **Memory Optimization**: Periodic cleanup of unused resources
* **Minimal JavaScript**: JavaScript enabled but with tight restrictions
* **Site Isolation**: Process-per-site model for improved security and stability

## V2 Performance Enhancements

### Enhanced Ad and Tracker Blocking
* Expanded blocklist covering 25+ major tracking networks
* Regular expression pattern matching for better tracker identification
* URL path-based blocking for analytics, beacons, and tracking pixels

### Advanced Memory Management
* Aggressive garbage collection with native memory trimming
* Intelligent tab hibernation strategy for background tabs
* Resource prioritization for critical content

### Network Optimizations
* DNS pre-fetching for common domains
* QUIC protocol support for faster connections
* Memory-only caching with 10MB per-tab limits

### Resource Efficiency
* Process-per-site architecture (instead of process-per-tab)
* JavaScript memory optimization with --lite-mode flag
* Intelligent resource priority management

## Requirements
* Python 3.8+
* PyQt6
* PyQt6-WebEngine
* Ubuntu 23.04+

## Installation

```bash
# Clone the repository
git clone https://github.com/visjble/eyebrow-sir.git
cd eyebrow-sir

# Install dependencies
pip install PyQt6 PyQt6-WebEngine

# Run the browser
python eyebrow-sir.py
```

## Usage

### Keyboard Shortcuts
* `Ctrl+T`: New tab
* `Ctrl+W`: Close tab
* `Ctrl+L`: Focus address bar
* `F5`: Refresh page

## Customization

### Blocking Additional Domains
Add domains to the `BLOCKED_DOMAINS` list at the top of the script:

```python
BLOCKED_DOMAINS = [
    "doubleclick.net",
    "yourdomainhere.com",
    # ...
]
```

### Modifying Security Headers
Adjust the default security headers in the `BrowserTab` class:

```python
self.default_headers = {
    "Content-Security-Policy": "default-src 'self' https:; script-src 'self' https: 'unsafe-inline'",
    # Add or modify headers here
}
```

### Advanced Configuration
Environment variables can be set to further customize behavior:
* `QTWEBENGINE_CHROMIUM_FLAGS`: Flags passed to the Chromium engine
* `QTWEBENGINE_DICTIONARIES_PATH`: Path for spelling dictionaries
* `QTWEBENGINE_DISABLE_LOGGING`: Set to "1" to disable verbose logging

## Why EyeBrow-sir?
* **Lightweight**: Minimal resource usage compared to mainstream browsers
* **Security-Focused**: Built with security as a primary design goal
* **No Telemetry**: Zero data collection or phone-home features
* **Customizable**: Easy to modify for specific security requirements

## Limitations
* Limited extension/plugin support
* No sync functionality
* Basic UI without advanced features
* May not work with sites requiring advanced JavaScript

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
## License

NONE

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
