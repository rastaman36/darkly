# Stored XSS via SVG Tag Injection

## 🎯 Overview
This vulnerability demonstrates a stored Cross-Site Scripting (XSS) attack through the feedback/guestbook functionality, bypassing WAF filters using SVG tags to execute arbitrary JavaScript code.

## 🔍 Vulnerability Details
- **Endpoint**: `/index.php?page=feedback`
- **Feature**: Guestbook/Feedback System
- **Attack Vector**: SVG Tag Injection
- **Impact**: Persistent JavaScript Execution
- **WAF Bypass**: Using SVG instead of script tags

## ⚔️ Exploitation Process

### 1. Initial Analysis
```html
<!-- Standard script tag - Blocked by WAF -->
<script>alert('XSS')</script>
Result: Blocked/Filtered
```

### 2. WAF Bypass Payload
```html
<!-- SVG tag with event handler -->
<svg/onload=alert('XSS')>a
Result: Successfully executed
```

### Attack Result
**Flag**: 0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e

## 🛡️ Security Issues Identified
1. Insufficient input validation
2. Incomplete WAF rules
3. Stored XSS vulnerability
4. Missing content security policy
5. Inadequate output encoding

## 🔒 Recommended Security Fixes

### 1. Input Validation
```php
class FeedbackValidator {
    public function sanitizeInput($input) {
        // Remove all HTML tags
        $clean = strip_tags($input);
        
        // Encode special characters
        return htmlspecialchars($clean, ENT_QUOTES, 'UTF-8');
    }
    
    public function validateFeedback($data) {
        if (preg_match('/<[^>]*>/', $data)) {
            throw new SecurityException('HTML tags not allowed');
        }
        return $this->sanitizeInput($data);
    }
}
```

### 2. Content Security Policy
```php
class SecurityHeaders {
    public function setCSPHeaders() {
        header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'");
    }
    
    public function setSecurityHeaders() {
        header('X-XSS-Protection: 1; mode=block');
        header('X-Content-Type-Options: nosniff');
    }
}
```

### 3. Output Encoding
```php
class FeedbackDisplay {
    private $purifier;
    
    public function __construct() {
        $config = HTMLPurifier_Config::createDefault();
        $this->purifier = new HTMLPurifier($config);
    }
    
    public function renderFeedback($feedback) {
        // Purify HTML content
        $safe = $this->purifier->purify($feedback);
        
        // Additional encoding for display
        return htmlspecialchars($safe, ENT_QUOTES, 'UTF-8');
    }
}
```

### 4. Security Measures Checklist
- [ ] Implement strict input validation
- [ ] Add content security policy
- [ ] Use HTML purifier
- [ ] Enable output encoding
- [ ] Block dangerous tags/attributes
- [ ] Add XSS protection headers
- [ ] Implement proper logging

## 📝 Best Practices

### XSS Prevention
1. Validate all input
2. Encode all output
3. Use Content Security Policy
4. Implement WAF rules
5. Use modern framework protections

### Feedback System Implementation
```php
class SecureFeedbackSystem {
    private $validator;
    private $display;
    private $db;
    
    public function submitFeedback($data) {
        // Validate input
        $cleanData = $this->validator->validateFeedback($data);
        
        // Store safely
        $stmt = $this->db->prepare("
            INSERT INTO feedback (content, author, created_at) 
            VALUES (?, ?, NOW())
        ");
        return $stmt->execute([$cleanData, $author]);
    }
    
    public function displayFeedback() {
        $feedback = $this->db->query("SELECT * FROM feedback")->fetchAll();
        foreach ($feedback as $entry) {
            echo $this->display->renderFeedback($entry['content']);
        }
    }
}
```

### WAF Configuration
```nginx
# WAF rules for XSS prevention
location /feedback {
    # Block known XSS patterns
    if ($request_body ~* "<script|<svg|<img|<iframe") {
        return 403;
    }
    
    # Limit request size
    client_max_body_size 2k;
    
    # Set security headers
    add_header X-XSS-Protection "1; mode=block";
    add_header Content-Security-Policy "default-src 'self'";
}
```

## 📚 Additional Resources
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [HTML Purifier Documentation](http://htmlpurifier.org/)
- [Content Security Policy Guide](https://developers.google.com/web/fundamentals/security/csp)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.
