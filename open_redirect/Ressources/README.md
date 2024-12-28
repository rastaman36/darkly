# Open Redirect Vulnerability

## 🎯 Overview
This vulnerability demonstrates an unvalidated URL redirect where the application fails to verify the destination of redirects, allowing attackers to redirect users to malicious websites.

## 🔍 Vulnerability Details
- **Endpoint**: `index.php?page=redirect&site=`
- **Parameter**: `site`
- **Location**: Footer social media links
- **Attack Vector**: URL Parameter Manipulation

## ⚔️ Exploitation Process

### 1. Vulnerability Discovery
- Located social media links in page footer
- Identified redirect mechanism in source code
- Found unvalidated `site` parameter

### 2. Attack Method
```http
GET /index.php?page=redirect&site=https://www.42.fr HTTP/1.1
Host: x.x.x.x
```

### Attack Result
**Flag**: b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3

## 🛡️ Security Issues Identified
1. No URL validation
2. Uncontrolled redirect
3. Missing whitelist of allowed domains
4. Direct user input in redirect
5. No URL sanitization

## 🔒 Recommended Security Fixes

### 1. Implement URL Validation
```php
function validateRedirectUrl($url) {
    $allowedDomains = [
        'facebook.com',
        'twitter.com',
        'instagram.com'
    ];
    
    $parsedUrl = parse_url($url);
    return in_array($parsedUrl['host'], $allowedDomains);
}
```

### 2. Security Measures Checklist
- [ ] Implement URL validation
- [ ] Create whitelist of allowed domains
- [ ] Use relative URLs where possible
- [ ] Implement proper URL parsing
- [ ] Add user warning for external redirects

### 3. Secure Redirect Implementation
```php
// Example secure redirect handler
public function handleRedirect($destination) {
    // Use internal route IDs instead of URLs
    $routes = [
        'twitter' => 'https://twitter.com/ourprofile',
        'facebook' => 'https://facebook.com/ourpage',
        'instagram' => 'https://instagram.com/ourprofile'
    ];
    
    if (!isset($routes[$destination])) {
        return redirect('/');
    }
    
    return redirect($routes[$destination]);
}
```

## 📝 Best Practices

### Safe Redirect Methods
1. Use relative paths when possible
2. Implement indirect references
3. Validate all redirect URLs
4. Use URL signing for necessary external redirects

### Example Safe Implementation
```html
<!-- Use route names instead of direct URLs -->
<a href="/redirect/twitter" class="social-link">Twitter</a>
<a href="/redirect/facebook" class="social-link">Facebook</a>
<a href="/redirect/instagram" class="social-link">Instagram</a>
```

## 📚 Additional Resources
- [OWASP Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [SANS: Preventing Open Redirect Vulnerabilities](https://www.sans.org/blog/preventing-open-redirect-vulnerabilities/)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.