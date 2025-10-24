# CRUD-vuln-SQL
**Proof-of-Concept and Advisory for Simple CRUD SQL**

---

## Vulnerability Advisory & Exploit

## Affected Version
**SIMPLE_CRUD_IN_CODEIGNITER_USING_VUE.JS_WITH_SOURCE_CODE** — server components (CodeIgniter application under `civuejs`).

## Vulnerability Type
**SQL Injection** (assessment summary: no exploitable SQL concatenation found in key application files; see *Affected file(s)* below).

---

## Overview (short)
A review of the application code shows the user-management workflows use CodeIgniter’s Query Builder / query binding APIs for inserts and updates (for example, the `addUser` flow constructs a `$data` array from POST inputs and calls `$this->db->insert('users', $data)`). This pattern prevents direct string interpolation of user input into SQL and reduces SQL injection risk. No location in the application controllers/models was found that directly assembles SQL via string concatenation from raw `$_POST` values.

However, SQL injection depends on specific code patterns. Defenders should still validate that every place accepting user input uses parameterized queries or Query Builder. The non-executable PoC below shows a defender-only method to confirm whether any SQL is constructed from raw inputs.

---

## Impact
If a vulnerable pattern (raw concatenation of user input into SQL) were present, impact could include:

- Authentication bypass / account impersonation  
- Data disclosure (PII, account records)  
- Data manipulation (unauthorized `INSERT`/`UPDATE`/`DELETE`)  
- Additional risk if DB credentials are over-privileged

In the current codebase scan, those impacts are **not confirmed** because the inspected user-management paths use safe binding.

---

## Affected file(s)
*(where the user-management flow was implemented and inspected)*

- `civuejs/application/controllers/User.php` — contains `addUser`, `updateUser`, `deleteUser`, `searchUser` endpoints (controller receives POSTed form data).  
- `civuejs/application/models/User_model.php` — contains `addUser`, `showAll`, `searchUser` and uses `$this->db->insert()` and Query Builder methods.

**Finding:** the `addUser` → `user_model->addUser($data)` chain uses Query Builder binding (`$this->db->insert('users', $data)`), so no direct SQL string concatenation was found in these files. No other controller/model was found that builds raw SQL from `$_POST` in a way that confirms an exploitable SQL injection.

---

## Advisory (Recommendations)

- Keep using Query Builder / query binding throughout the codebase.  
- Audit every controller/model to ensure no raw SQL strings are assembled from user input.  
- Enforce input validation (whitelists, length/type checks) at controller level before passing data to models.  
- Ensure DB user has least-privilege.  
- Avoid logging sensitive plaintext values in production. Use the non-executable POC below **in staging only**.  
- Add CI/linters that flag direct concatenation into SQL functions (grep for `->query(` combined with concatenation or `sprintf`/string interpolation that includes `$_POST`/input values).

---

## Proof-of-Concept (Non-executable, Defender-only)

**Where to add the temporary test (staging only):**  
Insert a single, reversible debug log in the controller method that handles user creation (example: `civuejs/application/controllers/User.php::addUser()`), immediately before any DB execution.

**Example (staging-only) debug snippet — do not run in production:**

      // in addUser() controller, before saving:
      $username = $this->input->post('firstname');   // example field
      
      // If the app builds an SQL string directly, log it for inspection
      // (If the app uses $this->db->insert($data) Query Builder, the constructed SQL will not contain raw user values.)
      $sql_preview = isset($sql) ? $sql : '[no_raw_sql_variable]';
      log_message('debug', '[DEBUG_SQL_PREVIEW] ' . $sql_preview);

**Verify in logs:** submit benign test data in staging and inspect logs for DEBUG_SQL_PREVIEW.

- If the log shows raw user values embedded verbatim in SQL text → vulnerable pattern confirmed (immediate remediation required).

- If no raw SQL text appears or Query Builder placeholders are used → binding is in place (lower risk).

**Cleanup:** remove the temporary logging immediately after verification.

This POC is intentionally non-executable and intended only to let developers confirm whether any raw SQL assembly exists.

---

## Detection & Test Guidance (safe)

- Static grep/scan: search repository for ->query(, sprintf(, str_replace( used to build SQL, or occurrences of $_POST / $this->input->post adjacent to string concatenation operators (.).

- Add linting rules or CI jobs that flag suspicious concatenation into DB calls.

- Run authorized, non-destructive tests only in staging.

---

## Remediation — secure patterns (examples)

Continue using Query Builder:

      $data = ['firstname' => $firstname, 'lastname' => $lastname /* ... */];
      $this->db->insert('users', $data);


Or use binding:

      $sql = "INSERT INTO users (firstname, lastname) VALUES (?, ?)";
      $this->db->query($sql, [$firstname, $lastname]);

**Also:** validate inputs and hash sensitive fields (passwords) before storing.
