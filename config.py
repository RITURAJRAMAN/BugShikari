"""
BugShikari - Advanced Bug Hunting & Reconnaissance Toolkit
Configuration settings
"""

import os

# ─── Target Defaults ─────────────────────────────────────────────────
DEFAULT_DOMAIN = "example.com"

# Example In-Scope Domains (e.g., Google VRP, Bugcrowd, HackerOne programs)
# You can update this list with your own targets.
IN_SCOPE_DOMAINS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "yahoo.com",
    "bing.com",
    "apple.com",
    "microsoft.com",
    "github.com",
    "linkedin.com",
    "netflix.com",
    "airbnb.com",
    "uber.com",
    "teslamotors.com",
    "paypal.com",
    "dropbox.com",
    "shopify.com",
    "slack.com",
    "spotify.com",
    "twitch.tv",
    "adobe.com"
]

# ─── HTTP Settings ────────────────────────────────────────────────────
REQUEST_TIMEOUT = 10  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds between retries

# User-Agent rotation list (common browser UAs)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

# ─── Subdomain Enumeration ────────────────────────────────────────────
# Common subdomain prefixes to brute-force
SUBDOMAIN_WORDLIST = [
    "admin", "api", "app", "beta", "blog", "cdn", "cloud", "cms",
    "console", "dashboard", "data", "db", "demo", "dev", "docs",
    "email", "ftp", "git", "grafana", "help", "internal", "jenkins",
    "jira", "lab", "labs", "login", "m", "mail", "manage", "monitor",
    "mysql", "ns1", "ns2", "panel", "portal", "prod", "proxy",
    "redis", "remote", "sandbox", "search", "secure", "server",
    "smtp", "sql", "stage", "staging", "static", "stats", "status",
    "store", "support", "test", "testing", "tools", "vpn", "web",
    "webmail", "wiki", "www", "accounts", "analytics", "ads",
    "adwords", "calendar", "chat", "classroom", "code", "colab",
    "contacts", "corp", "developers", "dialogflow", "dns", "domains",
    "drive", "earth", "firebase", "fonts", "groups", "hangouts",
    "images", "inbox", "keep", "maps", "meet", "news", "notebook",
    "one", "pay", "photos", "play", "podcasts", "policies", "privacy",
    "recaptcha", "scholar", "sheets", "sites", "slides", "stadia",
    "storage", "store", "stream", "translate", "trends", "vault",
    "video", "voice", "workspace",
]

# Certificate Transparency log API
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

# ─── Output Settings ──────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")

# Ensure results directory exists
os.makedirs(RESULTS_DIR, exist_ok=True)

# ─── Authenticated Scanning ──────────────────────────────────────────
# Path to a Netscape or JSON cookie file for authenticated scans
# To use, export your browser cookies for the target domain using an extension
# like "Cookie-Editor" and save it as 'cookies.json' in the root directory.
COOKIE_FILE_PATH = os.path.join(BASE_DIR, "cookies.json")

# ─── Security Headers to Check ────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "required": True,
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and injection attacks",
        "required": True,
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "required": True,
        "expected_value": "nosniff",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking",
        "required": True,
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (browser support varies)",
        "required": False,
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "required": True,
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access",
        "required": False,
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Prevents cross-origin attacks",
        "required": False,
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls cross-origin resource sharing",
        "required": False,
    },
}

# ─── CSP Dangerous Patterns ──────────────────────────────────────────
CSP_DANGEROUS_DIRECTIVES = {
    "'unsafe-inline'": "Allows inline scripts/styles — XSS risk",
    "'unsafe-eval'": "Allows eval() — code injection risk",
    "data:": "Allows data: URIs — can be used for XSS",
    "blob:": "Allows blob: URIs — can be used for code execution",
    "*": "Wildcard source — allows any origin",
}

# CDNs known to have CSP bypass potential
CSP_BYPASS_CDNS = [
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "rawgit.com",
    "raw.githubusercontent.com",
    "accounts.google.com",  # JSONP endpoints
]

# ─── Google Dork Categories ──────────────────────────────────────────
DORK_TEMPLATES = {
    "Exposed Files": [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:doc OR filetype:docx',
        'site:{domain} filetype:xls OR filetype:xlsx',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:log',
        'site:{domain} filetype:env',
        'site:{domain} filetype:cfg OR filetype:conf',
        'site:{domain} filetype:bak OR filetype:backup',
        'site:{domain} filetype:xml',
        'site:{domain} filetype:json',
    ],
    "Login & Admin Pages": [
        'site:{domain} inurl:login',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:signin',
        'site:{domain} inurl:dashboard',
        'site:{domain} inurl:panel',
        'site:{domain} intitle:"login"',
        'site:{domain} intitle:"admin"',
        'site:{domain} inurl:auth',
    ],
    "Error & Debug Pages": [
        'site:{domain} intitle:"error" OR intitle:"exception"',
        'site:{domain} intext:"stack trace"',
        'site:{domain} intext:"debug" inurl:debug',
        'site:{domain} intitle:"404 Not Found"',
        'site:{domain} intitle:"500 Internal Server Error"',
        'site:{domain} intext:"PHP Error"',
        'site:{domain} intext:"Warning:" filetype:php',
    ],
    "Directory Listings": [
        'site:{domain} intitle:"index of /"',
        'site:{domain} intitle:"directory listing"',
        'site:{domain} intitle:"parent directory"',
    ],
    "Sensitive Information": [
        'site:{domain} intext:"password" filetype:log',
        'site:{domain} intext:"api_key" OR intext:"apikey"',
        'site:{domain} intext:"secret" filetype:json',
        'site:{domain} intext:"token" filetype:json',
        'site:{domain} inurl:config',
        'site:{domain} inurl:setup',
        'site:{domain} inurl:backup',
        'site:{domain} ext:env intext:"DB_PASSWORD"',
    ],
    "API Endpoints": [
        'site:{domain} inurl:api',
        'site:{domain} inurl:v1 OR inurl:v2 OR inurl:v3',
        'site:{domain} inurl:graphql',
        'site:{domain} inurl:swagger OR inurl:openapi',
        'site:{domain} inurl:rest',
        'site:{domain} filetype:json inurl:api',
    ],
}

# ─── Port Scanner ────────────────────────────────────────────────────
# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 27017
]

# ─── Content Discovery ────────────────────────────────────────────────
# Default wordlist for content discovery
CONTENT_DISCOVERY_WORDLIST = [
    "admin", "administrator", "api", "backup", "config", "dashboard",
    "debug", "dev", "files", "images", "img", "js", "login", "logs",
    "media", "private", "public", "robots.txt", "sitemap.xml", "src",
    "static", "stats", "status", "test", "tmp", "uploads", "web",
    ".env", ".git", ".git/HEAD", ".svn", ".vscode", "backup.sql",
    "backup.zip", "config.json", "config.xml", "database.sql",
    "debug.log", "dump.sql", "error_log", "id_rsa", "package.json",
    "server-status", "web.config", "wp-admin", "composer.json"
]

# ─── JS Analysis ──────────────────────────────────────────────────────
ENTROPY_THRESHOLD = 4.5
MAX_SEARCH_DEPTH = 2
