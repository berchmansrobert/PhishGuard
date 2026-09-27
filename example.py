from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
from urllib.parse import urlparse
from dotenv import load_dotenv
from datetime import datetime, timezone
import base64
import ipaddress
import os
import re
import socket
import ssl

import httpx


load_dotenv()

app = FastAPI(title="PhishGuard")


# ============================================================
# REQUEST MODEL
# ============================================================

class URLRequest(BaseModel):
    url: HttpUrl


# ============================================================
# DETECTION RULES
# ============================================================

SUSPICIOUS_URL_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "confirm",
    "bank",
    "wallet",
    "payment",
]

SUSPICIOUS_PAGE_PHRASES = [
    "verify your account",
    "confirm your identity",
    "your account has been suspended",
    "login to continue",
    "enter your password",
    "security verification",
]

KNOWN_BRANDS = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
]


# ============================================================
# GENERAL HELPERS
# ============================================================

def add_finding(findings, message, score):
    findings.append({
        "message": message,
        "score": score
    })


def get_hostname(url):
    return urlparse(url).hostname or ""


def get_registered_domain(host):
    parts = host.lower().rstrip(".").split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return host.lower()


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_private_ip(ip):
    try:
        parsed_ip = ipaddress.ip_address(ip)

        return (
            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_reserved
            or parsed_ip.is_multicast
        )

    except ValueError:
        return False


def is_private_or_internal(host):
    if not host:
        return True

    if host.lower() in {
        "localhost",
        "localhost.localdomain",
    }:
        return True

    if is_ip_address(host):
        return is_private_ip(host)

    return False


# ============================================================
# DNS / IP CHECK
# ============================================================

def dns_scan(host, findings):
    score = 0

    if not host:
        return score

    resolved_ips = []

    try:
        results = socket.getaddrinfo(
            host,
            None
        )

        for result in results:
            ip = result[4][0]

            if ip not in resolved_ips:
                resolved_ips.append(ip)

        for ip in resolved_ips:

            if is_private_ip(ip):

                score += 100

                add_finding(
                    findings,
                    "Domain resolves to a private or reserved IP address",
                    100
                )

                break

    except socket.gaierror:
        pass

    return score


# ============================================================
# DOMAIN AGE / RDAP
# ============================================================

def domain_age_scan(host, findings):

    if not host or is_ip_address(host):
        return 0, None, None

    domain = get_registered_domain(host)

    tld = domain.rsplit(".", 1)[-1].lower()

    try:

        with httpx.Client(
            timeout=8
        ) as client:

            # Get the authoritative RDAP server
            # from IANA bootstrap data.
            bootstrap = client.get(
                "https://data.iana.org/rdap/dns.json",
                headers={
                    "User-Agent": "PhishGuard/1.0"
                }
            )

            if bootstrap.status_code != 200:
                return 0, None, None

            bootstrap_data = bootstrap.json()

            rdap_base_url = None

            for service in bootstrap_data.get(
                "services",
                []
            ):

                tlds = service[0]
                urls = service[1]

                if tld in [
                    item.lower()
                    for item in tlds
                ]:

                    if urls:
                        rdap_base_url = urls[0]
                        break

            if not rdap_base_url:
                return 0, None, None

            rdap_url = (
                rdap_base_url.rstrip("/")
                + "/domain/"
                + domain
            )

            response = client.get(
                rdap_url,
                headers={
                    "User-Agent": "PhishGuard/1.0"
                }
            )

            if response.status_code != 200:
                return 0, None, None

            data = response.json()

        registration_date = None

        for event in data.get(
            "events",
            []
        ):

            if event.get(
                "eventAction"
            ) == "registration":

                registration_date = event.get(
                    "eventDate"
                )

                break

        if not registration_date:
            return 0, None, None

        original_date = registration_date

        registration_date = registration_date.replace(
            "Z",
            "+00:00"
        )

        registered_at = datetime.fromisoformat(
            registration_date
        )

        if registered_at.tzinfo is None:
            registered_at = registered_at.replace(
                tzinfo=timezone.utc
            )

        age_days = (
            datetime.now(timezone.utc)
            - registered_at
        ).days

        score = 0

        # Less than 30 days
        if age_days < 30:

            score = 10

            add_finding(
                findings,
                f"Domain was registered recently ({age_days} days ago)",
                10
            )

        # 30-90 days
        elif age_days < 90:

            score = 5

            add_finding(
                findings,
                f"Domain is relatively new ({age_days} days old)",
                5
            )

        # Older than 90 days = 0
        return (
            score,
            age_days,
            original_date
        )

    except (
        httpx.HTTPError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
    ):

        return 0, None, None


# ============================================================
# TLS CHECK
# ============================================================

def tls_scan(host, port):

    if not host:
        return

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ):
                pass

    except (
        ssl.SSLCertVerificationError,
        ssl.SSLError,
        OSError,
        socket.timeout,
    ):

        # TLS failures currently do not
        # increase the risk score.
        pass


# ============================================================
# REDIRECT CHECK
# ============================================================

def redirect_scan(
    url,
    original_host,
    findings
):

    score = 0

    try:

        with httpx.Client(
            timeout=5,
            follow_redirects=True,
            max_redirects=5,
            headers={
                "User-Agent": "PhishGuard/1.0"
            }
        ) as client:

            response = client.head(url)

            redirect_count = len(
                response.history
            )

            final_url = str(
                response.url
            )

            if redirect_count >= 3:

                score += 5

                add_finding(
                    findings,
                    "URL uses multiple redirects",
                    5
                )

            final_host = get_hostname(
                final_url
            )

            # Check the final redirected host for
            # private or internal addresses.
            if final_host:

                if is_private_or_internal(
                    final_host
                ):

                    score += 100

                    add_finding(
                        findings,
                        "Redirect ends at a private or internal address",
                        100
                    )

            if (
                final_host
                and get_registered_domain(
                    final_host
                )
                != get_registered_domain(
                    original_host
                )
            ):

                score += 10

                add_finding(
                    findings,
                    "Redirect ends on a different domain",
                    10
                )

    except httpx.HTTPError:
        pass

    return score


# ============================================================
# URL ANALYSIS
# ============================================================

def pre_website_scan(
    url,
    findings
):

    score = 0

    parsed = urlparse(url)

    host = parsed.hostname or ""

    # HTTPS
    if parsed.scheme != "https":

        score += 5

        add_finding(
            findings,
            "Website does not use HTTPS",
            5
        )

    # @ symbol
    if "@" in url:

        score += 10

        add_finding(
            findings,
            "URL contains an @ symbol",
            10
        )

    # Long URL
    if len(url) > 150:

        score += 5

        add_finding(
            findings,
            "URL is unusually long",
            5
        )

    # IP address
    if is_ip_address(host):

        score += 10

        add_finding(
            findings,
            "URL uses an IP address instead of a domain",
            10
        )

    # Punycode
    if "xn--" in host.lower():

        score += 10

        add_finding(
            findings,
            "Domain uses punycode",
            10
        )

    # Too many subdomains
    parts = host.split(".")

    subdomain_count = max(
        len(parts) - 2,
        0
    )

    if subdomain_count >= 4:

        score += 5

        add_finding(
            findings,
            "Domain has many subdomains",
            5
        )

    # Suspicious URL words
    found_words = [
        word
        for word in SUSPICIOUS_URL_WORDS
        if word in url.lower()
    ]

    if found_words:

        word_score = min(
            len(found_words) * 3,
            9
        )

        score += word_score

        add_finding(
            findings,
            "URL contains suspicious security-related words",
            word_score
        )

    # Brand impersonation
    registered = get_registered_domain(
        host
    )

    for brand in KNOWN_BRANDS:

        if (
            brand in host.lower()
            and brand not in registered
        ):

            score += 8

            add_finding(
                findings,
                f"Possible {brand} domain impersonation",
                8
            )

    # DNS
    score += dns_scan(
        host,
        findings
    )

    # TLS
    if parsed.scheme == "https":

        tls_scan(
            host,
            parsed.port or 443
        )

    # Redirects
    score += redirect_scan(
        url,
        host,
        findings
    )

    return score


# ============================================================
# VIRUSTOTAL
# ============================================================

def virustotal_scan(
    url,
    findings
):

    api_key = os.getenv(
        "VIRUSTOTAL_API_KEY"
    )

    if not api_key:
        return 0

    try:

        url_id = (
            base64.urlsafe_b64encode(
                url.encode()
            )
            .decode()
            .strip("=")
        )

        endpoint = (
            "https://www.virustotal.com/api/v3/urls/"
            + url_id
        )

        with httpx.Client(
            timeout=10
        ) as client:

            response = client.get(
                endpoint,
                headers={
                    "x-apikey": api_key
                }
            )

        if response.status_code == 404:
            return 0

        if response.status_code == 429:

            add_finding(
                findings,
                "VirusTotal rate limit reached",
                0
            )

            return 0

        if response.status_code != 200:
            return 0

        data = response.json()

        stats = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        if malicious > 0:

            reputation_score = min(
                malicious * 5,
                25
            )

            add_finding(
                findings,
                f"VirusTotal: {malicious} security engines flagged this URL as malicious",
                reputation_score
            )

            return reputation_score

        if suspicious > 0:

            reputation_score = min(
                suspicious * 2,
                10
            )

            add_finding(
                findings,
                f"VirusTotal: {suspicious} security engines flagged this URL as suspicious",
                reputation_score
            )

            return reputation_score

    except (
        httpx.HTTPError,
        ValueError,
        KeyError,
        TypeError,
    ):

        pass

    return 0


# ============================================================
# WEBPAGE ANALYSIS
# ============================================================

def webpage_scan(
    html,
    original_host,
    findings
):

    score = 0

    html_lower = html.lower()

    # Password field
    password_form = re.search(
        r'<input[^>]+type\s*=\s*["\']password["\']',
        html_lower
    )

    if password_form:

        score += 10

        add_finding(
            findings,
            "Page contains a password input",
            10
        )

    # Suspicious phrases
    found_phrases = [
        phrase
        for phrase in SUSPICIOUS_PAGE_PHRASES
        if phrase in html_lower
    ]

    if found_phrases:

        phrase_score = min(
            len(found_phrases) * 3,
            9
        )

        score += phrase_score

        add_finding(
            findings,
            "Page contains suspicious account/security phrases",
            phrase_score
        )

    # External form destination
    forms = re.findall(
        r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']',
        html,
        re.IGNORECASE
    )

    original_domain = get_registered_domain(
        original_host
    )

    for action in forms:

        if action.startswith(
            (
                "http://",
                "https://"
            )
        ):

            form_host = get_hostname(
                action
            )

            if (
                form_host
                and get_registered_domain(
                    form_host
                )
                != original_domain
            ):

                score += 10

                add_finding(
                    findings,
                    "Form sends information to another domain",
                    10
                )

                break

    return score


# ============================================================
# FINAL DECISION
# ============================================================

def calculate_decision(score):

    if score >= 31:
        return (
            "high-risk",
            "block"
        )

    if score >= 10:
        return (
            "medium-risk",
            "ask_user"
        )

    return (
        "low-risk",
        "allow"
    )


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "message": "PhishGuard is running"
    }


# ============================================================
# CHECK URL
# ============================================================

@app.post("/check-url")
def check_url(
    request: URLRequest
):

    url = str(request.url)

    host = get_hostname(
        url
    )

    # ----------------------------------------
    # Block obvious internal targets
    # ----------------------------------------

    if is_private_or_internal(host):

        return {
            "url": url,
            "risk_score": 100,
            "risk_level": "high-risk",
            "action": "block",
            "website_fetched": False,
            "domain_age_days": None,
            "domain_registered": None,
            "findings": [
                "Private or internal address blocked"
            ]
        }

    findings = []

    # ----------------------------------------
    # Block domains resolving to private IPs
    # ----------------------------------------

    resolved_ips = []

    try:
        results = socket.getaddrinfo(
            host,
            None
        )

        for result in results:
            ip = result[4][0]

            if ip not in resolved_ips:
                resolved_ips.append(ip)

        for ip in resolved_ips:

            if is_private_ip(ip):

                return {
                    "url": url,
                    "risk_score": 100,
                    "risk_level": "high-risk",
                    "action": "block",
                    "website_fetched": False,
                    "domain_age_days": None,
                    "domain_registered": None,
                    "findings": [
                        "Domain resolves to a private or reserved IP address"
                    ]
                }

    except socket.gaierror:
        pass

    # ----------------------------------------
    # Stage 1
    # ----------------------------------------

    pre_score = pre_website_scan(
        url,
        findings
    )

    # ----------------------------------------
    # Domain age
    # ----------------------------------------

    (
        age_score,
        domain_age_days,
        domain_registered
    ) = domain_age_scan(
        host,
        findings
    )

    # ----------------------------------------
    # VirusTotal
    # ----------------------------------------

    reputation_score = virustotal_scan(
        url,
        findings
    )

    # ----------------------------------------
    # Total pre-website score
    # ----------------------------------------

    pre_score += (
        age_score
        + reputation_score
    )

    pre_level, pre_action = (
        calculate_decision(
            pre_score
        )
    )

    # ----------------------------------------
    # Block before webpage download
    # ----------------------------------------

    if pre_level == "high-risk":

        return {
            "url": url,
            "risk_score": pre_score,
            "risk_level": pre_level,
            "action": pre_action,
            "website_fetched": False,
            "domain_age_days": domain_age_days,
            "domain_registered": domain_registered,
            "findings": [
                item["message"]
                for item in findings
            ][:5]
        }

    # ----------------------------------------
    # Stage 2
    # ----------------------------------------

    webpage_score = 0

    website_fetched = False

    try:

        with httpx.Client(
            timeout=5,
            follow_redirects=True,
            max_redirects=5,
            headers={
                "User-Agent": "PhishGuard/1.0"
            }
        ) as client:

            response = client.get(
                url
            )

            website_fetched = True

            # Safe download detection:
            # inspect response headers only.
            content_type = response.headers.get(
                "content-type",
                ""
            ).lower()

            content_disposition = response.headers.get(
                "content-disposition",
                ""
            ).lower()

            suspicious_file_types = (
                ".exe",
                ".msi",
                ".apk",
                ".dmg",
                ".scr",
                ".bat",
                ".cmd",
                ".com",
                ".jar"
            )

            download_detected = (
                "attachment" in content_disposition
                or any(
                    file_type in content_disposition
                    for file_type in suspicious_file_types
                )
                or "application/x-msdownload" in content_type
                or "application/vnd.android.package-archive" in content_type
                or "application/x-msdos-program" in content_type
            )

            if download_detected:

                add_finding(
                    findings,
                    "Website response indicates a downloadable file",
                    5
                )

                webpage_score += 5

            webpage_score += webpage_scan(
                response.text,
                host,
                findings
            )

    except httpx.HTTPError:
        pass

    # ----------------------------------------
    # Final score
    # ----------------------------------------

    final_score = (
        pre_score
        + webpage_score
    )

    level, action = (
        calculate_decision(
            final_score
        )
    )

    # ----------------------------------------
    # Response
    # ----------------------------------------

    return {
        "url": url,
        "risk_score": final_score,
        "risk_level": level,
        "action": action,
        "website_fetched": website_fetched,
        "domain_age_days": domain_age_days,
        "domain_registered": domain_registered,
        "findings": [
            item["message"]
            for item in findings
        ][:5]
    }
