"""
SafeShield AI - URL Security Analyzer

Defensive URL analysis based on lexical and structural features.

IMPORTANT:
This module NEVER opens, requests, downloads, or connects to
the supplied URL.

It only analyzes the URL string itself.
"""

import ipaddress
import re
from urllib.parse import urlparse
from typing import Dict, List


# ============================================================
# Suspicious URL indicators
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "wallet",
    "payment",
    "bank",
    "signin",
    "unlock",
    "security",
    "recover",
    "claim",
    "reward",
    "bonus",
    "free",
]


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
}


SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".msi",
    ".vbs",
    ".js",
    ".jar",
    ".zip",
    ".rar",
]


class URLAnalyzer:
    """
    Analyze URLs without making network requests.

    The analyzer produces:
        - risk score
        - detected indicators
        - URL characteristics
        - recommendations
    """

    def __init__(self):
        self.suspicious_keywords = SUSPICIOUS_KEYWORDS
        self.shortener_domains = SHORTENER_DOMAINS
        self.suspicious_extensions = SUSPICIOUS_EXTENSIONS

    # ========================================================
    # URL Normalization
    # ========================================================

    def normalize_url(self, url: str) -> str:
        """
        Normalize a URL for analysis.

        If a scheme is missing, https:// is temporarily added
        for parsing purposes only.

        The URL is NEVER accessed.

        Parameters
        ----------
        url : str
            URL string.

        Returns
        -------
        str
            Normalized URL.
        """

        if not isinstance(url, str):
            return ""

        url = url.strip()

        if not url:
            return ""

        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            url,
        ):
            url = "https://" + url

        return url

    # ========================================================
    # IP Address Detection
    # ========================================================

    def is_ip_address(self, hostname: str) -> bool:
        """
        Check whether a hostname is an IP address.

        Parameters
        ----------
        hostname : str
            Domain/hostname.

        Returns
        -------
        bool
            True if hostname is an IP address.
        """

        if not hostname:
            return False

        try:
            ipaddress.ip_address(hostname)
            return True

        except ValueError:
            return False

    # ========================================================
    # URL Shortener Detection
    # ========================================================

    def is_shortened_url(self, hostname: str) -> bool:
        """
        Check whether hostname belongs to a known URL shortener.

        Parameters
        ----------
        hostname : str
            URL hostname.

        Returns
        -------
        bool
            True if known shortener.
        """

        if not hostname:
            return False

        hostname = hostname.lower()

        return (
            hostname in self.shortener_domains
            or any(
                hostname.endswith("." + domain)
                for domain in self.shortener_domains
            )
        )

    # ========================================================
    # Main Analysis
    # ========================================================

    def analyze(self, url: str) -> Dict:
        """
        Analyze a URL using lexical and structural features.

        NO network request is performed.

        Parameters
        ----------
        url : str
            URL to analyze.

        Returns
        -------
        dict
            URL security analysis.
        """

        if not isinstance(url, str) or not url.strip():
            return {
                "url": url,
                "valid": False,
                "risk_score": 0,
                "risk_level": "INVALID",
                "indicators": [
                    "No URL was provided."
                ],
                "features": {},
                "recommendations": [
                    "Provide a valid URL for analysis."
                ],
            }

        original_url = url.strip()

        normalized_url = self.normalize_url(
            original_url
        )

        try:
            parsed = urlparse(normalized_url)

        except Exception:
            return {
                "url": original_url,
                "valid": False,
                "risk_score": 0,
                "risk_level": "INVALID",
                "indicators": [
                    "The URL could not be parsed."
                ],
                "features": {},
                "recommendations": [
                    "Check the URL format."
                ],
            }

        hostname = parsed.hostname or ""

        hostname = hostname.lower()

        path = parsed.path or ""

        query = parsed.query or ""

        fragment = parsed.fragment or ""

        full_url_lower = normalized_url.lower()

        # ----------------------------------------------------
        # Basic features
        # ----------------------------------------------------

        url_length = len(original_url)

        has_https = parsed.scheme.lower() == "https"

        has_http = parsed.scheme.lower() == "http"

        has_at_symbol = "@" in original_url

        has_ip_address = self.is_ip_address(
            hostname
        )

        hostname_length = len(hostname)

        subdomain_count = max(
            hostname.count(".") - 1,
            0,
        )

        has_port = parsed.port is not None

        port = parsed.port

        has_fragment = bool(fragment)

        encoded_character_count = len(
            re.findall(
                r"%[0-9a-fA-F]{2}",
                original_url,
            )
        )

        hyphen_count = hostname.count("-")

        digit_count = sum(
            character.isdigit()
            for character in hostname
        )

        # ----------------------------------------------------
        # Suspicious keyword detection
        # ----------------------------------------------------

        detected_keywords = []

        for keyword in self.suspicious_keywords:

            if keyword in full_url_lower:
                detected_keywords.append(
                    keyword
                )

        # ----------------------------------------------------
        # URL shortener
        # ----------------------------------------------------

        is_shortener = self.is_shortened_url(
            hostname
        )

        # ----------------------------------------------------
        # Suspicious extension
        # ----------------------------------------------------

        detected_extensions = []

        for extension in self.suspicious_extensions:

            if path.lower().endswith(extension):
                detected_extensions.append(
                    extension
                )

        # ----------------------------------------------------
        # Suspicious TLD patterns
        # ----------------------------------------------------

        suspicious_tlds = {
            ".zip",
            ".mov",
            ".click",
            ".top",
            ".xyz",
            ".download",
            ".work",
            ".gq",
            ".tk",
            ".ml",
            ".cf",
        }

        detected_suspicious_tld = None

        for tld in suspicious_tlds:

            if hostname.endswith(tld):
                detected_suspicious_tld = tld
                break

        # ----------------------------------------------------
        # Calculate risk score
        # ----------------------------------------------------

        score = 0

        indicators: List[str] = []

        # URL length
        if url_length > 120:

            score += 10

            indicators.append(
                "The URL is unusually long."
            )

        elif url_length > 80:

            score += 5

            indicators.append(
                "The URL is relatively long."
            )

        # HTTP
        if has_http:

            score += 10

            indicators.append(
                "The URL uses HTTP instead of HTTPS."
            )

        # IP address
        if has_ip_address:

            score += 25

            indicators.append(
                "The hostname is an IP address rather than a domain name."
            )

        # @ symbol
        if has_at_symbol:

            score += 20

            indicators.append(
                "The URL contains an @ symbol, which can obscure the destination."
            )

        # Excessive subdomains
        if subdomain_count >= 4:

            score += 15

            indicators.append(
                "The URL contains an unusually high number of subdomains."
            )

        elif subdomain_count >= 3:

            score += 8

            indicators.append(
                "The URL contains multiple subdomains."
            )

        # Shortener
        if is_shortener:

            score += 15

            indicators.append(
                "The URL uses a known URL-shortening service."
            )

        # Suspicious keywords
        if detected_keywords:

            keyword_score = min(
                len(detected_keywords) * 4,
                20,
            )

            score += keyword_score

            indicators.append(
                "The URL contains potentially sensitive "
                "or action-oriented keywords: "
                + ", ".join(detected_keywords)
                + "."
            )

        # Suspicious extension
        if detected_extensions:

            score += 20

            indicators.append(
                "The URL points to a potentially executable "
                "or archive file type: "
                + ", ".join(detected_extensions)
                + "."
            )

        # Suspicious TLD
        if detected_suspicious_tld:

            score += 8

            indicators.append(
                "The domain uses a TLD frequently associated "
                "with suspicious links in this heuristic model: "
                + detected_suspicious_tld
                + "."
            )

        # Excessive encoding
        if encoded_character_count >= 8:

            score += 10

            indicators.append(
                "The URL contains many encoded characters."
            )

        elif encoded_character_count >= 4:

            score += 5

            indicators.append(
                "The URL contains several encoded characters."
            )

        # Excessive hostname hyphens
        if hyphen_count >= 4:

            score += 8

            indicators.append(
                "The hostname contains many hyphens."
            )

        # High digit ratio
        if (
            hostname_length >= 8
            and digit_count >= 5
        ):

            score += 8

            indicators.append(
                "The hostname contains an unusually high number of digits."
            )

        # Unusual port
        if has_port and port not in {
            80,
            443,
        }:

            score += 10

            indicators.append(
                f"The URL uses an uncommon port: {port}."
            )

        # Cap score
        score = min(
            max(score, 0),
            100,
        )

        # ----------------------------------------------------
        # Risk classification
        # ----------------------------------------------------

        if score < 30:

            risk_level = "LOW RISK"

        elif score < 60:

            risk_level = "SUSPICIOUS"

        else:

            risk_level = "HIGH RISK"

        # ----------------------------------------------------
        # Recommendations
        # ----------------------------------------------------

        recommendations = []

        if risk_level == "HIGH RISK":

            recommendations.extend(
                [
                    "Do not open this URL unless independently verified.",
                    "Verify the domain through an official source.",
                    "Do not enter passwords, OTPs, payment details, or other sensitive information.",
                ]
            )

        elif risk_level == "SUSPICIOUS":

            recommendations.extend(
                [
                    "Treat this URL cautiously.",
                    "Verify the destination domain independently before visiting.",
                    "Avoid entering sensitive information if the source is unexpected.",
                ]
            )

        else:

            recommendations.extend(
                [
                    "No strong lexical risk indicators were detected.",
                    "Still verify unexpected links before entering sensitive information.",
                ]
            )

        # Additional recommendation for shorteners
        if is_shortener:

            recommendations.append(
                "Shortened URLs hide the final destination, "
                "so verify the destination before opening."
            )

        # Additional recommendation for IP address
        if has_ip_address:

            recommendations.append(
                "Be cautious with links that use raw IP addresses "
                "instead of recognizable domains."
            )

        # Remove duplicate recommendations
        recommendations = list(
            dict.fromkeys(recommendations)
        )

        # ----------------------------------------------------
        # Feature dictionary
        # ----------------------------------------------------

        features = {
            "url_length": url_length,
            "hostname": hostname,
            "hostname_length": hostname_length,
            "scheme": parsed.scheme,
            "uses_https": has_https,
            "uses_http": has_http,
            "has_ip_address": has_ip_address,
            "has_at_symbol": has_at_symbol,
            "subdomain_count": subdomain_count,
            "has_port": has_port,
            "port": port,
            "has_fragment": has_fragment,
            "encoded_character_count": encoded_character_count,
            "hostname_hyphen_count": hyphen_count,
            "hostname_digit_count": digit_count,
            "is_shortened_url": is_shortener,
            "detected_keywords": detected_keywords,
            "detected_extensions": detected_extensions,
            "suspicious_tld": detected_suspicious_tld,
            "path": path,
            "query_present": bool(query),
        }

        # If there are no indicators, provide a clear message
        if not indicators:

            indicators.append(
                "No strong suspicious URL indicators were detected."
            )

        return {
            "url": original_url,
            "normalized_url": normalized_url,
            "valid": bool(hostname),
            "risk_score": score,
            "risk_level": risk_level,
            "indicators": indicators,
            "features": features,
            "recommendations": recommendations,
        }


# ============================================================
# Convenience function
# ============================================================

def analyze_url(url: str) -> Dict:
    """
    Convenience function for one-off URL analysis.

    Parameters
    ----------
    url : str
        URL to analyze.

    Returns
    -------
    dict
        Analysis result.
    """

    analyzer = URLAnalyzer()

    return analyzer.analyze(url)


# ============================================================
# Local testing
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("SafeShield AI - URL Analyzer")
    print("=" * 60)

    analyzer = URLAnalyzer()

    test_urls = [
        "https://www.google.com",
        "https://example.com/account",
        "http://192.168.1.50/login",
        "https://bit.ly/secure-account",
        "http://secure-login-verify-account.example.xyz/update",
        "https://example.com/download/file.exe",
    ]

    for url in test_urls:

        print("\n" + "-" * 60)

        result = analyzer.analyze(url)

        print(
            f"URL: {result['url']}"
        )

        print(
            f"Risk Score: "
            f"{result['risk_score']}/100"
        )

        print(
            f"Risk Level: "
            f"{result['risk_level']}"
        )

        print("\nIndicators:")

        for indicator in result["indicators"]:

            print(
                f"  - {indicator}"
            )

        print("\nRecommendations:")

        for recommendation in result[
            "recommendations"
        ]:

            print(
                f"  - {recommendation}"
            )

    print("\n" + "=" * 60)
    print("URL analyzer test completed.")
    print("=" * 60)