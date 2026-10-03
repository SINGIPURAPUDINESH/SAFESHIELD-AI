"""
SafeShield AI - Utility Functions

Reusable helper functions for:
- Text cleaning
- URL extraction
- Risk score formatting
- Safety recommendations
"""

import re
from typing import List, Dict


def clean_text(text: str) -> str:
    """
    Clean and normalize input text.

    Parameters
    ----------
    text : str
        Raw message text.

    Returns
    -------
    str
        Cleaned text.
    """
    if not isinstance(text, str):
        return ""

    # Convert to lowercase
    text = text.lower()

    # Remove extra whitespace
    text = re.sub(r"\s+", " ", text)

    # Remove leading/trailing whitespace
    text = text.strip()

    return text


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from a text message.

    This function only extracts URLs.
    It does NOT open or access them.

    Parameters
    ----------
    text : str
        Message containing possible URLs.

    Returns
    -------
    List[str]
        List of detected URLs.
    """
    if not isinstance(text, str):
        return []

    url_pattern = r"https?://[^\s<>\"]+|www\.[^\s<>\"]+"

    urls = re.findall(url_pattern, text, flags=re.IGNORECASE)

    # Remove common punctuation accidentally attached to URLs
    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,!?;:)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def get_risk_level(score: float) -> str:
    """
    Convert a numerical risk score into a risk category.

    Risk levels:
    0-29   -> LOW RISK
    30-59  -> SUSPICIOUS
    60-100 -> HIGH RISK

    Parameters
    ----------
    score : float
        Risk score between 0 and 100.

    Returns
    -------
    str
        Risk category.
    """
    score = max(0, min(100, float(score)))

    if score < 30:
        return "LOW RISK"

    elif score < 60:
        return "SUSPICIOUS"

    return "HIGH RISK"


def get_risk_emoji(risk_level: str) -> str:
    """
    Return an emoji corresponding to the risk level.

    Parameters
    ----------
    risk_level : str
        Risk category.

    Returns
    -------
    str
        Emoji.
    """
    risk_level = risk_level.upper()

    if risk_level == "LOW RISK":
        return "🟢"

    if risk_level == "SUSPICIOUS":
        return "🟠"

    if risk_level == "HIGH RISK":
        return "🔴"

    return "⚪"


def generate_recommendations(
    risk_level: str,
    has_url: bool = False,
    has_urgency: bool = False,
    requests_sensitive_info: bool = False,
) -> List[str]:
    """
    Generate safety recommendations based on detected risk signals.

    Parameters
    ----------
    risk_level : str
        Overall risk category.

    has_url : bool
        Whether a URL was detected.

    has_urgency : bool
        Whether urgency-related language was detected.

    requests_sensitive_info : bool
        Whether the message requests sensitive information.

    Returns
    -------
    List[str]
        Safety recommendations.
    """

    recommendations = []

    risk_level = risk_level.upper()

    if risk_level == "HIGH RISK":
        recommendations.append(
            "Do not click links or download attachments from this message."
        )

        recommendations.append(
            "Do not provide passwords, OTPs, banking information, "
            "or other sensitive information."
        )

        recommendations.append(
            "Verify the sender using an official website or trusted contact."
        )

    elif risk_level == "SUSPICIOUS":
        recommendations.append(
            "Treat the message cautiously and verify the sender independently."
        )

        recommendations.append(
            "Avoid clicking unfamiliar links or opening unexpected attachments."
        )

    else:
        recommendations.append(
            "No strong risk indicators were detected, but remain cautious."
        )

    if has_url:
        recommendations.append(
            "Review the URL carefully before visiting it."
        )

    if has_urgency:
        recommendations.append(
            "Be cautious of urgent or threatening requests that pressure you "
            "into immediate action."
        )

    if requests_sensitive_info:
        recommendations.append(
            "Never share passwords, OTPs, PINs, card numbers, or security codes "
            "through unsolicited messages."
        )

    # Remove duplicates while preserving order
    unique_recommendations = list(dict.fromkeys(recommendations))

    return unique_recommendations


def format_analysis_result(
    score: float,
    risk_level: str,
    explanations: List[str],
    recommendations: List[str],
) -> Dict:
    """
    Format the final SafeShield AI analysis result.

    Parameters
    ----------
    score : float
        Overall risk score.

    risk_level : str
        Risk category.

    explanations : List[str]
        Reasons contributing to the risk score.

    recommendations : List[str]
        Safety recommendations.

    Returns
    -------
    Dict
        Structured analysis result.
    """

    score = round(max(0, min(100, float(score))), 2)

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "emoji": get_risk_emoji(risk_level),
        "explanations": explanations,
        "recommendations": recommendations,
    }


def contains_sensitive_request(text: str) -> bool:
    """
    Detect whether a message appears to request sensitive information.

    This is a lexical check only.
    It does not attempt to identify actual credentials.

    Parameters
    ----------
    text : str
        Message text.

    Returns
    -------
    bool
        True if sensitive-information request patterns are detected.
    """

    if not isinstance(text, str):
        return False

    text = text.lower()

    sensitive_patterns = [
        r"\bpassword\b",
        r"\bpasswd\b",
        r"\botp\b",
        r"\bone[- ]time password\b",
        r"\bpin\b",
        r"\bcard number\b",
        r"\bcredit card\b",
        r"\bdebit card\b",
        r"\bcvv\b",
        r"\bsecurity code\b",
        r"\bbank account\b",
        r"\baccount number\b",
    ]

    return any(
        re.search(pattern, text, flags=re.IGNORECASE)
        for pattern in sensitive_patterns
    )


def contains_urgency(text: str) -> bool:
    """
    Detect common urgency or pressure language.

    Parameters
    ----------
    text : str
        Message text.

    Returns
    -------
    bool
        True if urgency indicators are detected.
    """

    if not isinstance(text, str):
        return False

    text = text.lower()

    urgency_patterns = [
        r"\bact now\b",
        r"\bimmediately\b",
        r"\burgent\b",
        r"\bexpires?\b",
        r"\bexpire\b",
        r"\blast chance\b",
        r"\bwithin \d+ (minutes?|hours?)\b",
        r"\baccount will be closed\b",
        r"\baccount will be blocked\b",
        r"\bverify now\b",
        r"\brespond immediately\b",
        r"\bfinal warning\b",
    ]

    return any(
        re.search(pattern, text, flags=re.IGNORECASE)
        for pattern in urgency_patterns
    )


def validate_score(score: float) -> float:
    """
    Ensure a risk score remains between 0 and 100.

    Parameters
    ----------
    score : float
        Risk score.

    Returns
    -------
    float
        Validated score.
    """

    try:
        score = float(score)
    except (TypeError, ValueError):
        return 0.0

    return round(max(0.0, min(100.0, score)), 2)