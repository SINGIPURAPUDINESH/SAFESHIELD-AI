"""
SafeShield AI - Risk Engine

Combines:
    - NLP message classification
    - URL lexical analysis
    - Urgency detection
    - Sensitive-information detection

Produces:
    - Overall risk score
    - Risk level
    - Explainable indicators
    - Safety recommendations

This module is designed for defensive cybersecurity analysis.
It does not open URLs or interact with external systems.
"""

from typing import Dict, List, Optional

from src.text_detector import TextDetector
from src.url_analyzer import URLAnalyzer
from src.utils import (
    clean_text,
    contains_sensitive_request,
    contains_urgency,
    extract_urls,
    generate_recommendations,
    get_risk_level,
)


class RiskEngine:
    """
    Main SafeShield AI risk assessment engine.

    The engine combines multiple independent signals
    rather than relying on a single classifier.
    """

    def __init__(
        self,
        text_detector: Optional[TextDetector] = None,
        url_analyzer: Optional[URLAnalyzer] = None,
    ):
        """
        Initialize the risk engine.

        Parameters
        ----------
        text_detector : TextDetector, optional
            Trained text classification model.

        url_analyzer : URLAnalyzer, optional
            URL lexical analyzer.
        """

        self.text_detector = (
            text_detector
            if text_detector is not None
            else TextDetector()
        )

        self.url_analyzer = (
            url_analyzer
            if url_analyzer is not None
            else URLAnalyzer()
        )

    # ========================================================
    # Model Initialization
    # ========================================================

    def ensure_text_model(
        self,
        model_path: str = "models/text_detector.joblib",
    ) -> None:
        """
        Load an existing text model if available.

        If no saved model exists, train the default model.

        Parameters
        ----------
        model_path : str
            Path to saved text model.
        """

        try:

            self.text_detector.load(
                model_path
            )

        except FileNotFoundError:

            self.text_detector.train()

    # ========================================================
    # Main Analysis
    # ========================================================

    def analyze(
        self,
        message: str,
        model_path: str = "models/text_detector.joblib",
    ) -> Dict:
        """
        Analyze a complete message.

        Parameters
        ----------
        message : str
            Message to analyze.

        model_path : str
            Path to trained text model.

        Returns
        -------
        dict
            Complete SafeShield AI analysis.
        """

        if not isinstance(message, str):
            raise ValueError(
                "Message must be a string."
            )

        message = message.strip()

        if not message:
            raise ValueError(
                "Message cannot be empty."
            )

        # ----------------------------------------------------
        # Ensure ML model is available
        # ----------------------------------------------------

        self.ensure_text_model(
            model_path
        )

        # ----------------------------------------------------
        # Clean text
        # ----------------------------------------------------

        cleaned_message = clean_text(
            message
        )

        # ----------------------------------------------------
        # Text ML prediction
        # ----------------------------------------------------

        text_result = self.text_detector.predict(
            cleaned_message
        )

        suspicious_probability = (
            text_result[
                "suspicious_probability"
            ]
        )

        text_score = (
            suspicious_probability * 100
        )

        # ----------------------------------------------------
        # Extract URLs
        # ----------------------------------------------------

        urls = extract_urls(
            message
        )

        url_results = []

        for url in urls:

            result = self.url_analyzer.analyze(
                url
            )

            url_results.append(
                result
            )

        # ----------------------------------------------------
        # URL risk score
        # ----------------------------------------------------

        if url_results:

            url_scores = [
                result["risk_score"]
                for result in url_results
            ]

            # Use highest-risk URL because one dangerous
            # URL can be enough to make a message dangerous.
            url_score = max(
                url_scores
            )

        else:

            url_score = 0.0

        # ----------------------------------------------------
        # Message heuristics
        # ----------------------------------------------------

        urgency_detected = contains_urgency(
            message
        )

        sensitive_request_detected = (
            contains_sensitive_request(
                message
            )
        )

        # ----------------------------------------------------
        # Calculate heuristic score
        # ----------------------------------------------------

        heuristic_score = 0.0

        heuristic_indicators: List[str] = []

        if urgency_detected:

            heuristic_score += 15

            heuristic_indicators.append(
                "The message uses urgent or pressure-based language."
            )

        if sensitive_request_detected:

            heuristic_score += 25

            heuristic_indicators.append(
                "The message appears to request sensitive information."
            )

        # Multiple URLs can increase complexity/risk
        if len(urls) >= 3:

            heuristic_score += 10

            heuristic_indicators.append(
                "The message contains multiple URLs."
            )

        # ----------------------------------------------------
        # Cap heuristic score
        # ----------------------------------------------------

        heuristic_score = min(
            heuristic_score,
            40,
        )

        # ----------------------------------------------------
        # Combine signals
        # ----------------------------------------------------
        #
        # Text ML       = 50%
        # URL analysis  = 30%
        # Heuristics    = 20%
        #
        # If no URL exists, redistribute URL weight
        # to text + heuristics.
        # ----------------------------------------------------

        if url_results:

            final_score = (
                (text_score * 0.50)
                + (url_score * 0.30)
                + (heuristic_score * 0.20)
            )

        else:

            final_score = (
                (text_score * 0.70)
                + (heuristic_score * 0.30)
            )

        # ----------------------------------------------------
        # Additional safety boost
        # ----------------------------------------------------
        #
        # A message containing BOTH:
        #   - sensitive request
        #   - suspicious URL
        #
        # gets a small additional risk adjustment.
        # ----------------------------------------------------

        if (
            sensitive_request_detected
            and url_score >= 30
        ):

            final_score += 10

        # ----------------------------------------------------
        # Another adjustment for highly suspicious URL
        # ----------------------------------------------------

        if url_score >= 75:

            final_score += 8

        # ----------------------------------------------------
        # Ensure valid range
        # ----------------------------------------------------

        final_score = max(
            0,
            min(
                100,
                final_score,
            ),
        )

        final_score = round(
            final_score,
            2,
        )

        # ----------------------------------------------------
        # Risk level
        # ----------------------------------------------------

        risk_level = get_risk_level(
            final_score
        )

        # ----------------------------------------------------
        # Explainable indicators
        # ----------------------------------------------------

        explanations: List[str] = []

        # ML explanation
        if suspicious_probability >= 0.75:

            explanations.append(
                "The NLP model identified strong suspicious-message patterns."
            )

        elif suspicious_probability >= 0.50:

            explanations.append(
                "The NLP model detected several suspicious language patterns."
            )

        else:

            explanations.append(
                "The NLP model did not identify strong suspicious-message patterns."
            )

        # URL explanations
        for result in url_results:

            for indicator in result[
                "indicators"
            ]:

                if indicator not in explanations:

                    explanations.append(
                        indicator
                    )

        # Heuristic explanations
        for indicator in heuristic_indicators:

            if indicator not in explanations:

                explanations.append(
                    indicator
                )

        # If no URL
        if not urls:

            explanations.append(
                "No URL was detected in the message."
            )

        # ----------------------------------------------------
        # Recommendations
        # ----------------------------------------------------

        recommendations = generate_recommendations(
            risk_level=risk_level,
            has_url=bool(urls),
            has_urgency=urgency_detected,
            requests_sensitive_info=sensitive_request_detected,
        )

        # ----------------------------------------------------
        # Build final result
        # ----------------------------------------------------

        return {
            "message": message,

            "risk_score": final_score,

            "risk_level": risk_level,

            "text_analysis": {
                "prediction": text_result[
                    "label"
                ],
                "suspicious_probability": round(
                    suspicious_probability,
                    4,
                ),
                "legitimate_probability": round(
                    text_result[
                        "legitimate_probability"
                    ],
                    4,
                ),
                "score": round(
                    text_score,
                    2,
                ),
            },

            "url_analysis": {
                "url_count": len(urls),
                "highest_url_score": round(
                    url_score,
                    2,
                ),
                "urls": url_results,
            },

            "heuristics": {
                "urgency_detected": urgency_detected,
                "sensitive_request_detected": (
                    sensitive_request_detected
                ),
                "multiple_urls": len(urls) >= 3,
                "score": round(
                    heuristic_score,
                    2,
                ),
            },

            "explanations": explanations,

            "recommendations": recommendations,
        }

    # ========================================================
    # Batch Analysis
    # ========================================================

    def analyze_batch(
        self,
        messages: List[str],
        model_path: str = "models/text_detector.joblib",
    ) -> List[Dict]:
        """
        Analyze multiple messages.

        Parameters
        ----------
        messages : list
            Messages to analyze.

        model_path : str
            Text model path.

        Returns
        -------
        list
            Analysis results.
        """

        if not messages:

            return []

        results = []

        for message in messages:

            try:

                result = self.analyze(
                    message=message,
                    model_path=model_path,
                )

                results.append(
                    result
                )

            except Exception as error:

                results.append(
                    {
                        "message": message,
                        "error": str(error),
                    }
                )

        return results


# ============================================================
# Convenience function
# ============================================================

def analyze_message(
    message: str,
    model_path: str = "models/text_detector.joblib",
) -> Dict:
    """
    Convenience function for analyzing one message.

    Parameters
    ----------
    message : str
        Message to analyze.

    model_path : str
        Text model path.

    Returns
    -------
    dict
        SafeShield AI result.
    """

    engine = RiskEngine()

    return engine.analyze(
        message=message,
        model_path=model_path,
    )


# ============================================================
# Local testing
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("SafeShield AI - Risk Engine")
    print("=" * 70)

    engine = RiskEngine()

    test_messages = [

        # Legitimate
        (
            "Your package has been delivered successfully. "
            "Thank you for shopping with us."
        ),

        # Suspicious text
        (
            "URGENT! Your account will be blocked. "
            "Verify your password immediately."
        ),

        # Suspicious URL
        (
            "Security alert! Verify your account now at "
            "http://192.168.1.50/login"
        ),

        # High-risk combination
        (
            "FINAL WARNING! Your bank account will be "
            "blocked today. Verify your OTP and password "
            "immediately at http://192.168.1.50/verify"
        ),
    ]

    for number, message in enumerate(
        test_messages,
        start=1,
    ):

        print("\n" + "-" * 70)

        print(
            f"TEST MESSAGE #{number}"
        )

        print("-" * 70)

        print(
            f"\nMessage:\n{message}"
        )

        result = engine.analyze(
            message
        )

        print(
            f"\nRisk Score: "
            f"{result['risk_score']}/100"
        )

        print(
            f"Risk Level: "
            f"{result['risk_level']}"
        )

        print("\nText Analysis:")

        print(
            f"  Prediction: "
            f"{result['text_analysis']['prediction']}"
        )

        print(
            f"  Suspicious Probability: "
            f"{result['text_analysis']['suspicious_probability']:.2%}"
        )

        print("\nURL Analysis:")

        print(
            f"  URLs detected: "
            f"{result['url_analysis']['url_count']}"
        )

        print(
            f"  Highest URL score: "
            f"{result['url_analysis']['highest_url_score']}/100"
        )

        print("\nHeuristics:")

        print(
            f"  Urgency detected: "
            f"{result['heuristics']['urgency_detected']}"
        )

        print(
            f"  Sensitive request: "
            f"{result['heuristics']['sensitive_request_detected']}"
        )

        print("\nWhy was this score assigned?")

        for explanation in result[
            "explanations"
        ]:

            print(
                f"  - {explanation}"
            )

        print("\nSafety Recommendations:")

        for recommendation in result[
            "recommendations"
        ]:

            print(
                f"  - {recommendation}"
            )

    print("\n" + "=" * 70)
    print("Risk engine test completed.")
    print("=" * 70)