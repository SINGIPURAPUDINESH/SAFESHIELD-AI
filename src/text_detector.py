"""
SafeShield AI - Text Detection Module

Machine-learning based detector for suspicious messages.

Model:
    TF-IDF Vectorizer + Logistic Regression

Labels:
    0 = Legitimate
    1 = Suspicious

The module is designed for defensive cybersecurity analysis.
It does not open links, execute attachments, or interact with
external websites.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# ============================================================
# Default training dataset
# ============================================================

DEFAULT_MESSAGES: List[str] = [
    # -------------------------
    # Legitimate messages
    # -------------------------
    "Your order has been shipped and will arrive tomorrow.",
    "Your appointment is confirmed for Monday at 10 AM.",
    "Your monthly electricity bill is ready to view.",
    "Your college class has been rescheduled to 2 PM.",
    "Your package has been delivered to the registered address.",
    "Your bank statement is available in your official banking app.",
    "Your meeting is scheduled for tomorrow afternoon.",
    "Your subscription has been renewed successfully.",
    "Thank you for attending today's workshop.",
    "Your flight booking confirmation has been sent to your email.",
    "Your payment was successfully completed.",
    "Your application has been received successfully.",
    "The project meeting will start at 11 AM.",
    "Your library book is due next week.",
    "Your food delivery is on the way.",
    "Your exam timetable has been published.",
    "Your account settings were updated successfully.",
    "Your service request has been registered.",
    "Your reservation has been confirmed.",
    "The report has been uploaded to the shared folder.",

    # -------------------------
    # Suspicious messages
    # -------------------------
    "Urgent! Your account will be blocked. Verify your password immediately.",
    "Congratulations! You won a cash prize. Claim your reward now.",
    "Your bank account has been suspended. Send your OTP to restore access.",
    "Final warning! Your account will be closed unless you verify now.",
    "You have been selected for a free gift. Claim it immediately.",
    "Your payment failed. Confirm your card number and CVV now.",
    "Security alert! Login immediately to prevent account closure.",
    "You won a lottery prize. Pay a small fee to receive your money.",
    "Your package is waiting. Confirm your details immediately.",
    "Act now or your account will be permanently disabled.",
    "Your password has expired. Verify your credentials immediately.",
    "You have an unpaid invoice. Pay now to avoid legal action.",
    "Congratulations winner! Send your bank details to receive the prize.",
    "Your account has suspicious activity. Provide your OTP for verification.",
    "Important warning! Your service will be terminated today.",
    "Claim your exclusive reward before the offer expires.",
    "Urgent payment required. Send your card details immediately.",
    "Your account will be blocked within 24 hours. Verify now.",
    "You are eligible for a special cash reward. Claim immediately.",
    "Final notice! Confirm your banking information to avoid suspension.",
]

# Corresponding labels:
# 0 = legitimate
# 1 = suspicious
DEFAULT_LABELS: List[int] = [
    # Legitimate = 20
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,

    # Suspicious = 20
    1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,
]


class TextDetector:
    """
    Machine-learning based suspicious message detector.

    Uses a scikit-learn Pipeline:

        TfidfVectorizer
                ↓
        LogisticRegression

    The model predicts whether a message is legitimate
    or suspicious.
    """

    def __init__(
        self,
        max_features: int = 5000,
        ngram_range: Tuple[int, int] = (1, 2),
    ):
        """
        Initialize the detector.

        Parameters
        ----------
        max_features : int
            Maximum number of TF-IDF features.

        ngram_range : tuple
            Range of n-grams used by TF-IDF.
        """

        self.max_features = max_features
        self.ngram_range = ngram_range

        self.pipeline = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        lowercase=True,
                        stop_words="english",
                        max_features=max_features,
                        ngram_range=ngram_range,
                        sublinear_tf=True,
                    ),
                ),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=1000,
                        class_weight="balanced",
                        random_state=42,
                    ),
                ),
            ]
        )

        self.is_trained = False

    # ========================================================
    # Training
    # ========================================================

    def train(
        self,
        messages: Optional[List[str]] = None,
        labels: Optional[List[int]] = None,
        test_size: float = 0.25,
    ) -> Dict:
        """
        Train the text classification model.

        Parameters
        ----------
        messages : list, optional
            Training messages.

        labels : list, optional
            Corresponding labels.

        test_size : float
            Percentage of data reserved for testing.

        Returns
        -------
        dict
            Training and evaluation metrics.
        """

        if messages is None:
            messages = DEFAULT_MESSAGES

        if labels is None:
            labels = DEFAULT_LABELS

        if len(messages) != len(labels):
            raise ValueError(
                "The number of messages must match the number of labels."
            )

        if len(messages) < 10:
            raise ValueError(
                "At least 10 training examples are recommended."
            )

        X_train, X_test, y_train, y_test = train_test_split(
            messages,
            labels,
            test_size=test_size,
            random_state=42,
            stratify=labels,
        )

        self.pipeline.fit(X_train, y_train)

        predictions = self.pipeline.predict(X_test)

        accuracy = accuracy_score(y_test, predictions)

        report = classification_report(
            y_test,
            predictions,
            target_names=["Legitimate", "Suspicious"],
            output_dict=True,
            zero_division=0,
        )

        matrix = confusion_matrix(y_test, predictions)

        self.is_trained = True

        return {
            "accuracy": float(accuracy),
            "classification_report": report,
            "confusion_matrix": matrix.tolist(),
            "training_samples": len(X_train),
            "testing_samples": len(X_test),
        }

    # ========================================================
    # Prediction
    # ========================================================

    def predict(self, message: str) -> Dict:
        """
        Analyze one message.

        Parameters
        ----------
        message : str
            Message to analyze.

        Returns
        -------
        dict
            Prediction result.
        """

        if not self.is_trained:
            raise RuntimeError(
                "The model has not been trained. "
                "Call train() or load() first."
            )

        if not isinstance(message, str) or not message.strip():
            raise ValueError("Message must be a non-empty string.")

        prediction = int(self.pipeline.predict([message])[0])

        probabilities = self.pipeline.predict_proba([message])[0]

        # Probability for suspicious class
        suspicious_probability = float(probabilities[1])

        # Probability for legitimate class
        legitimate_probability = float(probabilities[0])

        if prediction == 1:
            label = "Suspicious"
        else:
            label = "Legitimate"

        return {
            "prediction": prediction,
            "label": label,
            "suspicious_probability": round(
                suspicious_probability,
                4,
            ),
            "legitimate_probability": round(
                legitimate_probability,
                4,
            ),
        }

    # ========================================================
    # Batch Prediction
    # ========================================================

    def predict_batch(
        self,
        messages: List[str],
    ) -> List[Dict]:
        """
        Analyze multiple messages.

        Parameters
        ----------
        messages : list
            Messages to analyze.

        Returns
        -------
        list
            Prediction results.
        """

        if not self.is_trained:
            raise RuntimeError(
                "The model has not been trained."
            )

        if not messages:
            return []

        predictions = self.pipeline.predict(messages)
        probabilities = self.pipeline.predict_proba(messages)

        results = []

        for index, prediction in enumerate(predictions):

            suspicious_probability = float(
                probabilities[index][1]
            )

            legitimate_probability = float(
                probabilities[index][0]
            )

            label = (
                "Suspicious"
                if int(prediction) == 1
                else "Legitimate"
            )

            results.append(
                {
                    "message": messages[index],
                    "prediction": int(prediction),
                    "label": label,
                    "suspicious_probability": round(
                        suspicious_probability,
                        4,
                    ),
                    "legitimate_probability": round(
                        legitimate_probability,
                        4,
                    ),
                }
            )

        return results

    # ========================================================
    # Model Explanation
    # ========================================================

    def get_top_features(
        self,
        n: int = 15,
    ) -> Dict[str, List[Tuple[str, float]]]:
        """
        Return important TF-IDF features associated with
        legitimate and suspicious classifications.

        Parameters
        ----------
        n : int
            Number of features to return.

        Returns
        -------
        dict
            Top suspicious and legitimate features.
        """

        if not self.is_trained:
            raise RuntimeError(
                "The model has not been trained."
            )

        vectorizer = self.pipeline.named_steps["tfidf"]
        classifier = self.pipeline.named_steps["classifier"]

        feature_names = vectorizer.get_feature_names_out()

        coefficients = classifier.coef_[0]

        # High positive coefficient -> suspicious
        suspicious_indices = np.argsort(coefficients)[-n:][::-1]

        # High negative coefficient -> legitimate
        legitimate_indices = np.argsort(coefficients)[:n]

        suspicious_features = [
            (
                feature_names[index],
                float(coefficients[index]),
            )
            for index in suspicious_indices
        ]

        legitimate_features = [
            (
                feature_names[index],
                float(coefficients[index]),
            )
            for index in legitimate_indices
        ]

        return {
            "suspicious": suspicious_features,
            "legitimate": legitimate_features,
        }

    # ========================================================
    # Save Model
    # ========================================================

    def save(self, filepath: str = "models/text_detector.joblib"):
        """
        Save the trained model to disk.

        Parameters
        ----------
        filepath : str
            Destination model path.
        """

        if not self.is_trained:
            raise RuntimeError(
                "Cannot save an untrained model."
            )

        path = Path(filepath)

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        joblib.dump(
            self.pipeline,
            path,
        )

    # ========================================================
    # Load Model
    # ========================================================

    def load(
        self,
        filepath: str = "models/text_detector.joblib",
    ):
        """
        Load a previously trained model.

        Parameters
        ----------
        filepath : str
            Saved model path.
        """

        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(
                f"Model file not found: {path}"
            )

        self.pipeline = joblib.load(path)

        self.is_trained = True

        return self


# ============================================================
# Standalone helper
# ============================================================

def train_default_model(
    filepath: str = "models/text_detector.joblib",
) -> Dict:
    """
    Train and save the default SafeShield text detector.

    Parameters
    ----------
    filepath : str
        Destination model path.

    Returns
    -------
    dict
        Training metrics.
    """

    detector = TextDetector()

    metrics = detector.train()

    detector.save(filepath)

    return metrics


# ============================================================
# Local testing
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("SafeShield AI - Text Detector")
    print("=" * 60)

    detector = TextDetector()

    print("\nTraining model...")

    metrics = detector.train()

    print(
        f"\nAccuracy: "
        f"{metrics['accuracy']:.2%}"
    )

    print(
        f"Training samples: "
        f"{metrics['training_samples']}"
    )

    print(
        f"Testing samples: "
        f"{metrics['testing_samples']}"
    )

    # Test messages
    test_messages = [
        "Your package has been delivered successfully.",
        "Urgent! Verify your OTP immediately or your account will be blocked.",
        "Your meeting is scheduled for tomorrow at 10 AM.",
        "Congratulations! You won a cash prize. Claim it now.",
    ]

    print("\nTesting sample messages:")

    for message in test_messages:

        result = detector.predict(message)

        print("\nMessage:")
        print(message)

        print(
            f"Prediction: {result['label']}"
        )

        print(
            f"Suspicious probability: "
            f"{result['suspicious_probability']:.2%}"
        )

    print("\nSaving model...")

    detector.save(
        "models/text_detector.joblib"
    )

    print(
        "\nModel saved successfully to:"
    )

    print(
        "models/text_detector.joblib"
    )

    print("\nTop model features:")

    features = detector.get_top_features(n=10)

    print("\nSuspicious indicators:")

    for feature, coefficient in features["suspicious"]:
        print(
            f"  {feature:<25} "
            f"{coefficient:.4f}"
        )

    print("\nLegitimate indicators:")

    for feature, coefficient in features["legitimate"]:
        print(
            f"  {feature:<25} "
            f"{coefficient:.4f}"
        )

    print("\n" + "=" * 60)
    print("Text detector test completed.")
    print("=" * 60)