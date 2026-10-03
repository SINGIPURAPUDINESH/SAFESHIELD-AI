# SafeShield AI — Hackathon Demo Script

## Project

SafeShield AI

## Problem Statement

Digital scams and phishing messages are becoming increasingly difficult
for users to identify.

SafeShield AI provides a defensive AI-based solution that analyzes
suspicious messages and URLs without opening or interacting with the
submitted URLs.

---

# Demo Duration

Approximately 3 minutes.

---

# Scene 1 — Introduction

Time: 0:00–0:25

Say:

"Hello, I'm Singipurapu Dinesh, and this is SafeShield AI.

SafeShield AI is a defensive cybersecurity system designed to help
users identify potentially dangerous phishing and scam messages.

The system combines Natural Language Processing, machine learning,
URL analysis, and security heuristics to produce an explainable
cybersecurity risk score."

Show:

- SafeShield AI application
- Project title
- Problem statement

---

# Scene 2 — Normal Message

Time: 0:25–0:50

Enter:

Your package has been delivered successfully.
Thank you for shopping with us.

Click:

Analyze for Cybersecurity Risk

Explain:

"This message contains no major phishing indicators.
The system analyzes the language and security signals and produces
a low-risk assessment."

Show:

- Risk score
- Risk level
- Text analysis
- Recommendations

---

# Scene 3 — Suspicious Message

Time: 0:50–1:20

Enter:

Congratulations! You won a cash prize.
Claim your reward immediately.

Click:

Analyze for Cybersecurity Risk

Explain:

"Now we have a suspicious message.

The system identifies language patterns such as reward-related
language and urgency.

These signals contribute to the overall cybersecurity risk score."

Show:

- Risk score
- Risk level
- Security signals
- Explanation section

---

# Scene 4 — High-Risk Example

Time: 1:20–2:00

Enter:

FINAL WARNING! Your bank account will be blocked today.
Verify your OTP and password immediately at
http://192.168.1.50/login

Click:

Analyze for Cybersecurity Risk

Explain:

"This example demonstrates multiple risk signals.

The message contains urgency and requests sensitive information.

The URL also contains characteristics associated with suspicious
links, including an IP address and a login-related path.

SafeShield AI combines these signals to calculate the final risk
score."

Show:

- High risk score
- High risk level
- URL analysis
- Urgency detection
- Sensitive-information detection
- Explanations
- Safety recommendations

IMPORTANT:

This is a fictional demonstration URL.

Never enter real passwords, OTPs, banking information, API keys,
or other sensitive information during the demonstration.

---

# Scene 5 — Explain the AI

Time: 2:00–2:30

Say:

"The text detection component uses TF-IDF feature extraction and
Logistic Regression to classify message language.

The URL analyzer performs lexical analysis without opening the URL.

Finally, the risk engine combines the machine-learning probability,
URL risk indicators, and security heuristics into an explainable
0-to-100 risk score."

Show:

- Technology section
- Risk analysis
- Raw JSON analysis if useful

---

# Scene 6 — Responsible Cybersecurity

Time: 2:30–2:45

Say:

"SafeShield AI is designed as a defensive cybersecurity tool.

It does not open submitted URLs, perform network requests, collect
credentials, or attempt to exploit systems.

The training examples are synthetic so that the project can be
reproduced without exposing private user information."

Show:

- Privacy / safety section
- Recommendations

---

# Scene 7 — Closing

Time: 2:45–3:00

Say:

"SafeShield AI demonstrates how AI and explainable security analysis
can help users recognize potential phishing and scam attempts.

The goal is simple: analyze before interacting, understand the risk,
and make safer digital decisions.

Thank you."

---

# Demo Checklist

Before recording:

- [ ] Streamlit application launches successfully
- [ ] Normal message tested
- [ ] Suspicious message tested
- [ ] High-risk message tested
- [ ] Risk score is visible
- [ ] Risk level is visible
- [ ] URL analysis is visible
- [ ] Security signals are visible
- [ ] Recommendations are visible
- [ ] No real credentials are used
- [ ] No real banking information is used
- [ ] No real OTP is used
- [ ] No API keys are exposed
- [ ] Browser notifications are disabled
- [ ] Desktop notifications are disabled
- [ ] Screen recording resolution is clear

---

# Key Technical Highlights

## Machine Learning

TF-IDF + Logistic Regression

## Natural Language Processing

Message classification and suspicious-language detection

## URL Security

Lexical URL analysis without opening submitted URLs

## Risk Engine

Combines:

- ML probability
- URL risk
- Urgency detection
- Sensitive-information detection
- Multiple-URL detection

## Explainability

Provides:

- Risk score
- Risk level
- Security indicators
- Explanations
- Recommendations

## Privacy

Synthetic training data and no URL network requests.

---

# Responsible Use

SafeShield AI is intended for defensive cybersecurity awareness
and educational purposes.

A high-risk result does not guarantee that a message or URL is
malicious, and a low-risk result does not guarantee safety.

Users should independently verify important communications through
trusted channels.