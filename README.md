# InternGuard AI

**Internship Email Risk Analyzer** — paste an internship or job offer email and get an instant risk score, the specific red flags found, safe next steps, and a ready-to-send reply.

🔗 Live demo: [internguard-ai.vercel.app](https://internguard-ai.vercel.app)

👤 Made by [Ishan Prajapati](https://portfolio-ishan-1224.vercel.app) | Frontend Developer & Cybersecurity Enthusiast

---

## Overview

Students and freshers often receive internship and job offer emails that look professional but include risky patterns such as registration fees, vague onboarding steps, unrealistic stipend promises, or requests for payment screenshots.

**InternGuard AI** is a fully client-side tool that helps students pause and verify before clicking links, sharing personal details, or paying money. The app scans pasted email text and highlights scam-like red flags in a simple, explainable way.

This project is demonstrated using fictional internship email samples, including one that asks for a ₹1594 “registration fee” before enrollment.

## Problem Statement

Fake or misleading internship emails often:

- Use professional-sounding language, logos, and HR signatures
- Ask for a registration, training, certificate, or enrollment fee
- Promise high stipends, guaranteed placements, or pre-placement offers with little evaluation
- Keep project, team, and stipend details vague until after enrollment
- Ask candidates to reply with a payment screenshot
- Use shortened or unclear links instead of the company’s official domain

InternGuard AI analyzes these patterns and gives the user a clear verdict: **Safe**, **Suspicious**, or **High Risk**.

## Features

- 📋 Paste any internship or job offer email
- 🛡️ One-click email risk analysis
- 🎯 Risk score from 0 to 100
- 🚦 Verdict badge: **Safe / Suspicious / High Risk**
- ⚠️ Specific red flags with human-readable explanations
- ✅ Safe next steps based on detected issues
- ✉️ Copyable reply template for verifying whether any payment is required
- 📑 Copy full report to clipboard
- 🕘 Scan history stored only in the browser using `localStorage`
- 🧪 Built-in sample emails for quick demos
- 📱 Responsive interface for desktop and mobile

## Tech Stack

- **HTML5**
- **CSS3**
- **Vanilla JavaScript**
- **localStorage**
- **Vercel** for hosting

No backend, login, database, or API key is required. The analyzer runs completely in the browser.

## How It Works

1. **Paste** — the user pastes the full text of an internship or job offer email.
2. **Scan** — the rule-based analyzer checks the email against common risk categories.
3. **Review** — the app shows a score, verdict, red flags, safe next steps, and a suggested reply.

| Category | What it looks for | Weight |
|---|---|---|
| Payment request | Registration fee, refundable deposit, UPI ID, payment links | 35 |
| Suspicious instructions | Payment screenshot, confidentiality pressure, pay-first wording | 20 |
| Unrealistic promises | Guaranteed placement, instant selection, PPO claims | 15 |
| Vague onboarding | Details shared after enrollment, assigned later, unclear project info | 15 |
| Suspicious links | Shortened links or unclear domains | 10 |
| Poor language quality | Generic greetings, excessive punctuation, pressure wording | 5 |

## Risk Scoring Logic

InternGuard AI is intentionally rule-based and transparent.

- Each risk category contributes a fixed score when triggered.
- The maximum score is capped at 100.
- A category is counted once, even if multiple matching phrases appear.
- The final score maps to a simple verdict.

| Score | Verdict |
|---|---|
| 0–30 | Safe |
| 31–69 | Suspicious |
| 70–100 | High Risk |

This makes the result easy to explain during demos and easy to improve as new scam patterns appear.

## Demo Scenario

A student receives a fictional internship email offering an “HTML/CSS Developer Internship.” The email asks for a ₹1594 registration fee, mentions that project details will be shared after enrollment, and asks for a screenshot after payment.

When pasted into InternGuard AI, the app identifies the payment request, vague onboarding, and suspicious screenshot instruction, then returns a **High Risk** verdict with safe next steps.

## Privacy & Safety

InternGuard AI is designed with privacy in mind:

- Pasted email text is not sent to any server.
- No login is required.
- No personal data is collected.
- Scan history is saved only in the user’s browser through `localStorage`.
- The tool is for awareness and educational support only.

## Future Improvements

- Optional AI-assisted analysis layered on top of the current rule-based engine
- Browser extension version for Gmail and Outlook
- Exportable PDF scan reports
- Multi-language support for internship offers in different languages
- Community-maintained scam pattern updates

## Disclaimer

InternGuard AI is for **awareness and educational support only**. It does not provide legal advice or guaranteed fraud detection. A low risk score does not guarantee that an offer is genuine. Always verify internships and jobs through official company websites, verified LinkedIn pages, and direct company contact before sharing personal information or making any payment.

## Author

Made by **Ishan Prajapati** | Frontend Developer & Cybersecurity Enthusiast

- GitHub: [Ishan-113](https://github.com/Ishan-113)
- Portfolio: [portfolio-ishan-1224.vercel.app](https://portfolio-ishan-1224.vercel.app)
