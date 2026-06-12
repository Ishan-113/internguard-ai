# InternGuard AI

**Internship Email Risk Analyzer** - paste an internship or job offer email and get a transparent risk score, red flags, trust signals, recommended next steps, and a ready-to-send verification reply.

Live demo: [internguard-ai.vercel.app](https://internguard-ai.vercel.app)

Made by [Ishan Prajapati](https://portfolio-ishan-1224.vercel.app) | Frontend Developer & Cybersecurity Enthusiast

---

## Overview

Students and freshers often receive internship and job offer emails that look professional but include risky patterns such as registration fees, vague onboarding steps, unrealistic stipend promises, or requests for payment screenshots.

**InternGuard AI** helps students pause and verify before clicking links, sharing personal details, or paying money. The main safety backbone is a rule-based analyzer that runs fully in the browser. Optional AI-assisted review can be added later through a backend or serverless API, but AI is not the final authority.

The project is demonstrated using fictional internship email samples, including one that asks for a registration fee before enrollment.

## Problem Statement

Fake or misleading internship emails often:

- Use professional-sounding language, logos, and HR signatures
- Ask for a registration, training, certificate, or enrollment fee
- Promise high stipends, guaranteed placements, or pre-placement offers with little evaluation
- Keep project, team, and stipend details vague until after enrollment
- Ask candidates to reply with a payment screenshot
- Use shortened or unclear links instead of the company's official domain

InternGuard AI analyzes these patterns and gives the user a clear educational verdict: **Low Risk**, **Needs Verification**, or **High Risk**. It does not guarantee whether an email is genuine or fake.

## Features

- Paste any internship or job offer email
- One-click rule-based email risk analysis
- Risk score from 0 to 100
- Verdict badge: **Low Risk / Needs Verification / High Risk**
- Specific red flags with human-readable explanations
- Trust signals that can slightly reduce the score without overriding serious payment risks
- Recommended next steps based on detected issues
- Copyable reply template for verifying whether any payment is required
- Copy full report to clipboard
- Scan history stored only in the browser using `localStorage`
- Built-in sample emails for quick demos
- Optional AI review button that calls `/api/analyze` only after the user clicks it
- Responsive interface for desktop and mobile

## Tech Stack

- **HTML5**
- **CSS3**
- **Vanilla JavaScript**
- **localStorage**
- **Vercel** for hosting

The rule-based scan works fully in the browser with no login, database, backend, or API key. The optional AI review requires a backend or serverless endpoint and must never expose API keys in frontend files.

## How It Works

1. **Paste** - the user pastes the full text of an internship or job offer email.
2. **Scan** - the rule-based analyzer checks the email against common risk categories and positive trust signals.
3. **Review** - the app shows a score, verdict, red flags, trust signals, recommended next steps, and a suggested reply.
4. **Optional AI review** - if a backend is configured, the user can click a button to request a deeper AI-assisted explanation. The email text is not sent anywhere unless this button is clicked.

## Risk Rules

| Category | What it looks for | Weight |
|---|---|---:|
| Payment request | Registration fee, refundable deposit, UPI ID, payment links | 35 |
| Suspicious instructions | Payment screenshot, confidentiality pressure, pay-first wording | 20 |
| Unrealistic promises | Guaranteed placement, instant selection, PPO claims | 15 |
| Vague onboarding | Details shared after enrollment, assigned later, unclear project info | 15 |
| Suspicious links | Shortened links or unclear domains | 10 |
| Poor language quality | Generic greetings, excessive punctuation, pressure wording | 5 |

## Trust Signals

Trust signals are weak positive indicators. They can reduce the final score slightly, but they do not prove that an email is genuine.

| Trust signal | Examples | Adjustment |
|---|---|---:|
| Recognizable domain mention | `google.com`, `microsoft.com`, `github.com`, `linkedin.com` | -10 |
| No payment required | `no payment required`, `no fees`, `no registration fee` | -15 |
| Clear program details | `eligibility`, `selection process`, `timeline`, `official website` | -5 |
| Evaluation-based process | `interview`, `assessment`, `coding test`, `evaluation` | -5 |

Payment-related guardrails stay strict:

- If a payment risk rule is triggered, trust signals cannot reduce the final score below 55.
- If both payment and suspicious-instruction rules are triggered, trust signals cannot reduce the final score below 70.

## Risk Scoring Logic

InternGuard AI is intentionally transparent.

- Each risk category contributes a fixed score when triggered.
- Each trust category can apply a small negative adjustment.
- A category is counted once, even if multiple matching phrases appear.
- The final score is clamped between 0 and 100.
- The final verdict uses the adjusted score.

| Score | Verdict |
|---|---|
| 0-30 | Low Risk |
| 31-69 | Needs Verification |
| 70-100 | High Risk |

## Optional AI Review

The frontend includes a button for optional AI-assisted review. It sends a `POST` request to `/api/analyze` with:

- `emailText`
- `ruleResult`

If `/api/analyze` does not exist or is not configured, the app shows a friendly not-configured message and keeps the rule-based result visible.

To configure AI later on Vercel:

1. Add a serverless function at `api/analyze.js`.
2. Read the secret key from `process.env.AI_API_KEY` or `process.env.OPENAI_API_KEY`.
3. Add the environment variable in the Vercel project settings.
4. Return JSON with `aiSummary`, `verificationChecklist`, and `finalAdvice`.
5. Keep API keys out of `app.js`, `index.html`, `styles.css`, and `README.md`.

AI review should explain the rule-based result and suggest verification steps. It should not replace the rule-based engine or claim certainty.

## Demo Scenario

A student receives a fictional internship email offering a web development internship. The email asks for a registration fee, says project details will be shared after enrollment, and asks for a screenshot after payment.

When pasted into InternGuard AI, the app identifies the payment request, vague onboarding, and screenshot instruction, then returns a **High Risk** verdict with recommended next steps.

## Privacy & Safety

InternGuard AI is designed with privacy in mind:

- The rule-based scan runs locally in the browser.
- Pasted email text is not sent anywhere during the normal scan.
- Optional AI review sends email text only after the user clicks the AI review button.
- No login is required.
- No personal data is collected.
- Scan history is saved only in the user's browser through `localStorage`.
- The tool is for awareness and educational support only.

## Future Improvements

- Add a secure `api/analyze.js` serverless endpoint for optional AI review
- Browser extension version for Gmail and Outlook
- Exportable PDF scan reports
- Multi-language support for internship offers in different languages
- Community-maintained scam pattern updates

## Disclaimer

InternGuard AI is for **awareness and educational support only**. It does not provide legal advice or guaranteed fraud detection. A low-risk result does not guarantee that an offer is genuine. Always verify internships and jobs through official company websites, verified LinkedIn pages, and direct company contact before sharing personal information or making any payment.

## Author

Made by **Ishan Prajapati** | Frontend Developer & Cybersecurity Enthusiast

- GitHub: [Ishan-113](https://github.com/Ishan-113)
- Portfolio: [portfolio-ishan-1224.vercel.app](https://portfolio-ishan-1224.vercel.app)
