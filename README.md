# InternGuard AI

**Internship Email Risk Analyzer** — paste an internship or job offer email and get an instant risk score, the specific red flags found, safe next steps, and a ready-to-send reply.

🔗 Live demo: _add your Vercel URL here after deploying_
👤 Made by [Ishan Prajapati](https://portfolio-ishan-1224.vercel.app) | Frontend Developer & Cybersecurity Enthusiast

---

## Overview

Students and freshers regularly receive internship and job offer emails that *look* professional but ask for a "registration fee," "training fee," or "refundable deposit" before onboarding — or that keep the role, stipend, and project details vague until after payment.

InternGuard AI is a small, fully client-side tool that scans the text of any internship/job email and flags the patterns commonly seen in these scams, so a student can pause and verify **before** clicking a link, replying with a screenshot, or paying anything.

This project is demonstrated using a fictional internship email that asks for a ₹1594 "registration fee" before enrollment — a textbook example of the pattern this tool is built to catch.

## Problem Statement

Fake or misleading internship emails often:

- Use professional-sounding language, logos, and HR signatures
- Ask for a registration, training, certificate, or enrollment fee — sometimes framed as "refundable"
- Promise high stipends, guaranteed placements, or pre-placement offers (PPOs) with little to no evaluation
- Leave project, team, and stipend details "to be shared after enrollment"
- Ask candidates to reply with a screenshot of their payment, or to keep the offer "confidential"
- Use shortened links instead of the company's own domain

InternGuard AI analyzes the email text against these patterns and returns a risk score, a verdict (**Safe**, **Suspicious**, or **High Risk**), the exact red flags detected, recommended next steps, and a polite reply template that asks the sender to confirm — in writing — that no payment is required.

## Features

- 📋 Paste any internship/job offer email into a text area
- 🛡️ One-click **Analyze email** with an instant risk score (0–100)
- 🎯 Clear verdict badge: **Safe / Suspicious / High Risk**
- ⚠️ Specific, human-readable red flags — not just "looks risky"
- ✅ Tailored safe next steps based on what was actually detected
- ✉️ Ready-to-send reply that asks the sender to confirm there's no fee
- 📑 Copy the reply or the full report to your clipboard in one click
- 🕘 Scan history saved locally (no account, no server, no tracking)
- 🧪 Three built-in sample emails (Safe / Suspicious / High Risk) for instant demos
- 📱 Fully responsive, keyboard-accessible interface

## Tech Stack

- **HTML5, CSS3, Vanilla JavaScript** — no frameworks, no build step
- **localStorage** for scan history (stays on the user's device)
- **Google Fonts** — Space Grotesk, Inter, JetBrains Mono
- **Deployment** — Vercel (static site)

No API keys, accounts, or backend are required. The entire analyzer is a rule-based engine that runs in the browser.

## How It Works

1. **Paste** — drop in the full text of an internship/job offer email (subject, greeting, role, stipend, links, instructions).
2. **Scan** — the analyzer checks the text against six categories of red flags, each with its own weight:

   | Category | What it looks for | Weight |
   |---|---|---|
   | Payment request | "registration fee," "refundable deposit," "UPI ID," payment links, etc. | 35 |
   | Suspicious instructions | "reply with a screenshot," "keep this confidential," "pay first to confirm" | 20 |
   | Unrealistic promises | "guaranteed placement," "PPO offer up to 5 LPA," "instant selection" | 15 |
   | Vague onboarding | "details shared after enrollment," "assigned later" | 15 |
   | Suspicious links | shortened links (bit.ly, tinyurl, etc.) instead of a real domain | 10 |
   | Poor language quality | generic greetings ("Dear Candidate"), excessive "!!", ALL-CAPS pressure words | 5 |

3. **Act** — based on the total score, the email is labeled:

   | Score | Verdict |
   |---|---|
   | 0–30 | Safe |
   | 31–69 | Suspicious |
   | 70–100 | High Risk |

   The report then lists the exact red flags found, suggests next steps, and provides a copyable reply asking the sender to confirm there's no payment required.

## Risk Scoring Logic

The analyzer is intentionally **rule-based and transparent** rather than a black box:

- Each of the six categories above contributes a fixed weight to the score *only if* one of its keyword patterns (or, for "poor language quality," a heuristic check) is found in the email text.
- Weights sum to 100, so the score is always between 0 and 100.
- A category contributes at most once, even if multiple matching phrases appear.
- The final score maps directly to the Safe / Suspicious / High Risk verdict ranges above.

This keeps the logic easy to read, easy to extend, and easy to explain in a demo — every point on the score can be traced back to a specific phrase in the email.

## Sample Use Case

> Ishan registers for a hackathon and, around the same time, tests a fictional internship email offering an "HTML/CSS Developer Internship" that asks for a ₹1594 "registration fee" to confirm enrollment, promises a stipend "depending on successful completion," and asks for a screenshot after payment.
>
> Pasting this email into InternGuard AI returns a **High Risk** verdict (~85/100), flags the registration fee, the unclear stipend, the vague project details, and the screenshot request — and provides a reply asking the sender to confirm in writing that no fee is required.

Three ready-made examples are built into the app (and included in `sample-emails/`) so this flow can be demoed in under two minutes without needing a real scam email on hand.

## How to Run Locally

No build tools or dependencies are required.

```bash
git clone https://github.com/Ishan-113/internguard-ai.git
cd internguard-ai
```

Then either:

- Open `index.html` directly in your browser, **or**
- Use the VS Code "Live Server" extension for auto-reload during development.

## Deployment

This project is a static site and deploys directly to **Vercel**:

1. Push the repository to GitHub.
2. Go to [vercel.com](https://vercel.com), choose **New Project**, and import the `internguard-ai` repo.
3. Leave the framework preset as **Other** (no build command needed).
4. Deploy — Vercel will serve `index.html`, `styles.css`, and `app.js` directly.

## Future Improvements

- Optional AI-assisted analysis (e.g. Anthropic API) layered on top of the rule-based engine for nuanced cases, with the rule-based analyzer kept as an offline fallback
- Browser extension version that scans emails directly in Gmail/Outlook
- Crowd-sourced pattern list, with versioned updates as new scam formats appear
- Export scan history as a PDF report
- Multi-language support for non-English internship offers

## Disclaimer

InternGuard AI is for **awareness and educational support only**. It does not provide legal advice or guaranteed fraud detection, and a low risk score is not a guarantee that an offer is genuine. Always verify internship and job opportunities through a company's official website, LinkedIn page, and direct contact before sharing personal information or making any payment.

## Author

Made by **Ishan Prajapati** | Frontend Developer & Cybersecurity Enthusiast
- GitHub: [Ishan-113](https://github.com/Ishan-113)
- Portfolio: [portfolio-ishan-1224.vercel.app](https://portfolio-ishan-1224.vercel.app)
