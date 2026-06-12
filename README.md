# InternGuard AI

**Internship Email Risk Analyzer** — paste an internship or job offer email and get an instant risk score, the specific red flags and trust signals found, safe next steps, and a ready-to-send reply. Optionally, ask an AI model for a second-opinion review on top of that result.

🔗 Live demo: _add your Vercel URL here after deploying_

---

## Overview

Students and freshers regularly receive internship and job offer emails that *look* professional but ask for a "registration fee," "training fee," or "refundable deposit" before onboarding — or that keep the role, stipend, and project details vague until after payment.

InternGuard AI scans the text of any internship/job email for the patterns commonly seen in these offers — both warning signs and positive signals — so a student can pause and verify **before** clicking a link, replying with a screenshot, or paying anything.

## Problem Statement

Fake or misleading internship emails often:

- Use professional-sounding language, logos, and HR signatures
- Ask for a registration, training, certificate, or enrollment fee — sometimes framed as "refundable"
- Promise high stipends, guaranteed placements, or pre-placement offers (PPOs) with little to no evaluation
- Leave project, team, and stipend details "to be shared after enrollment"
- Ask candidates to reply with a screenshot of their payment, or to keep the offer "confidential"
- Use shortened links instead of the company's own domain

At the same time, genuine offers usually share some recognizable, positive signals: a clear "no fees" statement, mention of an official domain, a defined selection process, and an evaluation step (interview, assessment, coding test).

InternGuard AI looks for **both** sets of signals and returns a risk score, a verdict (**Low Risk**, **Needs Verification**, or **High Risk**), the specific signals detected, recommended next steps, and a polite reply template that asks the sender to confirm — in writing — that no payment is required.

## Features

- 📋 Paste any internship/job offer email into a text area
- 🛡️ One-click **Analyze email** with an instant risk score (0–100)
- 🎯 Clear verdict badge: **Low Risk / Needs Verification / High Risk**
- ⚠️ Specific, human-readable red flags — not just "looks risky"
- ✅ Trust signals — positive details the email shares, with a note to verify them independently
- 🧭 Tailored safe next steps based on what was actually detected
- 🤖 Optional **AI-assisted review** for a second opinion (works only if a backend is configured — the app is fully usable without it)
- ✉️ Ready-to-send reply that asks the sender to confirm there's no fee
- 📑 Copy the reply or the full report to your clipboard in one click
- 🕘 Scan history saved locally (no account, no server, no tracking)
- 🧪 Three built-in sample emails (Low Risk / Needs Verification / High Risk) for instant demos
- 📱 Fully responsive, keyboard-accessible interface

## Tech Stack

- **HTML5, CSS3, Vanilla JavaScript** — no frameworks, no build step
- **localStorage** for scan history (stays on the user's device)
- **Google Fonts** — Space Grotesk, Inter, JetBrains Mono
- **Optional serverless function** (`api/analyze.js`) for the AI review step, deployable on Vercel
- **Deployment** — Vercel (static site + optional serverless function)

The rule-based scan requires no API keys, accounts, or backend, and runs entirely in the browser. The AI review is an additional, optional layer.

## How It Works

1. **Paste** — drop in the full text of an internship/job offer email (subject, greeting, role, stipend, links, instructions).
2. **Scan** — the local rule-based analyzer checks the text against two sets of signals:

   **Risk signals** (each adds to the score):

   | Category | What it looks for | Weight |
   |---|---|---|
   | Payment request | "registration fee," "refundable deposit," "UPI ID," payment links, etc. | 35 |
   | Suspicious instructions | "reply with a screenshot," "keep this confidential," "pay first to confirm" | 20 |
   | Unrealistic promises | "guaranteed placement," "PPO offer up to 5 LPA," "instant selection" | 15 |
   | Vague onboarding | "details shared after enrollment," "assigned later" | 15 |
   | Suspicious links | shortened links (bit.ly, tinyurl, etc.) instead of a real domain | 10 |
   | Poor language quality | generic greetings ("Dear Candidate"), excessive "!!", ALL-CAPS pressure words | 5 |

   **Trust signals** (each slightly reduces the score):

   | Category | What it looks for | Weight |
   |---|---|---|
   | Official domain mentioned | google.com, hackerrank.com, microsoft.com, github.com, linkedin.com, vercel.com | -10 |
   | No payment stated | "no payment required," "no fees," "free registration," "no charges," etc. | -10 |
   | Clear program details | "eligibility," "selection process," "timeline," "official website," "terms and conditions" | -8 |
   | Evaluation-based process | "interview," "assessment," "coding test," "evaluation" | -8 |

   Trust signals can only reduce the score within limits — **safety floors** make sure they never hide a clearly risky email:
   - If a payment request is detected, the score never drops below **55**.
   - If a payment request **and** a suspicious instruction are both detected, the score never drops below **70** (always **High Risk**), even if the email also mentions a well-known domain.

3. **Act** — based on the final score, the email is labeled:

   | Score | Verdict |
   |---|---|
   | 0–30 | Low Risk |
   | 31–69 | Needs Verification |
   | 70–100 | High Risk |

   The report then lists the specific red flags and trust signals found, suggests next steps, and provides a copyable reply asking the sender to confirm there's no payment required.

## AI Pipeline (Hybrid Approach)

InternGuard AI uses a hybrid pipeline. The rule-based analyzer runs locally first and provides the main risk score. The optional AI review is a second layer that explains the result, summarizes risk and trust signals, and gives a verification checklist. The AI is not treated as the final authority; it supports the transparent rule-based result.

In more detail:

1. The user pastes an internship/job email and clicks **Analyze email**.
2. The rule-based engine in `app.js` runs first, entirely in the browser, and produces: risk signals, trust signals, a risk score (0–100), a verdict, red flags, and safe next steps.
3. This rule-based result is shown immediately and **works without any API** — there is no network dependency at this stage.
4. The user can optionally click **"Ask AI for deeper review"**.
5. The frontend calls `requestAiAnalysis(emailText, ruleResult)`, which sends a POST request to `/api/analyze` with the original email text and the structured rule-based result (score, verdict, red flags, trust signals).
6. `api/analyze.js`, an optional Vercel serverless function, receives this payload and uses the rule-based result **as context**. It does not re-score the email from scratch and must not override the rule-based verdict.
7. If configured, it returns three fields: `aiSummary` (plain-language explanation), `verificationChecklist` (concrete steps to verify the offer), and `finalAdvice` (a short closing recommendation consistent with the rule-based verdict).
8. If no API key is configured, or the request fails for any reason, the UI shows: *"AI review is not configured yet. The rule-based analysis above is still available and works offline."* — and the rule-based result above remains fully usable.
9. The AI response never guarantees whether an email is real or fake — it only gives risk-based guidance and verification steps, and it never asks the user to pay or to share sensitive data.

### Setting up the optional AI review

1. Deploy the project to Vercel (the `api/analyze.js` file becomes a serverless function automatically).
2. In the Vercel project settings, add an environment variable named `OPENAI_API_KEY` (or `AI_API_KEY`) with your API key.
3. Redeploy. The "Ask AI for deeper review" button will now return an AI-assisted explanation.

**API keys must only ever be stored in Vercel Environment Variables** — never in `app.js`, `index.html`, `styles.css`, or any other frontend file, and never committed to the repository.

## Sample Use Case

> A student receives an email offering an "HTML/CSS Developer Internship" that asks for a ₹1594 "registration fee" to confirm enrollment, promises a stipend "depending on successful completion," and asks for a screenshot after payment.
>
> Pasting this email into InternGuard AI returns a **High Risk** verdict (~85/100), flags the registration fee, the unclear stipend, the vague project details, and the screenshot request — and provides a reply asking the sender to confirm in writing that no fee is required.

Three ready-made examples are built into the app (and included in `sample-emails/`) so this flow can be demoed in under two minutes without needing a real example on hand.

## How to Run Locally

No build tools or dependencies are required for the rule-based app.

```bash
git clone https://github.com/Ishan-113/internguard-ai.git
cd internguard-ai
```

Then either:

- Open `index.html` directly in your browser, **or**
- Use the VS Code "Live Server" extension for auto-reload during development.

The "Ask AI for deeper review" button will show the "not configured" message when run this way, since `/api/analyze` is a serverless function that only exists once deployed to Vercel (or run with the Vercel CLI).

## Deployment

This project deploys directly to **Vercel** as a static site with one optional serverless function:

1. Push the repository to GitHub.
2. Go to [vercel.com](https://vercel.com), choose **New Project**, and import the repo.
3. Leave the framework preset as **Other** (no build command needed).
4. (Optional) Add the `OPENAI_API_KEY` or `AI_API_KEY` environment variable to enable the AI review step.
5. Deploy — Vercel will serve `index.html`, `styles.css`, and `app.js` as static files, and `api/analyze.js` as a serverless function at `/api/analyze`.

## Future Improvements

- Browser extension version that scans emails directly in Gmail/Outlook
- Crowd-sourced pattern list, with versioned updates as new offer formats appear
- Export scan history as a PDF report
- Multi-language support for non-English internship offers
- Support for additional AI providers in `api/analyze.js`

## Disclaimer

InternGuard AI is for **awareness and educational support only**. It does not provide legal advice or guaranteed fraud detection, and a "Low Risk" result is not a guarantee that an offer is genuine — nor does a "High Risk" result guarantee that it is fake. Always verify internship and job opportunities through a company's official website, official domain, and LinkedIn page, and never pay any fee to be considered for, or onboarded into, an internship.

## Author

Made by **Ishan Prajapati** | Frontend Developer & Cybersecurity Enthusiast
- GitHub: [Ishan-113](https://github.com/Ishan-113)
- Portfolio: [portfolio-ishan-1224.vercel.app](https://portfolio-ishan-1224.vercel.app)
