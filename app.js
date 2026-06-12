/* =========================================================
   InternGuard AI — rule-based email risk analyzer (v2)
   Everything runs locally in the browser by default. The
   rule-based scan never needs a network request. Scan
   history is stored only in localStorage. The optional AI
   review (if a backend is configured) is an extra, clearly
   separate step - it never replaces the rule-based result.
   ========================================================= */

(function () {
  "use strict";

  const PAYMENT_PHRASES = [
    "registration fee",
    "enrollment fee",
    "enrolment fee",
    "internship fee",
    "training fee",
    "certificate fee",
    "refundable fee",
    "refundable deposit",
    "processing fee",
    "confirmation fee",
    "security deposit",
    "payment link",
    "after payment",
    "payment screenshot",
    "transaction screenshot",
    "pay to confirm",
    "scan the qr code",
    "upi id",
    "upi",
    "qr",
    "inr",
    "rs",
    "\u20b9",
  ];

  const PAYMENT_WORDS = ["payment", "pay", "paid", "transaction", "upi", "qr", "amount", "fee", "inr", "rs", "\u20b9"];

  const CONFIRMATION_WORDS = [
    "confirm",
    "confirmation",
    "enrollment",
    "enrolment",
    "seat",
    "onboarding",
    "internship",
    "joining",
    "selected",
    "shortlisted",
  ];

  const SCREENSHOT_INSTRUCTION_PHRASES = [
    "payment screenshot",
    "transaction screenshot",
    "send a screenshot",
    "reply with a screenshot",
    "share a screenshot",
    "share screenshot",
    "send screenshot",
    "upload screenshot",
    "screenshot of the transaction",
    "screenshot after payment",
    "whatsapp your payment",
  ];

  const VAGUE_ONBOARDING_PHRASES = [
    "shared after enrollment",
    "shared after enrolment",
    "shared after payment",
    "shared post payment",
    "assigned later",
    "details after enrollment",
    "details after enrolment",
    "details after payment",
    "credentials after payment",
    "provided after registration",
    "will be shared once you complete",
  ];

  const NO_PAYMENT_TERMS = ["no payment required", "no fees", "free registration", "free to register", "no charges"];

  /* ---------------------------------------------------
     1. Risk rules
     Each rule contributes a fixed weight to the score if
     it fires. Weights sum to 100 so the raw score always
     sits between 0 and 100 before trust signals are applied.
     --------------------------------------------------- */
  const RISK_RULES = [
    {
      id: "payment",
      weight: 35,
      severity: "high",
      test: (rawText, text) => {
        const signal = detectPaymentSignal(text);
        if (!signal) return null;

        if (signal.type === "context") {
          return `Connects payment language ("${signal.paymentWord}") with internship confirmation language ("${signal.confirmationWord}"). Legitimate internships should not require candidates to pay to confirm a seat, joining, or onboarding.`;
        }

        return `Asks for money before onboarding - the email mentions "${signal.matched}". Legitimate internships never charge candidates to join.`;
      },
      keywords: [
        "registration fee",
        "training fee",
        "certificate fee",
        "enrollment fee",
        "enrolment fee",
        "internship fee",
        "processing fee",
        "confirmation fee",
        "security deposit",
        "refundable deposit",
        "pay to confirm",
        "payment link",
        "scan the qr code",
        "upi id",
      ],
      describe: (kw) =>
        `Asks for money before onboarding — the email mentions "${kw}". Legitimate internships never charge candidates to join.`,
    },
    {
      id: "instructions",
      weight: 20,
      severity: "high",
      keywords: [
        "payment screenshot",
        "transaction screenshot",
        "send a screenshot",
        "reply with a screenshot",
        "share a screenshot",
        "share screenshot",
        "send screenshot",
        "upload screenshot",
        "screenshot of the transaction",
        "screenshot after payment",
        "do not share this email",
        "keep this offer confidential",
        "pay first to confirm",
        "share your otp",
        "share your card details",
        "whatsapp your payment",
        "reply with the payment screenshot",
      ],
      describe: (kw) =>
        `Gives an unusual instruction — "${kw}". Requests like this are a common pressure tactic in scam offers.`,
    },
    {
      id: "unrealistic",
      weight: 15,
      severity: "medium",
      keywords: [
        "guaranteed job",
        "guaranteed placement",
        "100% placement",
        "instant selection",
        "no interview required",
        "limited seats",
        "urgent joining",
        "up to 5 lpa",
        "up to ₹5 lpa",
        "ppo offer",
        "pre-placement offer",
        "earn up to",
      ],
      describe: (kw) =>
        `Makes a promise that sounds too good to be true — "${kw}". Be cautious of guarantees, instant offers, or salary figures pitched before any real evaluation.`,
    },
    {
      id: "vague",
      weight: 15,
      severity: "medium",
      keywords: [
        "shared after enrollment",
        "shared after enrolment",
        "shared after payment",
        "shared post payment",
        "assigned later",
        "details after enrollment",
        "details after enrolment",
        "details after payment",
        "credentials after payment",
        "provided after registration",
        "will be shared once you complete",
      ],
      describe: (kw) =>
        `Keeps key details vague until later — "${kw}". A real employer can describe the team, project, and stipend up front.`,
    },
    {
      id: "links",
      weight: 10,
      severity: "medium",
      keywords: ["bit.ly", "tinyurl", "cutt.ly", "tiny.cc", "rebrand.ly", "is.gd", "goo.gl", "t.co/"],
      describe: (kw) =>
        `Uses a shortened or generic link service ("${kw}") instead of the company's own domain, which makes it harder to verify where it leads.`,
    },
    {
      id: "poor_language",
      weight: 5,
      severity: "low",
      test: (rawText, text) => {
        const genericGreeting = /dear (candidate|applicant|student|sir\/madam|sir or madam)/i.test(rawText);
        const excessivePunctuation = /[!?]{2,}/.test(rawText);
        const allCapsWords = (rawText.match(/\b[A-Z]{4,}\b/g) || []).filter(
          (w) => !["HTML", "CSS", "HTTP", "HTTPS", "URL", "INTERN"].includes(w)
        );

        if (excessivePunctuation) {
          return 'Uses excessive punctuation (like "!!" or "??"), which is common in mass-sent or pressure-driven messages.';
        }
        if (genericGreeting) {
          return 'Uses a generic greeting ("Dear Candidate" / "Dear Applicant") instead of your name — a sign of a mass-sent template.';
        }
        if (allCapsWords.length >= 2) {
          return "Relies on ALL-CAPS words for urgency, a common pattern in low-effort scam emails.";
        }
        return null;
      },
    },
  ];

  /* ---------------------------------------------------
     1b. Trust signals
     These slightly REDUCE the risk score when present.
     They are signals worth noting, not proof an email is
     genuine — safety floors below stop them from masking
     a clearly risky email.
     --------------------------------------------------- */
  const TRUST_RULES = [
    {
      id: "official_domain",
      weight: 8,
      keywords: [
        "google.com",
        "hackerrank.com",
        "microsoft.com",
        "github.com",
        "linkedin.com",
      ],
      describe: (kw) => `Mentions a recognizable official domain ("${kw}") — still worth confirming the email actually came from that domain.`,
    },
    {
      id: "no_payment",
      weight: 10,
      keywords: NO_PAYMENT_TERMS,
      describe: (kw) => `States there's no payment involved ("${kw}") — a good sign, though it's still worth confirming this in writing.`,
    },
    {
      id: "clear_details",
      weight: 6,
      keywords: [
        "eligibility",
        "selection process",
        "timeline",
        "official website",
        "terms and conditions",
      ],
      describe: (kw) => `Shares concrete program details up front ("${kw}") instead of leaving them vague.`,
    },
    {
      id: "evaluation_based",
      weight: 8,
      keywords: ["interview", "assessment", "coding test", "shortlisted after review", "evaluation"],
      describe: (kw) => `Describes an evaluation step ("${kw}") rather than promising instant selection.`,
    },
  ];

  /* ---------------------------------------------------
     2. Sample emails (also saved under sample-emails/*.txt)
     --------------------------------------------------- */
  const SAMPLE_EMAILS = {
    safe: `Subject: Frontend Developer Intern Opportunity - TechNova Solutions

Hi Ishan,

Thank you for applying to the Frontend Developer Internship at TechNova Solutions. We reviewed your portfolio and would like to invite you for a short video interview with our engineering team.

Role: Frontend Developer Intern
Duration: 8 weeks
Mode: Remote
Stipend: ₹8,000 per month, paid at the end of each month

There are no charges of any kind at any stage of our hiring or onboarding process - free registration, no fees. If selected, you'll receive an offer letter on company letterhead and an NDA before your first day.

You can find our eligibility criteria, selection process, and timeline on our official website at www.technova-solutions.com or on our LinkedIn page.

Please reply with your availability for a 20-minute interview this week.

Best regards,
Ananya Rao
HR, TechNova Solutions`,

    suspicious: `Subject: Congratulations!! You are selected for Web Development Internship

Dear Candidate,

Congratulations! Based on your resume, you have been shortlisted for our Web Development Internship Program. This is a great opportunity with guaranteed placement and a pre-placement offer (PPO) up to 5 LPA for top performers.

Your project team and mentor details will be shared after enrollment is completed. To proceed, please confirm your slot using the link below:

Enrollment link: bit.ly/webdev-intern-2026

Seats are limited, so we recommend confirming at the earliest.

Regards,
HR Team
BrightPath Careers`,

    "high-risk": `Subject: Internship Confirmation - Registration Fee Required

Hello,

We are pleased to inform you that you have been selected for the Web Development Internship at Clinch Cloud Workforce.

To confirm your enrollment, please pay a refundable registration fee of ₹1594 via the UPI link below. This amount will be refunded along with your first stipend.

Stipend: Up to ₹15,000 per month, with a PPO offer up to 5 LPA based on performance.

Your project, client, and team details will be shared after enrollment is completed. After making the payment, please reply with a screenshot of the transaction to confirm your seat.

Payment link: pay.clinchcloud-confirm.com/intern

Regards,
Onboarding Team
Clinch Cloud Workforce`,
  };

  /* ---------------------------------------------------
     3. Core analyzer
     --------------------------------------------------- */
  function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function keywordPattern(keyword, flags = "") {
    const normalized = keyword.toLowerCase();
    const escaped = escapeRegex(normalized).replace(/\s+/g, "\\s+");
    const startsWithWord = /^[a-z0-9]/.test(normalized);
    const endsWithWord = /[a-z0-9]$/.test(normalized);
    return new RegExp(`${startsWithWord ? "\\b" : ""}${escaped}${endsWithWord ? "\\b" : ""}`, flags);
  }

  function keywordMatches(text, keyword) {
    return keywordPattern(keyword).test(text);
  }

  function findKeyword(keywords, text) {
    return keywords.find((kw) => keywordMatches(text, kw)) || null;
  }

  function removeKeywordMatches(text, keywords) {
    return keywords.reduce((cleaned, kw) => cleaned.replace(keywordPattern(kw, "g"), " "), text);
  }

  function detectPaymentSignal(text) {
    const directMatch = findKeyword(PAYMENT_PHRASES, text);
    if (directMatch) {
      return { type: "direct", matched: directMatch };
    }

    const contextText = removeKeywordMatches(text, NO_PAYMENT_TERMS);
    const paymentWord = findKeyword(PAYMENT_WORDS, contextText);
    const confirmationWord = findKeyword(CONFIRMATION_WORDS, contextText);

    if (paymentWord && confirmationWord) {
      return { type: "context", paymentWord, confirmationWord };
    }

    return null;
  }

  function hasScreenshotInstruction(text) {
    return (
      Boolean(findKeyword(SCREENSHOT_INSTRUCTION_PHRASES, text)) ||
      /\b(send|share|reply|upload|attach|whatsapp)\b[\s\S]{0,80}\bscreenshot\b/.test(text) ||
      /\bscreenshot\b[\s\S]{0,80}\b(payment|transaction)\b/.test(text)
    );
  }

  function hasVagueOnboarding(text) {
    return Boolean(findKeyword(VAGUE_ONBOARDING_PHRASES, text));
  }

  function analyzeEmail(rawText) {
    const text = rawText.toLowerCase();
    let rawScore = 0;
    const flags = [];
    const hitIds = new Set();

    RISK_RULES.forEach((rule) => {
      if (rule.test) {
        const result = rule.test(rawText, text);
        if (result) {
          rawScore += rule.weight;
          hitIds.add(rule.id);
          flags.push({ text: result, severity: rule.severity });
        }
        return;
      }

      const matched = findKeyword(rule.keywords, text);
      if (matched) {
        rawScore += rule.weight;
        hitIds.add(rule.id);
        flags.push({ text: rule.describe(matched), severity: rule.severity });
      }
    });

    rawScore = Math.min(100, rawScore);

    // --- Trust signals: small reductions, never enough on their
    // own to override a clearly risky email (see floors below). ---
    const trustSignals = [];
    let trustReduction = 0;

    TRUST_RULES.forEach((rule) => {
      const matched = findKeyword(rule.keywords, text);
      if (matched) {
        trustSignals.push({ text: rule.describe(matched) });
        trustReduction += rule.weight;
      }
    });

    let score = rawScore - trustReduction;

    // --- Safety floors ---
    // A payment request alone is serious enough that trust signals
    // can't bring it below "Needs Verification" territory. Screenshot
    // and vague-onboarding combinations are stronger risk patterns.
    const paymentDetected = hitIds.has("payment");
    const screenshotInstructionDetected = hasScreenshotInstruction(text);
    const vagueOnboardingDetected = hitIds.has("vague") || hasVagueOnboarding(text);

    if (paymentDetected && screenshotInstructionDetected && vagueOnboardingDetected) {
      score = Math.max(score, 85);
    } else if (paymentDetected && screenshotInstructionDetected) {
      score = Math.max(score, 75);
    } else if (paymentDetected && vagueOnboardingDetected) {
      score = Math.max(score, 70);
    } else if (paymentDetected) {
      score = Math.max(score, 55);
    }

    score = Math.max(0, Math.min(100, score));

    let verdict;
    if (score >= 70) verdict = "High Risk";
    else if (score >= 31) verdict = "Needs Verification";
    else verdict = "Low Risk";

    return {
      score,
      verdict,
      flags,
      hitIds,
      trustSignals,
      summary: buildSummary(verdict, hitIds),
      nextSteps: buildNextSteps(verdict, hitIds, trustSignals),
      reply: buildReply(),
    };
  }

  function buildSummary(verdict, hitIds) {
    const reasons = [];
    if (hitIds.has("payment")) reasons.push("asks you to pay before onboarding");
    if (hitIds.has("instructions")) reasons.push("gives suspicious instructions, like sending a payment screenshot");
    if (hitIds.has("unrealistic")) reasons.push("makes promises about placement or salary that sound too good to be true");
    if (hitIds.has("vague")) reasons.push("keeps key project, team, or stipend details vague until after you commit");
    if (hitIds.has("links")) reasons.push("uses a shortened or generic link instead of the company's own domain");
    if (hitIds.has("poor_language")) reasons.push("has the generic tone and wording typical of mass-sent offers");

    const joined =
      reasons.length > 1
        ? reasons.slice(0, -1).join(", ") + ", and " + reasons[reasons.length - 1]
        : reasons[0];

    if (verdict === "Low Risk") {
      return "This email shows low-risk signals, but still verify through official channels before sharing personal information.";
    }

    if (verdict === "High Risk") {
      const suffix = joined ? ` It ${joined}.` : "";
      return `This email contains strong risk patterns.${suffix} Do not pay or share sensitive information.`;
    }

    // Needs Verification
    const suffix = joined ? ` It ${joined}.` : "";
    return `This email has unclear or risky patterns and should be verified before acting.${suffix}`;
  }

  function buildNextSteps(verdict, hitIds, trustSignals) {
    const steps = [];

    if (verdict === "Low Risk") {
      steps.push("Still confirm the recruiter and company on LinkedIn before sharing personal documents.");
      steps.push("Ask for an official offer letter and onboarding plan in writing.");
      steps.push("Keep a copy of all communication until your internship is confirmed.");
    } else {
      if (hitIds.has("payment")) {
        steps.push('Do not pay any registration, training, enrollment, or "refundable" fee - legitimate internships do not charge candidates to join.');
      }
      if (hitIds.has("instructions")) {
        steps.push('Ignore requests to send payment screenshots or to keep the offer "confidential" - both are common pressure tactics.');
      }
      if (hitIds.has("links")) {
        steps.push("Avoid clicking shortened or unfamiliar links. Search for the company directly instead of following the link.");
      }
      if (hitIds.has("vague")) {
        steps.push("Ask the sender to confirm the project, team, mentor, and stipend details in writing before you agree to anything.");
      }
      if (hitIds.has("unrealistic")) {
        steps.push("Be skeptical of guaranteed placements, instant selection, or salary figures pitched before any real evaluation.");
      }

      steps.push('Search the company name along with "reviews" or "scam" before replying.');
      steps.push("Never share bank details, UPI PIN, OTP, Aadhaar, or card numbers with a recruiter.");
    }

    if (trustSignals.length > 0 && verdict !== "Low Risk") {
      steps.push("This email also shows some positive signals - but verify them independently through the company's official website rather than relying on the email alone.");
    }

    return steps;
  }

  function buildReply() {
    return "Hello, thank you for the opportunity. Before proceeding, I would like to confirm whether there are any registration fees, internship fees, training fees, certificate charges, onboarding charges, or any other payment required from the candidate. Kindly also share the official company website, internship responsibilities, stipend details, and selection process.\n\nRegards,\nIshan Prajapati";
  }

  /* ---------------------------------------------------
     4. DOM wiring
     --------------------------------------------------- */
  const els = {
    input: document.getElementById("email-input"),
    charCount: document.getElementById("char-count"),
    analyzeBtn: document.getElementById("analyze-btn"),
    clearBtn: document.getElementById("clear-btn"),
    sampleChips: document.querySelectorAll(".chip[data-sample]"),

    resultEmpty: document.getElementById("result-empty"),
    resultContent: document.getElementById("result-content"),
    gaugeFill: document.getElementById("gauge-fill"),
    gaugeValue: document.getElementById("gauge-value"),
    verdictBadge: document.getElementById("verdict-badge"),
    resultSummary: document.getElementById("result-summary"),
    flagList: document.getElementById("flag-list"),
    trustList: document.getElementById("trust-list"),
    stepsList: document.getElementById("steps-list"),
    replyBox: document.getElementById("reply-box"),
    copyReplyBtn: document.getElementById("copy-reply-btn"),
    copyReportBtn: document.getElementById("copy-report-btn"),

    aiReviewBtn: document.getElementById("ai-review-btn"),
    aiReviewBox: document.getElementById("ai-review-box"),

    historyList: document.getElementById("history-list"),
    historyEmpty: document.getElementById("history-empty"),
    clearHistoryBtn: document.getElementById("clear-history-btn"),
  };

  const GAUGE_CIRCUMFERENCE = 314.16;
  const VERDICT_COLORS = {
    "Low Risk": "var(--safe)",
    "Needs Verification": "var(--suspicious)",
    "High Risk": "var(--risk)",
  };
  const VERDICT_CLASSES = {
    "Low Risk": "low-risk",
    "Needs Verification": "needs-verification",
    "High Risk": "high-risk",
  };

  const HISTORY_KEY = "internguard_history";
  const MAX_HISTORY = 12;

  // v1 used "Safe" / "Suspicious" labels - map old history entries
  // to the new labels so they still render correctly.
  const LEGACY_VERDICT_MAP = {
    Safe: "Low Risk",
    Suspicious: "Needs Verification",
    "High Risk": "High Risk",
  };

  function normalizeVerdict(verdict) {
    return LEGACY_VERDICT_MAP[verdict] || verdict;
  }

  let latestEmailText = "";
  let lastResult = null;

  /* --- Char count --- */
  els.input.addEventListener("input", () => {
    const len = els.input.value.length;
    els.charCount.textContent = `${len.toLocaleString()} character${len === 1 ? "" : "s"}`;
  });

  /* --- Sample chips --- */
  els.sampleChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const key = chip.getAttribute("data-sample");
      els.input.value = SAMPLE_EMAILS[key] || "";
      els.input.dispatchEvent(new Event("input"));
      els.input.focus();
    });
  });

  /* --- Clear --- */
  els.clearBtn.addEventListener("click", () => {
    els.input.value = "";
    els.input.dispatchEvent(new Event("input"));
    els.input.focus();
  });

  /* --- Analyze --- */
  els.analyzeBtn.addEventListener("click", () => {
    const raw = els.input.value.trim();
    if (!raw) {
      els.input.focus();
      els.input.classList.add("input-error");
      setTimeout(() => els.input.classList.remove("input-error"), 600);
      return;
    }

    const result = analyzeEmail(raw);
    latestEmailText = raw;
    lastResult = result;
    renderResult(result);
    resetAiReviewBox();
    saveToHistory(raw, result);
    renderHistory();
  });

  /* --- Render result --- */
  function renderResult(result) {
    els.resultEmpty.hidden = true;
    els.resultContent.hidden = false;

    // Gauge
    const offset = GAUGE_CIRCUMFERENCE * (1 - result.score / 100);
    els.gaugeFill.style.strokeDashoffset = String(offset);
    els.gaugeFill.style.stroke = VERDICT_COLORS[result.verdict];
    els.gaugeValue.textContent = result.score;

    // Verdict badge
    els.verdictBadge.textContent = result.verdict;
    els.verdictBadge.className = "verdict-badge " + (VERDICT_CLASSES[result.verdict] || "");

    // Summary
    els.resultSummary.textContent = result.summary;

    // Red flags
    els.flagList.innerHTML = "";
    if (result.flags.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No red flags detected.";
      li.classList.add("flag-none");
      els.flagList.appendChild(li);
    } else {
      result.flags.forEach((flag) => {
        const li = document.createElement("li");
        li.textContent = flag.text;
        if (flag.severity === "low" || flag.severity === "medium") {
          li.classList.add("flag-low");
        }
        els.flagList.appendChild(li);
      });
    }

    // Trust signals
    els.trustList.innerHTML = "";
    if (result.trustSignals.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No strong trust signals detected.";
      li.classList.add("trust-none");
      els.trustList.appendChild(li);
    } else {
      result.trustSignals.forEach((signal) => {
        const li = document.createElement("li");
        li.textContent = signal.text;
        els.trustList.appendChild(li);
      });
    }

    // Steps
    els.stepsList.innerHTML = "";
    result.nextSteps.forEach((step) => {
      const li = document.createElement("li");
      li.textContent = step;
      els.stepsList.appendChild(li);
    });

    // Reply
    els.replyBox.textContent = result.reply;

    els.resultContent.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  /* --- Copy buttons --- */
  els.copyReplyBtn.addEventListener("click", () => {
    if (!lastResult) return;
    copyText(lastResult.reply, els.copyReplyBtn, "Copy reply");
  });

  els.copyReportBtn.addEventListener("click", () => {
    if (!lastResult) return;
    const r = lastResult;
    const report = [
      "InternGuard AI - Email Risk Report",
      "------------------------------------",
      `Risk score: ${r.score} / 100`,
      `Verdict: ${r.verdict}`,
      "",
      "Summary:",
      r.summary,
      "",
      "Red flags:",
      r.flags.length ? r.flags.map((f) => `- ${f.text}`).join("\n") : "- None detected",
      "",
      "Trust signals:",
      r.trustSignals.length ? r.trustSignals.map((t) => `- ${t.text}`).join("\n") : "- None detected",
      "",
      "Safe next steps:",
      r.nextSteps.map((s) => `- ${s}`).join("\n"),
      "",
      "Suggested reply:",
      r.reply,
    ].join("\n");
    copyText(report, els.copyReportBtn, "Copy full report");
  });

  function copyText(text, button, originalLabel) {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        button.textContent = "Copied!";
        setTimeout(() => (button.textContent = originalLabel), 1500);
      })
      .catch(() => {
        button.textContent = "Couldn't copy";
        setTimeout(() => (button.textContent = originalLabel), 1500);
      });
  }

  /* ---------------------------------------------------
     5. AI pipeline (optional, second layer)

     InternGuard AI uses a hybrid pipeline:

       1. The user pastes an internship/job email and clicks
          "Analyze email".
       2. The LOCAL rule-based engine (sections 1-3 above) runs
          first, entirely in the browser.
       3. It produces: risk signals (flags), trust signals,
          a risk score (0-100), a verdict, and safe next steps.
       4. This rule-based result is shown immediately and works
          with zero network requests - it is the main result and
          always available, even with no backend deployed.
       5. The user can OPTIONALLY click "Ask AI for deeper review".
       6. That calls requestAiAnalysis(emailText, ruleResult) below.
       7. requestAiAnalysis() sends a POST request to /api/analyze
          with the original email text AND the structured
          rule-based result (score, verdict, flags, trust signals).
       8. api/analyze.js (serverless function) reads the API key
          from Vercel environment variables - never from the
          frontend - and, if configured, asks an AI model to
          review the email USING the rule-based result as context.
       9. The AI does not re-score the email from scratch and does
          not override the rule-based verdict; it explains and adds
          a verification checklist on top of it.
      10. The AI response is rendered as aiSummary,
          verificationChecklist, and finalAdvice, clearly separate
          from the rule-based report above.
      11. If no API key is configured, or the request fails for any
          reason, the UI shows a friendly message and the
          rule-based result above remains fully usable.

     The rule-based analyzer is the source of truth. The AI layer
     is an optional explanation/verification aid, never the final
     authority on whether an email is real or fake.
     --------------------------------------------------- */
  const AI_NOT_CONFIGURED_MESSAGE =
    "AI review is not configured yet. The rule-based analysis above is still available and works offline.";

  function resetAiReviewBox() {
    els.aiReviewBox.hidden = true;
    els.aiReviewBox.innerHTML = "";
    els.aiReviewBtn.disabled = false;
    els.aiReviewBtn.textContent = "Ask AI for deeper review";
  }

  els.aiReviewBtn.addEventListener("click", () => {
    if (!lastResult) return;
    requestAiAnalysis(latestEmailText, lastResult);
  });

  async function requestAiAnalysis(emailText, ruleResult) {
    els.aiReviewBox.hidden = false;
    els.aiReviewBox.innerHTML = "";
    els.aiReviewBox.appendChild(buildAiStatus("Asking AI for a deeper review..."));
    els.aiReviewBtn.disabled = true;
    els.aiReviewBtn.textContent = "Asking AI...";

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          emailText,
          ruleResult: serializeRuleResult(ruleResult),
        }),
      });

      if (!response.ok) {
        showAiUnavailable();
        return;
      }

      const data = await response.json();

      if (!data || data.configured === false) {
        showAiUnavailable(data && data.message);
        return;
      }

      if (data.error) {
        showAiUnavailable(
          "AI review is configured, but the AI request failed. Check the OpenAI API key, billing or credits, and model access, then redeploy if the key changed."
        );
        return;
      }

      renderAiReview(data);
    } catch (err) {
      showAiUnavailable();
    } finally {
      els.aiReviewBtn.disabled = false;
      els.aiReviewBtn.textContent = "Ask AI for deeper review";
    }
  }

  function serializeRuleResult(result) {
    return {
      score: result.score,
      verdict: result.verdict,
      flags: result.flags.map((f) => f.text),
      trustSignals: result.trustSignals.map((t) => t.text),
      hitCategories: Array.from(result.hitIds),
    };
  }

  function buildAiStatus(text) {
    const p = document.createElement("p");
    p.className = "ai-status";
    p.textContent = text;
    return p;
  }

  function showAiUnavailable(message) {
    els.aiReviewBox.innerHTML = "";
    els.aiReviewBox.appendChild(buildAiStatus(message || AI_NOT_CONFIGURED_MESSAGE));
  }

  function renderAiReview(data) {
    els.aiReviewBox.innerHTML = "";

    if (data.aiSummary) {
      const summary = document.createElement("p");
      summary.className = "ai-summary";
      summary.textContent = data.aiSummary;
      els.aiReviewBox.appendChild(summary);
    }

    const checklist = Array.isArray(data.verificationChecklist) ? data.verificationChecklist : [];
    if (checklist.length > 0) {
      const heading = document.createElement("h5");
      heading.textContent = "Verification checklist";
      els.aiReviewBox.appendChild(heading);

      const ul = document.createElement("ul");
      ul.className = "ai-checklist";
      checklist.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        ul.appendChild(li);
      });
      els.aiReviewBox.appendChild(ul);
    }

    if (data.finalAdvice) {
      const advice = document.createElement("p");
      advice.className = "ai-advice";
      advice.textContent = data.finalAdvice;
      els.aiReviewBox.appendChild(advice);
    }

    if (!data.aiSummary && checklist.length === 0 && !data.finalAdvice) {
      els.aiReviewBox.appendChild(buildAiStatus(AI_NOT_CONFIGURED_MESSAGE));
    }
  }

  /* ---------------------------------------------------
     6. History (localStorage)
     --------------------------------------------------- */
  function loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) {
      return [];
    }
  }

  function saveToHistory(rawText, result) {
    const history = loadHistory();
    const snippet = rawText.replace(/\s+/g, " ").trim().slice(0, 140);

    history.unshift({
      date: new Date().toISOString(),
      score: result.score,
      verdict: result.verdict,
      snippet,
    });

    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
  }

  function renderHistory() {
    const history = loadHistory();
    els.historyList.innerHTML = "";

    if (history.length === 0) {
      els.historyEmpty.hidden = false;
      els.historyList.appendChild(els.historyEmpty);
      return;
    }

    els.historyEmpty.hidden = true;

    history.forEach((entry) => {
      const verdict = normalizeVerdict(entry.verdict);

      const card = document.createElement("div");
      card.className = "history-card";

      const score = document.createElement("div");
      score.className = "history-score";
      score.textContent = entry.score;
      score.style.color = VERDICT_COLORS[verdict] || "var(--ink)";

      const meta = document.createElement("div");
      meta.className = "history-meta";

      const date = document.createElement("span");
      date.className = "history-date";
      date.textContent = formatDate(entry.date);

      const snippet = document.createElement("p");
      snippet.className = "history-snippet";
      snippet.textContent = entry.snippet || "(no preview)";

      meta.appendChild(date);
      meta.appendChild(snippet);

      const badge = document.createElement("span");
      badge.className = "verdict-badge " + (VERDICT_CLASSES[verdict] || "");
      badge.textContent = verdict;

      card.appendChild(score);
      card.appendChild(meta);
      card.appendChild(badge);

      els.historyList.appendChild(card);
    });
  }

  function formatDate(iso) {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  els.clearHistoryBtn.addEventListener("click", () => {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  });

  /* ---------------------------------------------------
     7. Init
     --------------------------------------------------- */
  renderHistory();
})();
