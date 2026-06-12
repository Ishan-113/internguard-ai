/* =========================================================
   InternGuard AI — rule-based email risk analyzer
   Everything runs locally in the browser. Nothing is sent
   anywhere, and scan history is stored only in localStorage.
   ========================================================= */

(function () {
  "use strict";

  /* ---------------------------------------------------
     1. Risk rules
     Each rule contributes a fixed weight to the score if
     it fires. Weights sum to 100 so the score always sits
     between 0 and 100.
     --------------------------------------------------- */
  const RISK_RULES = [
    {
      id: "payment",
      weight: 35,
      severity: "high",
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
        "send a screenshot",
        "reply with a screenshot",
        "share a screenshot",
        "share screenshot",
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
        "shared after payment",
        "shared post payment",
        "assigned later",
        "details after enrollment",
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

  const TRUST_RULES = [
    {
      id: "official_or_clear_domain",
      points: -10,
      keywords: ["google.com", "hackerrank.com", "microsoft.com", "github.com", "linkedin.com", "vercel.com"],
      describe: (kw) =>
        `Mentions a recognizable domain (${kw}). This is only a weak trust signal and does not prove the email is genuine.`,
    },
    {
      id: "no_payment_required",
      points: -15,
      keywords: [
        "no payment required",
        "no fees",
        "free to register",
        "free registration",
        "no charges",
        "no registration fee",
      ],
      describe: (kw) => `States that no payment or registration fee is required ("${kw}").`,
    },
    {
      id: "clear_program_details",
      points: -5,
      keywords: [
        "eligibility",
        "selection process",
        "timeline",
        "program details",
        "official website",
        "terms and conditions",
      ],
      describe: (kw) => `Includes clearer program or verification details ("${kw}").`,
    },
    {
      id: "interview_or_evaluation_based",
      points: -5,
      keywords: ["interview", "assessment", "coding test", "shortlisted after review", "evaluation"],
      describe: (kw) => `Mentions an interview, assessment, or review-based selection step ("${kw}").`,
    },
  ];

  /* ---------------------------------------------------
     2. Sample emails (also saved under sample-emails/*.txt)
     --------------------------------------------------- */
  // Demo samples use fictional company names for safe public sharing.
     const SAMPLE_EMAILS = {
    safe: `Subject: Frontend Developer Intern Opportunity - TechNova Solutions

Hi Ishan,

Thank you for applying to the Frontend Developer Internship at TechNova Solutions. We reviewed your portfolio and would like to invite you for a short video interview with our engineering team.

Role: Frontend Developer Intern
Duration: 8 weeks
Mode: Remote
Stipend: ₹8,000 per month, paid at the end of each month

There are no charges of any kind at any stage of our hiring or onboarding process. If selected, you'll receive an offer letter on company letterhead and an NDA before your first day.

You can verify our company details at www.technova-solutions.com or on our LinkedIn page.

Please reply with your availability for a 20-minute call this week.

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

We are pleased to inform you that you have been selected for the Web Development Internship at CloudEdge Internship Services.

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
  function analyzeEmail(rawText) {
    const text = rawText.toLowerCase();
    let riskScore = 0;
    const flags = [];
    const hitIds = new Set();

    RISK_RULES.forEach((rule) => {
      if (rule.test) {
        const result = rule.test(rawText, text);
        if (result) {
          riskScore += rule.weight;
          hitIds.add(rule.id);
          flags.push({ text: result, severity: rule.severity });
        }
        return;
      }

      const matched = rule.keywords.find((kw) => text.includes(kw) && !isNegatedRiskKeyword(rule.id, kw, text));
      if (matched) {
        riskScore += rule.weight;
        hitIds.add(rule.id);
        flags.push({ text: rule.describe(matched), severity: rule.severity });
      }
    });

    riskScore = clampScore(riskScore);

    const trustSignals = [];
    const trustAdjustment = TRUST_RULES.reduce((total, rule) => {
      const matched = rule.keywords.find((kw) => text.includes(kw));
      if (!matched) return total;

      trustSignals.push({
        text: rule.describe(matched),
        points: rule.points,
      });
      return total + rule.points;
    }, 0);

    let score = clampScore(riskScore + trustAdjustment);

    if (hitIds.has("payment") && hitIds.has("instructions")) {
      score = Math.max(score, 70);
    } else if (hitIds.has("payment")) {
      score = Math.max(score, 55);
    }

    score = clampScore(score);
    const verdict = getVerdict(score);

    return {
      score,
      rawRiskScore: riskScore,
      trustAdjustment,
      verdict,
      flags,
      hitIds: Array.from(hitIds),
      trustSignals,
      summary: buildSummary(verdict, hitIds, trustSignals),
      nextSteps: buildNextSteps(verdict, hitIds),
      reply: buildReply(),
    };
  }

  function isNegatedRiskKeyword(ruleId, keyword, text) {
    if (ruleId !== "payment") return false;

    const noPaymentPhrases = [
      "no payment required",
      "no fees",
      "free to register",
      "free registration",
      "no charges",
      "no registration fee",
      "no internship fee",
      "no training fee",
      "no certificate fee",
      "no enrollment fee",
      "no enrolment fee",
      "no processing fee",
      "no confirmation fee",
      "no security deposit",
      "no refundable deposit",
    ];

    return noPaymentPhrases.some((phrase) => phrase.includes(keyword) && text.includes(phrase));
  }

  function clampScore(value) {
    return Math.max(0, Math.min(100, Math.round(value)));
  }

  function getVerdict(score) {
    if (score >= 70) return "High Risk";
    if (score >= 31) return "Needs Verification";
    return "Low Risk";
  }

  function buildSummary(verdict, hitIds, trustSignals) {
    const reasons = [];
    if (hitIds.has("payment")) reasons.push("asks you to pay before onboarding");
    if (hitIds.has("instructions")) reasons.push("gives suspicious instructions, like sending a payment screenshot");
    if (hitIds.has("unrealistic")) reasons.push("makes promises about placement or salary that sound too good to be true");
    if (hitIds.has("vague")) reasons.push("keeps key project, team, or stipend details vague until after you commit");
    if (hitIds.has("links")) reasons.push("uses a shortened or generic link instead of the company's own domain");
    if (hitIds.has("poor_language")) reasons.push("has the generic tone and wording typical of mass-sent offers");

    const redFlagText =
      reasons.length > 0
        ? ` Red flags found: ${joinAsSentence(reasons)}.`
        : " No major red flags were detected by the rule-based scan.";
    const trustText =
      trustSignals.length > 0
        ? ` Trust signals found: ${trustSignals.length}. These only lower the score slightly and never prove an email is genuine.`
        : " No strong trust signals were found.";

    if (verdict === "Low Risk") {
      return `This email shows low-risk signals, but still verify through official channels.${redFlagText}${trustText}`;
    }
    if (verdict === "Needs Verification") {
      return `This email has some unclear or risky patterns and should be verified before acting.${redFlagText}${trustText}`;
    }
    if (verdict === "High Risk") {
      return `This email contains strong risk patterns. Do not pay or share sensitive information.${redFlagText}${trustText}`;
    }

    return `This email should be verified before acting.${redFlagText}${trustText}`;
  }

  function joinAsSentence(items) {
    if (items.length <= 1) return items[0] || "";
    return items.slice(0, -1).join(", ") + ", and " + items[items.length - 1];
  }

  function buildNextSteps(verdict, hitIds) {
    const steps = [];

    if (verdict === "Low Risk") {
      steps.push("Verify the sender through the official company site or a clear company-owned domain.");
      steps.push("Check the company's verified LinkedIn or careers page before sharing personal documents.");
      steps.push("Keep a copy of all communication until your internship is confirmed.");
      return steps;
    }

    if (verdict === "Needs Verification") {
      steps.push("Check the sender domain, official website, and verified LinkedIn page before replying.");
      steps.push("Ask for written confirmation that no payment, fee, or deposit is required.");
      steps.push("Request the selection process, role details, stipend, and onboarding timeline in writing.");
    }

    if (verdict === "High Risk") {
      steps.push("Do not pay any registration, training, certificate, enrollment, or refundable deposit fee.");
      steps.push("Do not share bank details, UPI PIN, OTP, Aadhaar, card numbers, or sensitive documents.");
      steps.push("Verify the opportunity independently through the official company website or verified company contact.");
    }

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
    steps.push("If anything feels unclear, contact the company through a public official channel instead of the email thread.");

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
    "Low Risk": "safe",
    "Needs Verification": "needs-verification",
    "High Risk": "high-risk",
  };

  const HISTORY_KEY = "internguard_history";
  const MAX_HISTORY = 12;

  let lastResult = null;
  let lastEmailText = "";

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
    lastResult = result;
    lastEmailText = raw;
    renderResult(result);
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

    // Flags
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

    resetAiReview();

    els.resultContent.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function resetAiReview() {
    if (!els.aiReviewBox) return;
    els.aiReviewBox.hidden = true;
    els.aiReviewBox.classList.remove("ai-review-error", "ai-review-loading");
    els.aiReviewBox.textContent = "";
  }

  function setAiReviewLoading() {
    els.aiReviewBox.hidden = false;
    els.aiReviewBox.classList.remove("ai-review-error");
    els.aiReviewBox.classList.add("ai-review-loading");
    els.aiReviewBox.textContent = "Checking whether optional AI review is available...";
  }

  async function requestAiAnalysis(emailText, ruleResult) {
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          emailText,
          ruleResult: serializeRuleResult(ruleResult),
        }),
      });

      const contentType = response.headers.get("content-type") || "";
      if (!response.ok || !contentType.includes("application/json")) {
        return buildAiUnavailableReview();
      }

      const data = await response.json();
      return {
        aiSummary: data.aiSummary || "AI review did not return a summary.",
        verificationChecklist: Array.isArray(data.verificationChecklist) ? data.verificationChecklist : [],
        finalAdvice:
          data.finalAdvice ||
          "Use the rule-based result above as the main safety signal and verify through official channels.",
      };
    } catch (error) {
      return buildAiUnavailableReview();
    }
  }

  function serializeRuleResult(result) {
    return {
      score: result.score,
      rawRiskScore: result.rawRiskScore,
      trustAdjustment: result.trustAdjustment,
      verdict: result.verdict,
      flags: result.flags,
      trustSignals: result.trustSignals,
      summary: result.summary,
      nextSteps: result.nextSteps,
    };
  }

  function buildAiUnavailableReview() {
    return {
      error: true,
      aiSummary:
        "Optional AI review is not configured yet or could not be reached. The rule-based scan above still works fully in your browser.",
      verificationChecklist: [
        "Verify the sender domain against the official company website.",
        "Check the company's verified LinkedIn or careers page.",
        "Ask for written confirmation that no payment or deposit is required.",
      ],
      finalAdvice: "Do not rely on AI alone. Treat the rule-based result and independent verification as the main safety checks.",
    };
  }

  function renderAiReview(review) {
    els.aiReviewBox.hidden = false;
    els.aiReviewBox.classList.remove("ai-review-loading");
    els.aiReviewBox.classList.toggle("ai-review-error", Boolean(review.error));
    els.aiReviewBox.innerHTML = "";

    const summary = document.createElement("p");
    summary.textContent = review.aiSummary;
    els.aiReviewBox.appendChild(summary);

    if (review.verificationChecklist.length > 0) {
      const heading = document.createElement("h5");
      heading.textContent = "Verification checklist";
      els.aiReviewBox.appendChild(heading);

      const list = document.createElement("ul");
      review.verificationChecklist.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        list.appendChild(li);
      });
      els.aiReviewBox.appendChild(list);
    }

    const advice = document.createElement("p");
    advice.className = "ai-final-advice";
    advice.textContent = review.finalAdvice;
    els.aiReviewBox.appendChild(advice);
  }

  /* --- Copy buttons --- */
  if (els.aiReviewBtn) {
    els.aiReviewBtn.addEventListener("click", async () => {
      if (!lastResult || !lastEmailText) return;

      setAiReviewLoading();
      els.aiReviewBtn.disabled = true;

      const review = await requestAiAnalysis(lastEmailText, lastResult);
      renderAiReview(review);

      els.aiReviewBtn.disabled = false;
    });
  }

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
      r.trustSignals.length ? r.trustSignals.map((s) => `- ${s.text}`).join("\n") : "- No strong trust signals detected",
      "",
      "Recommended next steps:",
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
     5. History (localStorage)
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

  function normalizeVerdict(verdict) {
    if (verdict === "Safe") return "Low Risk";
    if (verdict === "Suspicious") return "Needs Verification";
    return verdict;
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
     6. Init
     --------------------------------------------------- */
  renderHistory();
})();
