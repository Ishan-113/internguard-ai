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
    let score = 0;
    const flags = [];
    const hitIds = new Set();

    RISK_RULES.forEach((rule) => {
      if (rule.test) {
        const result = rule.test(rawText, text);
        if (result) {
          score += rule.weight;
          hitIds.add(rule.id);
          flags.push({ text: result, severity: rule.severity });
        }
        return;
      }

      const matched = rule.keywords.find((kw) => text.includes(kw));
      if (matched) {
        score += rule.weight;
        hitIds.add(rule.id);
        flags.push({ text: rule.describe(matched), severity: rule.severity });
      }
    });

    score = Math.min(100, score);

    let verdict;
    if (score >= 70) verdict = "High Risk";
    else if (score >= 31) verdict = "Suspicious";
    else verdict = "Safe";

    return {
      score,
      verdict,
      flags,
      hitIds,
      summary: buildSummary(verdict, hitIds),
      nextSteps: buildNextSteps(verdict, hitIds),
      reply: buildReply(),
    };
  }

  function buildSummary(verdict, hitIds) {
    if (verdict === "Safe") {
      return "This email doesn't show the common red flags of internship scams - no payment requests, vague onboarding, or unrealistic promises were detected. It's still worth double-checking the company independently before sharing personal documents.";
    }

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

    if (verdict === "High Risk") {
      return `This email looks high risk because it ${joined}. Treat it as a likely scam - don't send money, documents, or OTPs.`;
    }
    return `This email looks suspicious because it ${joined}. Verify carefully before you respond, click any link, or share information.`;
  }

  function buildNextSteps(verdict, hitIds) {
    const steps = [];

    if (verdict === "Safe") {
      steps.push("Still confirm the recruiter and company on LinkedIn before sharing personal documents.");
      steps.push("Ask for an official offer letter and onboarding plan in writing.");
      steps.push("Keep a copy of all communication until your internship is confirmed.");
      return steps;
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
    steps.push("Never share bank details, UPI PIN, OTP, Aadhaar, or card numbers with a recruiter.");

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
    stepsList: document.getElementById("steps-list"),
    replyBox: document.getElementById("reply-box"),
    copyReplyBtn: document.getElementById("copy-reply-btn"),
    copyReportBtn: document.getElementById("copy-report-btn"),

    historyList: document.getElementById("history-list"),
    historyEmpty: document.getElementById("history-empty"),
    clearHistoryBtn: document.getElementById("clear-history-btn"),
  };

  const GAUGE_CIRCUMFERENCE = 314.16;
  const VERDICT_COLORS = {
    Safe: "var(--safe)",
    Suspicious: "var(--suspicious)",
    "High Risk": "var(--risk)",
  };
  const VERDICT_CLASSES = {
    Safe: "safe",
    Suspicious: "suspicious",
    "High Risk": "high-risk",
  };

  const HISTORY_KEY = "internguard_history";
  const MAX_HISTORY = 12;

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
    lastResult = result;
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
      const card = document.createElement("div");
      card.className = "history-card";

      const score = document.createElement("div");
      score.className = "history-score";
      score.textContent = entry.score;
      score.style.color = VERDICT_COLORS[entry.verdict] || "var(--ink)";

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
      badge.className = "verdict-badge " + (VERDICT_CLASSES[entry.verdict] || "");
      badge.textContent = entry.verdict;

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
     6. Init
     --------------------------------------------------- */
  renderHistory();
})();
