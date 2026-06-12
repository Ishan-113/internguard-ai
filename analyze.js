/**
 * InternGuard AI - optional AI review endpoint
 * --------------------------------------------
 * This is the second layer of the hybrid pipeline. The rule-based
 * analyzer in app.js always runs first, in the browser, and never
 * depends on this file. This endpoint adds an OPTIONAL AI-assisted
 * explanation on top of that rule-based result.
 *
 * Request body (JSON), sent by requestAiAnalysis() in app.js:
 *   {
 *     emailText: string,
 *     ruleResult: {
 *       score: number,            // 0-100, from the rule-based engine
 *       verdict: string,          // "Low Risk" | "Needs Verification" | "High Risk"
 *       flags: string[],          // risk signals already detected
 *       trustSignals: string[],   // trust signals already detected
 *       hitCategories: string[]   // ids of risk categories that fired
 *     }
 *   }
 *
 * Response (JSON):
 *   - Not configured:
 *       { configured: false, message: "AI review is not configured yet." }
 *   - Configured, success:
 *       {
 *         configured: true,
 *         aiSummary: string,
 *         verificationChecklist: string[],
 *         finalAdvice: string
 *       }
 *   - Configured, but the AI call itself failed:
 *       { configured: true, error: "..." }
 *
 * SECURITY:
 *   - The API key is read ONLY from environment variables
 *     (OPENAI_API_KEY or AI_API_KEY), set in the Vercel project's
 *     Environment Variables settings. It is never read from, or
 *     sent to, the frontend.
 *   - This file contains NO real API key. Deploying it with no key
 *     configured is safe - it simply returns { configured: false }.
 */

const SYSTEM_PROMPT = `You are a safety reviewer inside InternGuard AI, a tool that helps students assess internship and job offer emails.

You will be given:
- the original email text
- a rule-based risk analysis that already includes a risk score (0-100), a verdict, detected risk signals (red flags), and detected trust signals

Your job is to ADD a short, second-opinion explanation on top of that rule-based result. Follow these rules strictly:

1. Do NOT invent a new score and do NOT contradict or override the rule-based verdict. Treat the rule-based score and verdict as the primary result; your role is to explain it and add verification guidance.
2. Do NOT state with certainty whether the email is "real" or "fake" / "genuine" or "a scam". Only describe risk and trust signals and what they suggest.
3. Always recommend verifying the opportunity through the company's OFFICIAL website, official domain email, and official LinkedIn page - never through links provided in the email itself.
4. NEVER tell the user to pay any fee, deposit, or charge, under any circumstance.
5. NEVER ask the user for, or suggest sharing, sensitive data (passwords, OTPs, bank details, card numbers, Aadhaar, etc).
6. Keep the tone concise, calm, and student-friendly. No fear-mongering, no legal claims.

Respond with ONLY a JSON object (no markdown, no code fences) in this exact shape:
{
  "aiSummary": "2-3 sentence explanation of what the rule-based result means in plain language",
  "verificationChecklist": ["short actionable verification step", "..."],
  "finalAdvice": "1-2 sentence closing recommendation, consistent with the rule-based verdict"
}`;

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ configured: false, message: "Method not allowed. Use POST." });
    return;
  }

  const apiKey = process.env.OPENAI_API_KEY || process.env.AI_API_KEY;

  // No key configured -> tell the frontend so it can fall back to the
  // rule-based result, which already works without this endpoint.
  if (!apiKey) {
    res.status(200).json({
      configured: false,
      message: "AI review is not configured yet.",
    });
    return;
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (e) {
      body = {};
    }
  }
  body = body || {};

  const emailText = typeof body.emailText === "string" ? body.emailText : "";
  const ruleResult = body.ruleResult || {};

  if (!emailText.trim()) {
    res.status(400).json({ configured: true, error: "Missing emailText." });
    return;
  }

  // Build the structured context the AI will use. The rule-based
  // result is passed in as-is, so the AI explains THIS result
  // rather than re-deriving its own score.
  const userPrompt = JSON.stringify(
    {
      emailText,
      ruleBasedResult: {
        score: ruleResult.score,
        verdict: ruleResult.verdict,
        redFlags: ruleResult.flags || [],
        trustSignals: ruleResult.trustSignals || [],
        riskCategoriesTriggered: ruleResult.hitCategories || [],
      },
    },
    null,
    2
  );

  try {
    const aiResponse = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        temperature: 0.3,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
        ],
      }),
    });

    if (!aiResponse.ok) {
      res.status(200).json({ configured: true, error: "AI request failed." });
      return;
    }

    const data = await aiResponse.json();
    const content = data && data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;

    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch (e) {
      parsed = null;
    }

    if (!parsed) {
      res.status(200).json({ configured: true, error: "AI returned an unexpected response." });
      return;
    }

    res.status(200).json({
      configured: true,
      aiSummary: typeof parsed.aiSummary === "string" ? parsed.aiSummary : "",
      verificationChecklist: Array.isArray(parsed.verificationChecklist) ? parsed.verificationChecklist : [],
      finalAdvice: typeof parsed.finalAdvice === "string" ? parsed.finalAdvice : "",
    });
  } catch (err) {
    res.status(200).json({ configured: true, error: "AI request failed." });
  }
};
