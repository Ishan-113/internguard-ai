/**
 * InternGuard AI - optional AI review endpoint
 *
 * Vercel exposes this serverless function at /api/analyze.
 * The browser rule-based analyzer works without this endpoint.
 */

const SYSTEM_PROMPT = `You are a safety reviewer inside InternGuard AI, a tool that helps students assess internship and job offer emails.

You will be given:
- the original email text
- a rule-based risk analysis with a score, verdict, detected risk signals, and detected trust signals

Follow these rules strictly:
1. Do not create a new score. Do not override or contradict the rule-based verdict.
2. Do not say the email is definitely real, fake, genuine, or a scam. Discuss risk signals, trust signals, and verification steps only.
3. Always recommend verifying through the company's official website, official domain email, and official LinkedIn page instead of links in the email.
4. Never tell the user to pay a fee, deposit, or charge.
5. Never ask the user to share passwords, OTPs, bank details, card numbers, Aadhaar, or similar sensitive data.
6. Keep the tone concise, calm, and student-friendly.

Respond with only a JSON object in this exact shape:
{
  "aiSummary": "2-3 sentence explanation of what the rule-based result means",
  "verificationChecklist": ["short actionable verification step", "..."],
  "finalAdvice": "1-2 sentence closing recommendation consistent with the rule-based verdict"
}`;

const NOT_CONFIGURED_MESSAGE =
  "AI review is not configured yet. The rule-based analysis above is still available and works offline.";

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ configured: false, message: "Method not allowed. Use POST." });
    return;
  }

  const apiKey = process.env.OPENAI_API_KEY || process.env.AI_API_KEY;

  if (!apiKey) {
    res.status(200).json({
      configured: false,
      message: NOT_CONFIGURED_MESSAGE,
    });
    return;
  }

  const body = parseBody(req.body);
  const emailText = typeof body.emailText === "string" ? body.emailText : "";
  const ruleResult = body.ruleResult && typeof body.ruleResult === "object" ? body.ruleResult : {};

  if (!emailText.trim()) {
    res.status(400).json({ configured: true, error: "Missing emailText." });
    return;
  }

  try {
    const apiBaseUrl = (process.env.AI_API_BASE_URL || "https://api.openai.com/v1").replace(/\/+$/, "");
    const response = await fetch(`${apiBaseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: process.env.AI_MODEL || "gpt-4o-mini",
        temperature: 0.2,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          {
            role: "user",
            content: JSON.stringify(
              {
                emailText,
                ruleBasedResult: {
                  score: ruleResult.score,
                  verdict: ruleResult.verdict,
                  redFlags: Array.isArray(ruleResult.flags) ? ruleResult.flags : [],
                  trustSignals: Array.isArray(ruleResult.trustSignals) ? ruleResult.trustSignals : [],
                  riskCategoriesTriggered: Array.isArray(ruleResult.hitCategories) ? ruleResult.hitCategories : [],
                },
              },
              null,
              2
            ),
          },
        ],
      }),
    });

    if (!response.ok) {
      res.status(200).json({ configured: true, error: "AI request failed." });
      return;
    }

    const data = await response.json();
    const content = data?.choices?.[0]?.message?.content || "";
    const parsed = parseJson(content);

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
  } catch (error) {
    res.status(200).json({ configured: true, error: "AI request failed." });
  }
};

function parseBody(body) {
  if (!body) return {};
  if (typeof body === "object") return body;
  if (typeof body !== "string") return {};
  return parseJson(body) || {};
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch (error) {
    return null;
  }
}
