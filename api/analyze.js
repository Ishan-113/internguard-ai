/**
 * InternGuard AI - optional Gemini AI review endpoint
 * Vercel serverless function
 */

const SYSTEM_PROMPT = `You are a safety reviewer inside InternGuard AI, a tool that helps students assess internship and job offer emails.

You will be given:
- the original email text
- a rule-based risk analysis that already includes a risk score, verdict, red flags, and trust signals

Rules:
1. Do NOT invent a new score.
2. Do NOT contradict or override the rule-based verdict.
3. Do NOT say the email is definitely real or definitely fake.
4. Explain risk and trust signals clearly.
5. Never tell the user to pay money.
6. Never ask for OTP, bank details, card details, Aadhaar, passwords, or UPI PIN.
7. Recommend verifying through official company website, official domain email, and official LinkedIn.
8. Keep it concise and student-friendly.

Return ONLY valid JSON in this shape:
{
  "aiSummary": "2-3 sentence explanation",
  "verificationChecklist": ["step 1", "step 2", "step 3"],
  "finalAdvice": "1-2 sentence recommendation"
}`;

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      configured: false,
      message: "Method not allowed. Use POST.",
    });
  }

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    return res.status(200).json({
      configured: false,
      message:
        "AI review is not configured yet. The rule-based analysis above is still available and works offline.",
    });
  }

  let body = req.body;

  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }

  const emailText = typeof body.emailText === "string" ? body.emailText : "";
  const ruleResult = body.ruleResult || {};

  if (!emailText.trim()) {
    return res.status(400).json({
      configured: true,
      error: "Missing emailText.",
    });
  }

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
    const geminiResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key=${apiKey}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": apiKey,
        },
        body: JSON.stringify({
          contents: [
            {
              role: "user",
              parts: [
                {
                  text: `${SYSTEM_PROMPT}\n\nAnalyze this structured email risk report and return only JSON:\n\n${userPrompt}`,
                },
              ],
            },
          ],
          generationConfig: {
            temperature: 0.3,
            responseMimeType: "application/json",
          },
        }),
      }
    );

    if (!geminiResponse.ok) {
      const errorText = await geminiResponse.text();

      console.error(
        "Gemini API error:",
        geminiResponse.status,
        errorText.slice(0, 700)
      );

      return res.status(200).json({
        configured: true,
        error: `Gemini request failed with status ${geminiResponse.status}. Check Vercel Function Logs.`,
      });
    }

    const data = await geminiResponse.json();
    const content =
      data?.candidates?.[0]?.content?.parts?.[0]?.text || "";

    let parsed;

    try {
      parsed = JSON.parse(content);
    } catch {
      parsed = null;
    }

    if (!parsed) {
      return res.status(200).json({
        configured: true,
        error: "Gemini returned an unexpected response.",
      });
    }

    return res.status(200).json({
      configured: true,
      aiSummary: typeof parsed.aiSummary === "string" ? parsed.aiSummary : "",
      verificationChecklist: Array.isArray(parsed.verificationChecklist)
        ? parsed.verificationChecklist
        : [],
      finalAdvice:
        typeof parsed.finalAdvice === "string" ? parsed.finalAdvice : "",
    });
  } catch (err) {
    console.error("Gemini function error:", err);

    return res.status(200).json({
      configured: true,
      error: "Gemini request failed. Check Vercel Function Logs.",
    });
  }
};