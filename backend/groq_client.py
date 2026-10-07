import os
import json

from groq import Groq
from dotenv import load_dotenv


# ============================================================
# Environment
# ============================================================

load_dotenv()

GROQ_API_KEY = os.getenv(
    "GROQ_API_KEY"
)


# ============================================================
# Groq Client
# ============================================================

client = (
    Groq(api_key=GROQ_API_KEY)
    if GROQ_API_KEY
    else None
)


# ============================================================
# AI Security Assistant
# ============================================================

def get_chat_response(
    question: str,
    context: dict
) -> str:

    if not GROQ_API_KEY or client is None:

        return (
            "AI is disabled because "
            "GROQ_API_KEY is missing."
        )

    try:

        # ----------------------------------------------------
        # Extract report information
        # ----------------------------------------------------

        score = context.get(
            "score",
            "Unknown"
        )

        score_breakdown = context.get("score_breakdown", {})

        risk_level = context.get(
            "risk_level",
            "Unknown"
        )

        flags = context.get(
            "flags",
            []
        )

        vulnerabilities = context.get(
            "prioritized_vulnerabilities",
            []
        )

        repairs = context.get(
            "repair_suggestions",
            []
        )

        readiness = context.get(
            "deployment_readiness",
            {}
        )

        onchain = context.get(
            "onchain",
            {}
        )

        liquidity = context.get(
            "liquidity",
            {}
        )

        live_intelligence = context.get(
            "live_intelligence",
            {}
        )

        ml_predictions = (
            live_intelligence.get(
                "ml_predictions",
                []
            )
            if isinstance(
                live_intelligence,
                dict
            )
            else []
        )

        explanations = (
            live_intelligence.get(
                "explanations",
                {}
            )
            if isinstance(
                live_intelligence,
                dict
            )
            else {}
        )

        features = (
            live_intelligence.get(
                "features",
                {}
            )
            if isinstance(
                live_intelligence,
                dict
            )
            else {}
        )

        unified_findings = (
            live_intelligence.get(
                "unified_findings",
                []
            )
            if isinstance(
                live_intelligence,
                dict
            )
            else []
        )

        # ----------------------------------------------------
        # Compact report context
        # ----------------------------------------------------

        report_context = {

            "security_score": score,

            "risk_level": risk_level,
            "score_breakdown": score_breakdown,


            "red_flags": flags,

            "prioritized_vulnerabilities":
                vulnerabilities,

            "repair_suggestions":
                repairs,

            "deployment_readiness":
                readiness,

            "onchain":
                onchain,

            "liquidity":
                liquidity,

            "ml_predictions":
                ml_predictions,

            "explanations":
                explanations,

            "feature_count":
                len(features),

            "unified_findings":
                unified_findings,
        }

        # ----------------------------------------------------
        # Convert report to readable JSON
        # ----------------------------------------------------

        report_json = json.dumps(
            report_context,
            indent=2,
            default=str
        )

        # ----------------------------------------------------
        # System instructions
        # ----------------------------------------------------

        system_prompt = """
You are TrustGuard AI, a smart-contract
security analysis assistant.

Your job is to explain the CURRENT contract
analysis report to the user.

IMPORTANT RULES:

1. Use the supplied analysis report as the
   primary source of truth.

2. Never invent vulnerabilities, scores,
   predictions, evidence, or remediation.

3. Clearly distinguish between:
   - detected findings
   - ML predictions
   - evidence
   - explanations
   - uncertainty

4. A machine-learning prediction is NOT proof
   that a vulnerability is exploitable.

5. Do not say that a contract is definitely
   exploitable unless the supplied report
   explicitly establishes that.

6. When the user is a beginner, explain
   technical concepts using simple English
   and practical real-world analogies.

7. When the user asks for a technical answer,
   use proper smart-contract security terminology.

8. If the report does not contain enough
   information to answer something, say so
   instead of inventing information.

9. When discussing what to fix, use the
   actual prioritization and remediation
   information supplied in the report.

9a. When explaining the security score, use the
    actual scoring fields in the supplied report.
    Do not infer score penalties from vulnerability
    severity scores, priority scores, or ML probabilities.

    If the report provides base_score, total_penalty,
    final_score, and formula, explain the score using
    those exact fields.

    When those fields are available, explicitly state the
    actual calculation using the supplied values. Do not
    replace the actual formula with generic statements or
    speculate that the score is based on unrelated factors.

    Clearly distinguish:
    - vulnerability severity/priority scores
    - score penalty points
    - final security score

    For example, if base_score is 20 and total_penalty
    is 0, explain that the final score is 20/20 because
    the configured penalty is 0, even if findings have
    HIGH or MEDIUM severity.

    Do not claim that deployment readiness 'overrides'
    the security score. Treat security score/risk and
    deployment readiness as separate assessments and
    explain each using its supplied report fields.

10. If the user asks whether they should
    deploy, explain the documented findings,
    readiness information, evidence, and
    limitations. Do not pretend the analysis
    guarantees safety.

11. Keep answers clear and concise unless
    the user asks for more detail.

You can answer questions such as:

- What is a smart contract?
- Explain this contract like a first-year student.
- Why is this risky?
- What is the biggest finding?
- What should I fix first?
- Explain this vulnerability.
- What does the ML prediction mean?
- What does SHAP mean?
- What does LIME mean?
- What does deployment readiness mean?
- Is this finding proven or predicted?
- Explain this using a real-world example.
"""

        # ----------------------------------------------------
        # User message
        # ----------------------------------------------------

        user_prompt = (
            "CURRENT TRUSTGUARD SECURITY REPORT:\n\n"
            f"{report_json}\n\n"
            "USER QUESTION:\n"
            f"{question}"
        )

        # ----------------------------------------------------
        # Groq request
        # ----------------------------------------------------

        response = (
            client.chat.completions.create(

                model="openai/gpt-oss-120b",

                messages=[

                    {
                        "role":
                            "system",

                        "content":
                            system_prompt
                    },

                    {
                        "role":
                            "user",

                        "content":
                            user_prompt
                    }
                ],

                temperature=0.3,

                max_completion_tokens=500
            )
        )

        return (
            response
            .choices[0]
            .message
            .content
            .strip()
        )

    except Exception as error:

        print(
            "Groq error:",
            error
        )

        return (
            "AI service temporarily "
            "unavailable."
        )
