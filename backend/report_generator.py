from datetime import datetime, timezone
import json
import os


class ReportGenerator:
    """Generate a structured JSON security report from TrustGuard analysis."""

    def __init__(self, output_dir=None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        self.output_dir = output_dir or os.path.join(
            base_dir, "data", "reports"
        )

        os.makedirs(self.output_dir, exist_ok=True)

    def build_report(self, analysis):
        if not isinstance(analysis, dict):
            raise ValueError("Analysis must be a dictionary.")

        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_type": "TrustGuard AI Security Report",
                "version": "1.0"
            },

            "contract": {
                "address": analysis.get("contract_address"),
                "network": analysis.get("network"),
                "profile": analysis.get("contract_profile")
            },

            "security_summary": analysis.get(
                "security_summary", {}
            ),

            "security_score": {
                "score": analysis.get("score"),
                "risk_level": analysis.get("risk_level"),
                "breakdown": analysis.get("score_breakdown", {})
            },

            "attack_surface": analysis.get(
                "attack_surface", {}
            ),

            "security_evidence": analysis.get(
                "security_evidence", {}
            ),

            "ml_assessment": analysis.get(
                "ml_probability_matrix", {}
            ),

            "explanations": analysis.get(
                "explanation_center", {}
            ),

            "findings": {
                "static_findings": analysis.get(
                    "static_findings", []
                ),
                "vulnerabilities": analysis.get(
                    "vulnerabilities", []
                ),
                "severity": analysis.get(
                    "severity", {}
                )
            },

            "vulnerability_correlation": analysis.get(
                "vulnerability_correlation", {}
            ),

            "prioritization": analysis.get(
                "prioritized_vulnerabilities", []
            ),

            "remediation": analysis.get(
                "repair_suggestions", []
            ),

            "deployment_readiness": analysis.get(
                "deployment_readiness", {}
            ),

            "confidence": analysis.get(
                "confidence_assessment", {}
            ),

            "limitations_and_evidence": analysis.get(
                "limitations_evidence_notes", {}
            ),

            "analysis_pipeline": analysis.get(
                "analysis_pipeline", {}
            ),

            "performance": analysis.get(
                "performance_metrics", {}
            )
        }

    def save_json(self, analysis, filename=None):
        report = self.build_report(analysis)

        if filename is None:
            address = analysis.get(
                "contract_address",
                "unknown_contract"
            )

            timestamp = datetime.now(timezone.utc).strftime(
                "%Y%m%d_%H%M%S"
            )

            filename = f"trustguard_report_{address}_{timestamp}.json"

        path = os.path.join(self.output_dir, filename)

        with open(path, "w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=2,
                ensure_ascii=False
            )

        return {
            "success": True,
            "report_path": path,
            "report": report
        }
