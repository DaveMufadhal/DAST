import google.genai as genai
from typing import List, Dict, Any
from scanner.efficiency_layer import EfficiencyOrchestrator

class GeminiAnalyzer:
    """Integrates Google Gemini AI for vulnerability analysis and mitigation generation."""

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash-lite"):
        self.client = genai.Client(api_key=api_key)
        self.model = model
        self.efficiency = EfficiencyOrchestrator(min_severity=2.0)

    def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze findings with efficiency optimization."""

        # Process through efficiency pipeline
        pipeline_result = self.efficiency.process_findings(findings)

        # Print efficiency metrics
        self._print_pipeline_stats(pipeline_result)

        compressed_findings = pipeline_result["stage_5_compression"]["compressed_findings"]
        enriched_findings = []

        for finding in compressed_findings:
            enriched = self._analyze_single_finding(finding)
            enriched_findings.append(enriched)

        return enriched_findings

    def _print_pipeline_stats(self, result: Dict[str, Any]):
        """Print efficiency pipeline statistics."""
        print("\n" + "=" * 60)
        print("📊 EFFICIENCY PIPELINE STATISTICS")
        print("=" * 60)

        stage2 = result["stage_2_summarizer"]["stats"]
        stage5 = result["stage_5_compression"]["stats"]

        print(f"Stage 2 - Filtering: {stage2['removed_count']} removed ({stage2['removal_percentage']})")
        print(f"Stage 5 - Compression: {stage5['token_reduction']} token reduction")
        print(f"Final: {result['pipeline_summary']['final_findings_count']} findings ready for LLM")
        print("=" * 60 + "\n")

    def _analyze_single_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze single compressed finding."""
        prompt = self._build_optimized_prompt(finding)

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            analysis = self._parse_response(response.text, finding)
            return {**finding, **analysis}
        except Exception as e:
            return {**finding, "ai_analysis": None, "ai_error": str(e)}

    def _build_optimized_prompt(self, finding: Dict[str, Any]) -> str:
        """Build efficient prompt with full output structure."""
        vuln_type = finding.get("type", "unknown")
        url = finding.get("url", "")
        evidence = finding.get("evidence", "")
        severity = finding.get("severity_score", 0)

        prompt = f"""Analyze this security vulnerability concisely:

**Vulnerability:** {vuln_type}
**URL:** {url}
**Severity:** {severity}/10
**Evidence:** {evidence}

Respond in this JSON format (no markdown):
{{"vulnerability_explanation": "Clear, concise explanation",
"attack_scenario": "Brief realistic attack scenario",
"impact": "Potential impact if exploited",
"mitigation_steps": ["step1", "step2", "step3"],
"code_mitigation": "Code example showing how to fix",
"tools_to_use": ["tool1", "tool2"],
"references": ["reference1", "reference2"]}}"""

        return prompt

    def _parse_response(self, response_text: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Parse response."""
        import json
        import re

        try:
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            analysis_data = json.loads(json_match.group() if json_match else response_text)
            return {"ai_analysis": analysis_data}
        except json.JSONDecodeError:
            return {"ai_analysis": {"raw": response_text}}