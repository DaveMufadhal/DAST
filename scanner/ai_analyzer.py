import google.generativeai as genai
from typing import List, Dict, Any

class GeminiAnalyzer:
    """Integrates Google Gemini AI for vulnerability analysis and mitigation generation."""

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash-lite"):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model)

    def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze raw findings and generate explanations with mitigation code."""
        enriched_findings = []

        for finding in findings:
            enriched = self._analyze_single_finding(finding)
            enriched_findings.append(enriched)

        return enriched_findings

    def _analyze_single_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single finding and generate mitigation details."""

        prompt = self._build_prompt(finding)

        try:
            response = self.model.generate_content(prompt)
            analysis = self._parse_response(response.text, finding)
            return {**finding, **analysis}
        except Exception as e:
            return {
                **finding,
                "ai_analysis": None,
                "ai_error": str(e)
            }

    def _build_prompt(self, finding: Dict[str, Any]) -> str:
        """Build a detailed prompt for Gemini analysis."""
        vuln_type = finding.get("type", "unknown")
        url = finding.get("url", "")
        evidence = finding.get("evidence", "")
        severity = finding.get("severity_score", 0)

        prompt = f"""You are a cybersecurity expert. Analyze this vulnerability finding and provide:

**Vulnerability Details:**
- Type: {vuln_type}
- URL: {url}
- Severity Score: {severity}/10
- Evidence: {evidence}

Please provide your response in this exact JSON format (no markdown, pure JSON):
{{"vulnerability_explanation": "Clear explanation of what this vulnerability is and why it's dangerous",
    "attack_scenario": "Describe a realistic attack scenario",
    "impact": "Describe the potential impact if exploited",
    "mitigation_steps": ["step1", "step2", "step3"],
    "code_mitigation": "Provide a code example (any language) showing how to fix this vulnerability",
    "tools_to_use": ["tool1", "tool2"],
    "references": ["reference1", "reference2"]
}}

Focus on practical, actionable mitigation code."""

        return prompt

    def _parse_response(self, response_text: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Gemini response and structure it."""
        import json
        import re

        try:
            # Extract JSON from response (handle markdown code blocks)
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                analysis_data = json.loads(json_match.group())
            else:
                analysis_data = json.loads(response_text)

            return {"ai_analysis": analysis_data}
        except json.JSONDecodeError:
            return {
                "ai_analysis": {
                    "raw_analysis": response_text
                }
            }