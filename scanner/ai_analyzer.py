from openai import OpenAI
from dotenv import load_dotenv
from typing import List, Dict, Any
from scanner.efficiency_layer import EfficiencyOrchestrator
import os

load_dotenv()


class AIAnalyzer:
    """Integrates OpenRouter DeepSeek AI for vulnerability analysis and mitigation generation."""

    def __init__(self, model: str = "deepseek/deepseek-v4-flash:free"):

        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("OPENROUTER_API_KEY")
        )

        self.model = model

        self.efficiency = EfficiencyOrchestrator(min_severity=2.0)

        self.success_count = 0
        self.error_count = 0
        self.errors = []

    def analyze_findings(self, original_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze findings while preserving original DAST engine data."""

        # Process through efficiency pipeline
        pipeline_result = self.efficiency.process_findings(original_findings)

        # Print efficiency metrics
        self._print_pipeline_stats(pipeline_result)

        compressed_findings = pipeline_result["stage_5_compression"]["compressed_findings"]

        # Create mapping: compressed finding -> original finding(s)
        enriched_findings = []

        for compressed in compressed_findings:

            # Find original finding(s) that match this compressed one
            original = self._find_original_finding(
                compressed,
                original_findings
            )

            # Analyze the compressed version
            analysis = self._analyze_single_finding(compressed)

            # CRITICAL FIX: Merge correctly - original data + AI analysis
            merged = original.copy()  # Start with all original DAST data
            if analysis.get("ai_analysis"):  # Only add if analysis succeeded
                merged["ai_analysis"] = analysis["ai_analysis"]
            elif analysis.get("ai_error"):  # Preserve error if analysis failed
                merged["ai_error"] = analysis["ai_error"]

            enriched_findings.append(merged)

        # Print success/error statistics
        self._print_analysis_stats()

        return enriched_findings

    def _find_original_finding(self, compressed: Dict[str, Any], original_findings: List[Dict[str, Any]]) -> Dict[
        str, Any]:
        """Find the original finding that corresponds to this compressed finding."""
        for original in original_findings:
            # Match by type and url
            if (original.get("type") == compressed.get("type") and
                    original.get("url") == compressed.get("url")):
                return original.copy()
        # Fallback: return compressed if no match
        return compressed.copy()

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
        """Analyze single compressed finding and return AI analysis only."""

        prompt = self._build_optimized_prompt(finding)

        try:

            response = self.client.chat.completions.create(
                model=self.model,
                temperature=0.2,
                max_tokens=2048,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert web application security analyst "
                            "specialized in secure coding, penetration testing, "
                            "OWASP Top 10, and vulnerability remediation."
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                extra_body={
                    "reasoning": {
                        "enabled": True
                    }
                }
            )

            response_text = response.choices[0].message.content

            analysis = self._parse_response(
                response_text,
                finding
            )

            self.success_count += 1

            print(
                f"✅ Analyzed: "
                f"{finding.get('type', 'unknown')} "
                f"at {finding.get('url', 'unknown')}"
            )

            return analysis

        except Exception as e:

            self.error_count += 1

            error_msg = str(e)

            self.errors.append({
                "finding": finding.get("type", "unknown"),
                "url": finding.get("url", "unknown"),
                "error": error_msg
            })

            print(
                f"❌ Failed: "
                f"{finding.get('type', 'unknown')} "
                f"at {finding.get('url', 'unknown')}"
            )

            print(f"   Error: {error_msg}")

            return {
                "ai_analysis": None,
                "ai_error": error_msg
            }

    def _print_analysis_stats(self):
        """Print API analysis statistics."""
        total = self.success_count + self.error_count
        success_rate = (self.success_count / total * 100) if total > 0 else 0

        print("\n" + "=" * 60)
        print("🤖 AI ANALYSIS STATISTICS")
        print("=" * 60)
        print(f"Total Analyzed: {total}")
        print(f"✅ Successful: {self.success_count}")
        print(f"❌ Failed: {self.error_count}")
        print(f"Success Rate: {success_rate:.1f}%")

        if self.errors:
            print("\n⚠️  Error Details:")
            for err in self.errors[:5]:
                print(f"  - {err['finding']} at {err['url']}: {err['error'][:100]}")
            if len(self.errors) > 5:
                print(f"  ... and {len(self.errors) - 5} more errors")

        print("=" * 60 + "\n")

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
        """Parse response and return only AI analysis."""
        import json
        import re

        try:
            # Handle None or empty response
            if not response_text:
                return {
                    "ai_analysis": None,
                    "ai_error": "Empty response from AI model"
                }

            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)

            if not json_match:
                return {
                    "ai_analysis": None,
                    "ai_error": f"No JSON found in response: {response_text[:100]}"
                }

            analysis_data = json.loads(json_match.group())
            return {"ai_analysis": analysis_data}

        except json.JSONDecodeError as e:
            return {
                "ai_analysis": None,
                "ai_error": f"JSON parse error: {str(e)}"
            }
        except Exception as e:
            return {
                "ai_analysis": None,
                "ai_error": f"Parse error: {str(e)}"
            }