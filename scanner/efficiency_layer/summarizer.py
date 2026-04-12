# scanner/efficiency_layer/summarizer.py
from typing import List, Dict, Any
from collections import defaultdict


class FindingSummarizer:
    """Summarizes and filters findings to reduce token usage."""

    def __init__(self, min_severity: float = 2.0):
        self.min_severity = min_severity

    def filter_by_severity(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter findings by severity threshold."""
        return [f for f in findings if f.get("severity_score", 0) >= self.min_severity]

    def deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate or near-duplicate findings."""
        seen = set()
        unique = []

        for finding in findings:
            signature = (
                finding.get("type"),
                finding.get("url"),
                finding.get("evidence", "")[:100]
            )

            if signature not in seen:
                seen.add(signature)
                unique.append(finding)

        return unique

    def create_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create concise summary grouped by vulnerability type."""
        by_type = defaultdict(list)

        for finding in findings:
            vuln_type = finding.get("type", "unknown")
            by_type[vuln_type].append(finding)

        summary = {
            "total_findings": len(findings),
            "by_type": {}
        }

        for vuln_type, findings_list in by_type.items():
            summary["by_type"][vuln_type] = {
                "count": len(findings_list),
                "avg_severity": sum(f.get("severity_score", 0) for f in findings_list) / len(findings_list),
                "affected_urls": list(set(f.get("url", "") for f in findings_list))[:5],
                "severity_scores": sorted([f.get("severity_score", 0) for f in findings_list], reverse=True)
            }

        return summary

    def get_filter_stats(self, original: List[Dict[str, Any]],
                         filtered: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get filtering statistics."""
        return {
            "original_count": len(original),
            "filtered_count": len(filtered),
            "removed_count": len(original) - len(filtered),
            "removal_percentage": f"{((len(original) - len(filtered)) / len(original) * 100):.1f}%" if original else "0%"
        }