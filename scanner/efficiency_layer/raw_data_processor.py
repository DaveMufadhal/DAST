# scanner/efficiency_layer/raw_data_processor.py
from typing import List, Dict, Any
from enum import Enum


class SeverityLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class RawDataProcessor:
    """Processes raw findings from scanner into standardized format."""

    @staticmethod
    def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw finding to standard format."""
        return {
            "type": finding.get("type", "unknown"),
            "url": finding.get("url", ""),
            "evidence": finding.get("evidence", ""),
            "severity_score": finding.get("severity_score", 0),
            "description": finding.get("description", ""),
            "tags": finding.get("tags", []),
            "timestamp": finding.get("timestamp", ""),
            "_original": finding
        }

    @staticmethod
    def validate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate and normalize raw findings."""
        valid_findings = []

        for finding in findings:
            if finding.get("type") and finding.get("url"):
                valid_findings.append(RawDataProcessor.normalize_finding(finding))

        return valid_findings

    @staticmethod
    def get_stats(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistics about raw findings."""
        severity_dist = {}
        type_dist = {}

        for finding in findings:
            severity = finding.get("severity_score", 0)
            vuln_type = finding.get("type", "unknown")

            severity_dist[severity] = severity_dist.get(severity, 0) + 1
            type_dist[vuln_type] = type_dist.get(vuln_type, 0) + 1

        return {
            "total": len(findings),
            "by_severity": severity_dist,
            "by_type": type_dist
        }