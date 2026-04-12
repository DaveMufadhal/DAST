# scanner/efficiency_layer/context_compressor.py
from typing import List, Dict, Any
import json


class ContextCompressor:
    """Compresses context before sending to LLM."""

    # Constants
    EVIDENCE_MAX_LENGTH = 250
    DESCRIPTION_MAX_LENGTH = 150
    URL_MAX_LENGTH = 200

    @staticmethod
    def compress_evidence(evidence: str, max_length: int = None) -> str:
        """Truncate and compress evidence strings."""
        max_len = max_length or ContextCompressor.EVIDENCE_MAX_LENGTH
        if len(evidence) > max_len:
            return evidence[:max_len] + "..."
        return evidence

    @staticmethod
    def compress_description(description: str, max_length: int = None) -> str:
        """Compress description field."""
        max_len = max_length or ContextCompressor.DESCRIPTION_MAX_LENGTH
        if len(description) > max_len:
            return description[:max_len] + "..."
        return description

    @staticmethod
    def compress_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Compress a single finding by removing unnecessary fields."""
        compressed = {
            "type": finding.get("type"),
            "url": finding.get("url", "")[:ContextCompressor.URL_MAX_LENGTH],
            "severity_score": finding.get("severity_score"),
            "evidence": ContextCompressor.compress_evidence(finding.get("evidence", "")),
            "description": ContextCompressor.compress_description(finding.get("description", "")),
            "tags": finding.get("tags", [])[:3]  # Limit tags
        }
        return compressed

    @staticmethod
    def compress_batch(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Compress multiple findings for batch processing."""
        return [ContextCompressor.compress_finding(f) for f in findings]

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Rough estimation of tokens (1 token ≈ 4 chars for English)."""
        return max(1, len(text) // 4)

    @staticmethod
    def calculate_compression_ratio(original: List[Dict[str, Any]],
                                    compressed: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate compression efficiency metrics."""
        original_json = json.dumps(original)
        compressed_json = json.dumps(compressed)

        original_tokens = ContextCompressor.estimate_tokens(original_json)
        compressed_tokens = ContextCompressor.estimate_tokens(compressed_json)

        return {
            "original_chars": len(original_json),
            "compressed_chars": len(compressed_json),
            "original_tokens": original_tokens,
            "compressed_tokens": compressed_tokens,
            "char_reduction": f"{((1 - len(compressed_json)/len(original_json)) * 100):.1f}%" if original_json else "0%",
            "token_reduction": f"{((1 - compressed_tokens/original_tokens) * 100):.1f}%" if original_tokens > 0 else "0%"
        }