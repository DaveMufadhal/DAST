# scanner/efficiency_layer/rag_retriever.py
from typing import List, Dict, Any


class RAGRetriever:
    """Retrieves relevant findings for batch processing using clustering."""

    def __init__(self, clusters: Dict[str, List[Dict[str, Any]]]):
        self.clusters = clusters

    def retrieve_by_type(self, vuln_type: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve findings by vulnerability type."""
        matching = []
        for cluster_key, findings in self.clusters.items():
            if vuln_type in cluster_key:
                matching.extend(findings)

        return sorted(
            matching,
            key=lambda f: f.get("severity_score", 0),
            reverse=True
        )[:limit]

    def retrieve_high_priority(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve top priority findings across all clusters."""
        all_findings = []
        for findings in self.clusters.values():
            all_findings.extend(findings)

        return sorted(
            all_findings,
            key=lambda f: f.get("severity_score", 0),
            reverse=True
        )[:limit]

    def retrieve_batch_by_cluster(self, cluster_key: str,
                                   limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve batch from specific cluster."""
        findings = self.clusters.get(cluster_key, [])
        return sorted(
            findings,
            key=lambda f: f.get("severity_score", 0),
            reverse=True
        )[:limit]

    def retrieve_batch_for_analysis(self, batch_size: int = 5) -> Dict[str, List[Dict[str, Any]]]:
        """Organize findings into batches for efficient LLM analysis."""
        batches = {}

        for cluster_key, findings in self.clusters.items():
            sorted_findings = sorted(
                findings,
                key=lambda f: f.get("severity_score", 0),
                reverse=True
            )

            # Split into batches
            for i in range(0, len(sorted_findings), batch_size):
                batch_key = f"{cluster_key}::batch_{i // batch_size}"
                batches[batch_key] = sorted_findings[i:i + batch_size]

        return batches

    def get_retrieval_stats(self) -> Dict[str, Any]:
        """Get retrieval statistics."""
        all_findings = []
        for findings in self.clusters.values():
            all_findings.extend(findings)

        return {
            "total_retrievable": len(all_findings),
            "clusters_available": len(self.clusters),
            "avg_per_cluster": len(all_findings) / len(self.clusters) if self.clusters else 0
        }