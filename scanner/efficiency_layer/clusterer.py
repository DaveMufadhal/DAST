# scanner/efficiency_layer/clusterer.py
from typing import List, Dict, Any
from collections import defaultdict


class FindingCluster:
    """Groups similar findings by type and characteristics."""

    def __init__(self):
        self.clusters: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def cluster_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Cluster findings by type and URL pattern."""
        self.clusters.clear()

        for finding in findings:
            vuln_type = finding.get("type", "unknown")
            cluster_key = self._generate_cluster_key(finding, vuln_type)
            self.clusters[cluster_key].append(finding)

        return dict(self.clusters)

    def _generate_cluster_key(self, finding: Dict[str, Any], vuln_type: str) -> str:
        """Generate cluster key based on type and URL pattern."""
        url = finding.get("url", "")

        # Extract base path from URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_path = parsed.path.split("/")[1] if parsed.path else "root"
        except:
            base_path = "unknown"

        return f"{vuln_type}::{base_path}"

    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get statistics about clusters."""
        return {
            "total_clusters": len(self.clusters),
            "clusters": {
                cluster_type: {
                    "count": len(findings),
                    "severity_avg": sum(f.get("severity_score", 0) for f in findings) / len(findings) if findings else 0
                }
                for cluster_type, findings in self.clusters.items()
            }
        }

    def get_cluster(self, cluster_key: str) -> List[Dict[str, Any]]:
        """Get findings from specific cluster."""
        return self.clusters.get(cluster_key, [])

    def get_all_clusters(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all clusters."""
        return dict(self.clusters)