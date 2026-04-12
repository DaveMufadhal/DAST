# scanner/efficiency_layer/orchestrator.py
from typing import List, Dict, Any
from .raw_data_processor import RawDataProcessor
from .summarizer import FindingSummarizer
from .clusterer import FindingCluster
from .rag_retriever import RAGRetriever
from .context_compressor import ContextCompressor


class EfficiencyOrchestrator:
    """Orchestrates the complete efficiency layer pipeline."""

    def __init__(self, min_severity: float = 2.0):
        self.min_severity = min_severity
        self.raw_processor = RawDataProcessor()
        self.summarizer = FindingSummarizer(min_severity=min_severity)
        self.clusterer = FindingCluster()
        self.compressor = ContextCompressor()
        self.rag_retriever = None

    def process_findings(self, raw_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process findings through complete pipeline:
        1. Raw Data Processor → Normalize findings
        2. Summarizer → Filter & deduplicate
        3. Clusterer → Group similar findings
        4. RAG Retriever → Prepare for batch analysis
        5. Context Compressor → Reduce token usage
        """

        # Stage 1: Normalize raw data
        print("📊 Stage 1: Processing raw data...")
        processed = self.raw_processor.validate_findings(raw_findings)
        raw_stats = self.raw_processor.get_stats(processed)

        # Stage 2: Summarize and filter
        print("📊 Stage 2: Filtering and deduplicating...")
        filtered = self.summarizer.filter_by_severity(processed)
        unique = self.summarizer.deduplicate_findings(filtered)
        summary = self.summarizer.create_summary(unique)
        filter_stats = self.summarizer.get_filter_stats(processed, unique)

        # Stage 3: Cluster findings
        print("📊 Stage 3: Clustering findings...")
        clusters = self.clusterer.cluster_findings(unique)
        cluster_stats = self.clusterer.get_cluster_stats()

        # Stage 4: Initialize RAG retriever
        print("📊 Stage 4: Preparing RAG retrieval...")
        self.rag_retriever = RAGRetriever(clusters)
        retrieval_batches = self.rag_retriever.retrieve_batch_for_analysis(batch_size=5)
        rag_stats = self.rag_retriever.get_retrieval_stats()

        # Stage 5: Compress context
        print("📊 Stage 5: Compressing context...")
        compressed_findings = self.compressor.compress_batch(unique)
        compression_stats = self.compressor.calculate_compression_ratio(unique, compressed_findings)

        return {
            "stage_1_raw_data": {
                "processed_findings": processed,
                "stats": raw_stats
            },
            "stage_2_summarizer": {
                "filtered_findings": filtered,
                "unique_findings": unique,
                "summary": summary,
                "stats": filter_stats
            },
            "stage_3_clusterer": {
                "clusters": clusters,
                "stats": cluster_stats
            },
            "stage_4_rag": {
                "retrieval_batches": retrieval_batches,
                "stats": rag_stats
            },
            "stage_5_compression": {
                "compressed_findings": compressed_findings,
                "stats": compression_stats
            },
            "pipeline_summary": {
                "total_stages": 5,
                "final_findings_count": len(compressed_findings),
                "efficiency_gain": compression_stats.get("token_reduction", "0%")
            }
        }

    def get_batch_for_llm(self, batch_key: str) -> List[Dict[str, Any]]:
        """Get compressed batch for LLM analysis."""
        if not self.rag_retriever:
            return []

        # Get batch from RAG and compress
        retrieval_batches = self.rag_retriever.retrieve_batch_for_analysis()
        batch = retrieval_batches.get(batch_key, [])
        return self.compressor.compress_batch(batch)

    def get_high_priority_for_llm(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get high-priority findings for immediate LLM analysis."""
        if not self.rag_retriever:
            return []

        findings = self.rag_retriever.retrieve_high_priority(limit=limit)
        return self.compressor.compress_batch(findings)