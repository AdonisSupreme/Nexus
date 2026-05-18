from app.rag.indexer import KnowledgeIndexer
from app.rag.retriever import HybridRetriever


def test_indexer_normalizes_existing_corpus():
    indexer = KnowledgeIndexer()
    result = indexer.ingest()
    assert result["sops"] >= 70
    assert "SOP-B-010" in indexer.normalized_sops
    assert "SOP-E-APP-DEPENDENCIES-010" in indexer.normalized_sops


def test_retriever_returns_postilion_restart_evidence():
    indexer = KnowledgeIndexer()
    indexer.ingest()
    retriever = HybridRetriever(indexer=indexer)
    retriever.rebuild()
    results = retriever.search("daily restart of postilion and sql server", top_k=3)
    assert results
    assert any(result.sop_id == "SOP-B-010" for result in results)
