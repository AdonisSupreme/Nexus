import asyncio

from app.models.mistral_client import MistralClient
from app.orchestrator.intent_extractor import IntentExtractor
from app.schemas.intent_schema import QueryIntent


def test_intent_extractor_routes_dr_queries():
    extractor = IntentExtractor(mistral_client=MistralClient())
    result = asyncio.run(extractor.classify("We need a full DR failover and rollback plan now", use_remote_classifier=False))
    assert result.intent == QueryIntent.DISASTER_RECOVERY
    assert result.confidence >= 0.35
