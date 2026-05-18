from app.orchestrator.response_validator import ResponseValidator


def test_validator_falls_back_when_no_evidence_exists():
    validator = ResponseValidator()
    answer = validator.validate(answer=None, evidence=[], warnings=["No evidence"])
    assert "could not find strong sop-backed guidance" in answer.lower()


def test_validator_extracts_next_steps_from_citations():
    validator = ResponseValidator()
    steps = validator.recommended_steps(
        evidence=[],
        citations=[
            type(
                "CitationStub",
                (),
                {"section": "actions", "excerpt": "Restart Transaction Manager service", "sop_id": "SOP-B-010"},
            )(),
            type(
                "CitationStub",
                (),
                {"section": "escalation", "excerpt": "Escalate to IDC support team", "sop_id": "SOP-A-002"},
            )(),
        ],
    )
    assert steps[0] == "Restart Transaction Manager service"
    assert any("Escalate to IDC support team" == step for step in steps)


def test_validator_skips_context_fragments_and_low_score_citations():
    validator = ResponseValidator()
    steps = validator.recommended_steps(
        evidence=[
            type(
                "EvidenceStub",
                (),
                {"sop_id": "SOP-B-010"},
            )(),
        ],
        citations=[
            type(
                "CitationStub",
                (),
                {"section": "checks", "excerpt": "After Postilion service restarts", "score": 0.99, "sop_id": "SOP-E-002"},
            )(),
            type(
                "CitationStub",
                (),
                {"section": "actions", "excerpt": "Restart Transaction Manager service", "score": 0.88, "sop_id": "SOP-B-010"},
            )(),
            type(
                "CitationStub",
                (),
                {"section": "actions", "excerpt": "Receive Excel file with transaction references from Treasury", "score": 0.0, "sop_id": "SOP-B-014"},
            )(),
        ],
    )
    assert "After Postilion service restarts" not in steps
    assert "Receive Excel file with transaction references from Treasury" not in steps
    assert "Restart Transaction Manager service" in steps
