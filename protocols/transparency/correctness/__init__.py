"""
Correctness protocol family.

Shared transcript and evaluation events live in `common.py`. Mechanism-specific
control flow lives in `reexecution.py` and `zero_knowledge.py`.
"""

from .common import (
    CorrectnessCheckRequestedEvent,
    CorrectnessCheckTimedOutEvent,
    CorrectnessCommitmentRef,
    CorrectnessEvaluatedEvent,
    InferenceClaimedEvent,
    WorkloadAddress,
)
from .reexecution import (
    ReexecutionBundle,
    ReexecutionEvidencePublishedEvent,
    ReexecutionProver,
    ReexecutionVerifier,
)
from .zero_knowledge import (
    ZeroKnowledgeProofBundle,
    ZeroKnowledgeProofSubmittedEvent,
    ZeroKnowledgeProver,
    ZeroKnowledgeVerifier,
)

CorrectnessArtifactRef = CorrectnessCommitmentRef
CorrectnessArtifactPublishedEvent = ReexecutionEvidencePublishedEvent
CorrectnessProver = ReexecutionProver
CorrectnessVerifier = ReexecutionVerifier

__all__ = [
    "CorrectnessArtifactPublishedEvent",
    "CorrectnessArtifactRef",
    "CorrectnessCheckRequestedEvent",
    "CorrectnessCheckTimedOutEvent",
    "CorrectnessCommitmentRef",
    "CorrectnessEvaluatedEvent",
    "CorrectnessProver",
    "CorrectnessVerifier",
    "InferenceClaimedEvent",
    "ReexecutionBundle",
    "ReexecutionEvidencePublishedEvent",
    "ReexecutionProver",
    "ReexecutionVerifier",
    "WorkloadAddress",
    "ZeroKnowledgeProofBundle",
    "ZeroKnowledgeProofSubmittedEvent",
    "ZeroKnowledgeProver",
    "ZeroKnowledgeVerifier",
]
