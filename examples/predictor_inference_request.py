"""Tiny inference-request example using the current PoComp skeleton.

The transcript is just NetworkEvent records. Any event content lives behind the
blob hash, as in pocomp.py.
"""

from __future__ import annotations

import pocomp
from pocomp import (
    EXTERNAL,
    Storage,
    NetworkEvent,
    NetworkEventLog,
    PolicyParams,
)


DATACENTER_GATEWAY = 0
POD_GATEWAY = 1
MODEL_ID = b"model-m"
CLAIM_PREDICTOR_PROGRAM = b"""
COMPUTE_COST = 20


def main(event_log, advice):
    from pocomp import EXTERNAL, Claim

    datacenter_gateway = 0
    pod_gateway = int(advice or "0", 2)

    prompt_event, request_event, completion_event, response_event = event_log.events

    assert prompt_event.sender == EXTERNAL
    assert prompt_event.receiver == datacenter_gateway
    assert request_event.sender == datacenter_gateway
    assert request_event.receiver == pod_gateway

    assert completion_event.sender == pod_gateway
    assert completion_event.receiver == datacenter_gateway

    assert response_event.sender == datacenter_gateway
    assert response_event.receiver == EXTERNAL

    return (
        Claim(input_hashes=(prompt_event.blob_hash,), measurement_ids=(1,)),
        Claim(input_hashes=(request_event.blob_hash,), measurement_ids=(2,)),
        Claim(input_hashes=(completion_event.blob_hash,), measurement_ids=(3,)),
    )
"""
MEASUREMENT_PREDICTOR_PROGRAM = b"""
COMPUTE_COST = 7
MODEL_ID = b"model-m"


def encode_request(prompt):
    return MODEL_ID + b"\\n" + prompt


def decode_request(request):
    model_id, prompt = request.split(b"\\n", maxsplit=1)
    assert model_id == MODEL_ID
    return prompt


def run_model(prompt):
    if prompt == b"What is 2 + 2?":
        return b"4"
    return b"I do not know."


def main(claim, inputs, advice):
    if claim.measurement_ids == (1,):
        prompt = inputs[0]
        return (encode_request(prompt),)

    if claim.measurement_ids == (2,):
        request = inputs[0]
        prompt = decode_request(request)
        return (run_model(prompt),)

    if claim.measurement_ids == (3,):
        completion = inputs[0]
        return (completion,)

    raise AssertionError(f"unknown claim: {claim}")
"""


class ExampleBaseline:
    def __init__(self, committed_hashes: set[int]) -> None:
        self.committed_hashes = committed_hashes

    def contains(self, blob_hash: int) -> bool:
        return blob_hash in self.committed_hashes


def encode_request(prompt: bytes) -> bytes:
    return MODEL_ID + b"\n" + prompt


def decode_request(request: bytes) -> bytes:
    model_id, prompt = request.split(b"\n", maxsplit=1)
    assert model_id == MODEL_ID
    return prompt


def run_model(prompt: bytes) -> bytes:
    if prompt == b"What is 2 + 2?":
        return b"4"
    return b"I do not know."


def make_storage(*blobs: bytes) -> Storage:
    return Storage({hash(blob): blob for blob in blobs})


def make_event(sender: int, receiver: int, blob: bytes) -> NetworkEvent:
    return NetworkEvent(
        sender=sender,
        receiver=receiver,
        blob_hash=hash(blob),
        blob_size=len(blob),
    )


def make_epoch() -> tuple[NetworkEventLog, Storage]:
    prompt = b"What is 2 + 2?"
    request = encode_request(prompt)
    completion = run_model(prompt)
    response = completion

    event_log = NetworkEventLog(
        events=(
            make_event(EXTERNAL, DATACENTER_GATEWAY, prompt),
            make_event(DATACENTER_GATEWAY, POD_GATEWAY, request),
            make_event(POD_GATEWAY, DATACENTER_GATEWAY, completion),
            make_event(DATACENTER_GATEWAY, EXTERNAL, response),
        )
    )
    return event_log, make_storage(
        prompt,
        request,
        completion,
        response,
        CLAIM_PREDICTOR_PROGRAM,
        MEASUREMENT_PREDICTOR_PROGRAM,
    )


def main() -> None:
    event_log, storage = make_epoch()
    claim_predictor_hash = hash(CLAIM_PREDICTOR_PROGRAM)
    measurement_predictor_hash = hash(MEASUREMENT_PREDICTOR_PROGRAM)
    params = PolicyParams(
        claim_predictor_hash=claim_predictor_hash,
        measurement_predictor_hash=measurement_predictor_hash,
        compute_budget_for_claims=50,
        compute_budget_per_claim=10,
        error_entropy_budget_per_epoch=8,
        entropy_budget_per_claim=2,
        sample_rate_per_output_byte=1.0,
    )
    claim_advice = "1"

    claims = pocomp.audit_epoch(
        event_log,
        storage,
        ExampleBaseline(set(storage.blobs)),
        params,
        beacon=b"public randomness",
        claim_advice=claim_advice,
        measurement_advice="",
    )

    print(f"network_events={event_log.events}")
    print(f"claims={claims}")
    print(f"error_entropy_bits={pocomp.error_entropy_bits(claim_advice)}")


if __name__ == "__main__":
    main()
