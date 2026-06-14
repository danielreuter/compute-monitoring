"""Single-script inference-request example for the PoComp sketch.

The audit still checks predictor hashes against the baseline commitment. In this
prototype, the Python callables below are trusted stand-ins for executing those
committed predictor artifacts; the code does not prove that a callable
corresponds to the committed hash.
"""

from __future__ import annotations

import pocomps
from pocomps import (
    EXTERNAL,
    Baseline,
    Blob,
    Task,
    NetworkEvent,
    NetworkEventLog,
    PolicyParams,
    Storage,
)


DATACENTER_GATEWAY = 0
POD_GATEWAY = 1
MODEL_ID = b"model-m"
PROMPT = b"What is 2 + 2?"
PUBLIC_RANDOMNESS = b"public randomness"

TASK_PREDICTOR_COMMITMENT = b"task-predictor:inference-request:v1"
MEASUREMENT_PREDICTOR_COMMITMENT = b"measurement-predictor:inference-request:v1"


def encode_request(prompt: bytes) -> bytes:
    return MODEL_ID + b"\n" + prompt


def decode_request(request: bytes) -> bytes:
    model_id, prompt = request.split(b"\n", maxsplit=1)
    assert model_id == MODEL_ID
    return prompt


def run_model(prompt: bytes) -> bytes:
    if prompt == PROMPT:
        return b"4"
    return b"I do not know."


def make_storage(*blobs: Blob) -> Storage:
    return Storage({hash(blob): blob for blob in blobs})


def make_event(sender: int, receiver: int, blob: Blob) -> NetworkEvent:
    return NetworkEvent(
        sender=sender,
        receiver=receiver,
        blob_hash=hash(blob),
        blob_size=pocomps.object_size(blob),
    )


def make_epoch() -> tuple[NetworkEventLog, Storage]:
    prompt = PROMPT
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
    return event_log, make_storage(prompt, request, completion, response)


def make_policy() -> PolicyParams:
    return PolicyParams(
        task_predictor_hash=hash(TASK_PREDICTOR_COMMITMENT),
        measurement_predictor_hash=hash(MEASUREMENT_PREDICTOR_COMMITMENT),
        compute_budget_for_tasks=50,
        compute_budget_per_task=10,
        error_entropy_budget_per_epoch=8,
        entropy_budget_per_task=2,
        sample_rate_per_output_byte=1.0,
    )


def predict_inference_request_tasks(
    event_log: NetworkEventLog,
    advice: str,
) -> tuple[Task, ...]:
    datacenter_gateway = DATACENTER_GATEWAY
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
        Task(input_hashes=(prompt_event.blob_hash,), measurement_ids=(1,)),
        Task(input_hashes=(request_event.blob_hash,), measurement_ids=(2,)),
        Task(input_hashes=(completion_event.blob_hash,), measurement_ids=(3,)),
    )


def predict_inference_request_measurements(
    task: Task,
    inputs: tuple[Blob, ...],
    _advice: str,
) -> tuple[Blob, ...]:
    if task.measurement_ids == (1,):
        prompt = inputs[0]
        assert isinstance(prompt, bytes)
        return (encode_request(prompt),)
    elif task.measurement_ids == (2,):
        request = inputs[0]
        assert isinstance(request, bytes)
        return (run_model(decode_request(request)),)
    elif task.measurement_ids == (3,):
        completion = inputs[0]
        return (completion,)

    raise AssertionError(f"unknown task: {task}")


def audit_inference_request() -> tuple[NetworkEventLog, tuple[Task, ...], int]:
    event_log, storage = make_epoch()
    params = make_policy()
    baseline = Baseline(
        set(storage.blobs)
        | {
            params.task_predictor_hash,
            params.measurement_predictor_hash,
        }
    )
    task_advice = "1"

    tasks = pocomps.audit_epoch(
        event_log,
        storage,
        baseline,
        params,
        beacon=PUBLIC_RANDOMNESS,
        task_advice=task_advice,
        measurement_advice="",
        task_predictor=predict_inference_request_tasks,
        measurement_predictor=predict_inference_request_measurements,
    )

    return event_log, tasks, len(task_advice)


def main() -> None:
    event_log, tasks, error_entropy = audit_inference_request()

    print(f"network_events={event_log.events}")
    print(f"tasks={tasks}")
    print(f"error_entropy={error_entropy}")


if __name__ == "__main__":
    main()
