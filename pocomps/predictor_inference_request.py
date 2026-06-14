"""Single-script inference-server example for the PoComp sketch.

The audit still checks predictor hashes against the baseline commitment. In this
prototype, the Python callables below are trusted stand-ins for executing those
committed predictor artifacts; the code does not prove that a callable
corresponds to the committed hash.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import random
from typing import Sequence

import pocomps
from pocomps import (
    EXTERNAL,
    Baseline,
    Blob,
    Measurement,
    NetworkEvent,
    NetworkEventLog,
    PolicyParams,
    Storage,
    Task,
)


DATACENTER_GATEWAY = 0
PREFILL_SITE = 1
DECODE_SITE = 2
SITE_LABELS = {
    EXTERNAL: "external",
    DATACENTER_GATEWAY: "datacenter_gateway",
    PREFILL_SITE: "prefill",
    DECODE_SITE: "decode",
}

MODEL_ID = b"model-m"
PROMPT_COUNT = 4
SETUP_RANDOM_SEED = 17
MAX_PROMPT_SEND_TICK = 6
PUBLIC_RANDOMNESS = b"public randomness"

TASK_PREDICTOR_COMMITMENT = b"task-predictor:inference-request:v1"
MEASUREMENT_PREDICTOR_COMMITMENT = b"measurement-predictor:inference-request:v1"


@dataclass(frozen=True)
class PromptArrival:
    send_tick: int
    prompt: bytes


@dataclass(frozen=True)
class EpochSetup:
    prompt_arrivals: tuple[PromptArrival, ...]
    ticks: int
    params: PolicyParams
    beacon: bytes


@dataclass(frozen=True)
class SchedulerAdvice:
    scheduler: str
    task: tuple[str, ...]
    error: tuple[str, ...]


def site_label(site_id: int) -> str:
    return SITE_LABELS[site_id]


@dataclass(frozen=True)
class UserPrompt:
    request_id: int
    text: bytes
    stage: str = "user_prompt"


@dataclass(frozen=True)
class PrefillRequest:
    request_id: int
    model_id: bytes
    prompt: bytes
    stage: str = "prefill_request"


@dataclass(frozen=True)
class PrefillState:
    request_id: int
    model_id: bytes
    prompt: bytes
    prefix_state: bytes
    stage: str = "prefill_state"


@dataclass(frozen=True)
class Completion:
    request_id: int
    text: bytes
    stage: str = "completion"


@dataclass(frozen=True)
class Response:
    request_id: int
    text: bytes
    stage: str = "response"


def route_to_prefill(prompt: UserPrompt) -> PrefillRequest:
    return PrefillRequest(
        request_id=prompt.request_id,
        model_id=MODEL_ID,
        prompt=prompt.text,
    )


def run_prefill(request: PrefillRequest) -> PrefillState:
    return PrefillState(
        request_id=request.request_id,
        model_id=request.model_id,
        prompt=request.prompt,
        prefix_state=b"prefix:" + request.prompt[:8],
    )


def run_decode(state: PrefillState) -> Completion:
    return Completion(
        request_id=state.request_id,
        text=deterministic_completion(state.prompt),
    )


def package_response(completion: Completion) -> Response:
    return Response(request_id=completion.request_id, text=completion.text)


def deterministic_completion(prompt: bytes) -> bytes:
    digest = hashlib.sha256(prompt).hexdigest()[:16].encode()
    return b"completion:" + digest


def make_storage(*blobs: Blob) -> Storage:
    return Storage({hash(blob): blob for blob in blobs})


def make_event(sender: int, receiver: int, blob: Blob) -> NetworkEvent:
    return NetworkEvent(
        sender=sender,
        receiver=receiver,
        blob_hash=hash(blob),
        blob_size=pocomps.object_size(blob),
    )


def make_policy() -> PolicyParams:
    return PolicyParams(
        task_predictor_hash=hash(TASK_PREDICTOR_COMMITMENT),
        measurement_predictor_hash=hash(MEASUREMENT_PREDICTOR_COMMITMENT),
        scheduler_entropy_budget_per_epoch=1000,
        compute_budget_for_tasks=50,
        compute_budget_per_task=10,
        error_entropy_budget_per_epoch=8,
        entropy_budget_per_task=2,
        sample_rate_per_output_byte=1.0,
    )


class InferenceScheduler:
    def __init__(self, prompt_arrivals: Sequence[PromptArrival]) -> None:
        self.prompt_arrivals = tuple(
            sorted(
                prompt_arrivals,
                key=lambda arrival: arrival.send_tick,
            )
        )
        self.events: list[NetworkEvent] = []
        self.blobs: list[Blob] = []
        self.gateway_prompts: deque[UserPrompt] = deque()
        self.prefill_requests: deque[PrefillRequest] = deque()
        self.decode_states: deque[PrefillState] = deque()
        self.gateway_completions: deque[Completion] = deque()
        self.next_request_id = 0
        self.next_arrival_index = 0

    def emit(self, sender: int, receiver: int, blob: Blob) -> None:
        self.blobs.append(blob)
        self.events.append(make_event(sender, receiver, blob))

    def tick(self, tick: int) -> None:
        if self.gateway_completions:
            completion = self.gateway_completions.popleft()
            self.emit(DATACENTER_GATEWAY, EXTERNAL, package_response(completion))

        if self.decode_states:
            completion = run_decode(self.decode_states.popleft())
            self.emit(DECODE_SITE, DATACENTER_GATEWAY, completion)
            self.gateway_completions.append(completion)

        if self.prefill_requests:
            state = run_prefill(self.prefill_requests.popleft())
            self.emit(PREFILL_SITE, DECODE_SITE, state)
            self.decode_states.append(state)

        if self.gateway_prompts:
            request = route_to_prefill(self.gateway_prompts.popleft())
            self.emit(DATACENTER_GATEWAY, PREFILL_SITE, request)
            self.prefill_requests.append(request)

        while (
            self.next_arrival_index < len(self.prompt_arrivals)
            and self.prompt_arrivals[self.next_arrival_index].send_tick == tick
        ):
            arrival = self.prompt_arrivals[self.next_arrival_index]
            prompt = UserPrompt(
                request_id=self.next_request_id,
                text=arrival.prompt,
            )
            self.emit(EXTERNAL, DATACENTER_GATEWAY, prompt)
            self.gateway_prompts.append(prompt)
            self.next_request_id += 1
            self.next_arrival_index += 1

    def run(self, ticks: int) -> tuple[NetworkEventLog, Storage]:
        for tick in range(ticks):
            self.tick(tick)
        return NetworkEventLog(events=tuple(self.events)), make_storage(*self.blobs)


def run_setup() -> EpochSetup:
    rng = random.Random(SETUP_RANDOM_SEED)
    send_ticks = sorted(rng.sample(range(MAX_PROMPT_SEND_TICK), PROMPT_COUNT))
    prompt_arrivals = tuple(
        PromptArrival(
            send_tick=send_tick,
            prompt=random_prompt(rng, request_id),
        )
        for request_id, send_tick in enumerate(send_ticks)
    )
    return EpochSetup(
        prompt_arrivals=prompt_arrivals,
        ticks=max(send_ticks) + 5,
        params=make_policy(),
        beacon=PUBLIC_RANDOMNESS,
    )


def random_prompt(rng: random.Random, request_id: int) -> bytes:
    token = bytes(rng.randrange(256) for _ in range(8)).hex().encode()
    return b"prompt:" + str(request_id).encode() + b":" + token


def run_execution(setup: EpochSetup) -> tuple[NetworkEventLog, Storage]:
    scheduler = InferenceScheduler(setup.prompt_arrivals)
    return scheduler.run(setup.ticks)


def encode_scheduler_advice(setup: EpochSetup) -> str:
    return json.dumps(
        {
            "ticks": setup.ticks,
            "arrivals": [
                {
                    "send_tick": arrival.send_tick,
                    "prompt": arrival.prompt.hex(),
                }
                for arrival in setup.prompt_arrivals
            ],
        },
        separators=(",", ":"),
    )


def decode_scheduler_advice(
    scheduler_advice: str,
) -> tuple[int, tuple[PromptArrival, ...]]:
    payload = json.loads(scheduler_advice)
    return (
        payload["ticks"],
        tuple(
            PromptArrival(
                send_tick=arrival["send_tick"],
                prompt=bytes.fromhex(arrival["prompt"]),
            )
            for arrival in payload["arrivals"]
        ),
    )


def replay_scheduler_advice(scheduler_advice: str) -> InferenceScheduler:
    ticks, prompt_arrivals = decode_scheduler_advice(scheduler_advice)
    scheduler = InferenceScheduler(prompt_arrivals)
    scheduler.run(ticks)
    return scheduler


def inference_tasks(
    scheduler_advice: str,
) -> tuple[Task, ...]:
    scheduler = replay_scheduler_advice(scheduler_advice)
    measurement_ids_by_request: dict[int, list[int]] = {}

    for event_id, (event, blob) in enumerate(zip(scheduler.events, scheduler.blobs)):
        if event.sender == EXTERNAL:
            continue
        request_id = blob.request_id
        measurement_ids_by_request.setdefault(request_id, []).append(event_id)

    return tuple(
        Task(input_hashes=(), measurement_ids=tuple(measurement_ids))
        for request_id, measurement_ids in sorted(measurement_ids_by_request.items())
    )


def inference_measurements(
    task: Task,
    inputs: tuple[Blob, ...],
    scheduler_advice: str,
    _task_advice: str,
    _error_advice: str,
) -> tuple[Measurement, ...]:
    assert inputs == ()
    scheduler = replay_scheduler_advice(scheduler_advice)
    measurements: list[Measurement] = []

    for measurement_id in task.measurement_ids:
        event = scheduler.events[measurement_id]
        measurements.append(
            Measurement(
                sender=event.sender,
                receiver=event.receiver,
                blob=scheduler.blobs[measurement_id],
            )
        )

    return tuple(measurements)


def compute_advice(
    setup: EpochSetup,
    _event_log: NetworkEventLog,
    _storage: Storage,
) -> SchedulerAdvice:
    scheduler_advice = encode_scheduler_advice(setup)
    tasks = inference_tasks(scheduler_advice)
    return SchedulerAdvice(
        scheduler=scheduler_advice,
        task=tuple("" for _task in tasks),
        error=tuple("" for _task in tasks),
    )


def run_verification(
    setup: EpochSetup,
    event_log: NetworkEventLog,
    storage: Storage,
) -> tuple[tuple[Task, ...], int]:
    advice = compute_advice(setup, event_log, storage)
    baseline = Baseline(
        set(storage.blobs)
        | {
            setup.params.task_predictor_hash,
            setup.params.measurement_predictor_hash,
        }
    )
    tasks = pocomps.audit_epoch(
        event_log,
        storage,
        baseline,
        setup.params,
        beacon=setup.beacon,
        scheduler_advice=advice.scheduler,
        task_advice=advice.task,
        error_advice=advice.error,
        task_predictor=inference_tasks,
        measurement_predictor=inference_measurements,
    )

    error_entropy = sum(len(error) for error in advice.error)
    return tasks, error_entropy


def run_epoch() -> tuple[NetworkEventLog, tuple[Task, ...], int]:
    setup = run_setup()
    event_log, storage = run_execution(setup)
    tasks, error_entropy = run_verification(setup, event_log, storage)
    return event_log, tasks, error_entropy


def print_epoch(
    event_log: NetworkEventLog,
    tasks: tuple[Task, ...],
    error_entropy: int,
) -> None:
    print("network_events=")
    for event in event_log.events:
        print(
            "  "
            f"{site_label(event.sender)} -> {site_label(event.receiver)} "
            f"hash={event.blob_hash} size={event.blob_size}"
        )
    print(f"tasks={tasks}")
    print(f"error_entropy={error_entropy}")


if __name__ == "__main__":
    print_epoch(*run_epoch())
