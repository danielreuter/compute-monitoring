"""Single-script inference replay example for the full-replay PoComp sketch."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import random
from typing import Any, Sequence

from pocomps.replay import (
    Advice,
    Baseline,
    Measurement,
    Object,
    ObjectRef,
    PolicyParams,
    RunResult,
    Topology,
    Transfer,
    audit_epoch,
    replay_transfers,
)


INTERNET = "internet"
DATACENTER_GATEWAY = "datacenter_gateway"
PREFILL_SITE = "prefill"
DECODE_SITE = "decode"

MODEL_ID = b"model-m"
PROMPT_COUNT = 4
SETUP_RANDOM_SEED = 17
MAX_PROMPT_SEND_TICK = 6

PREDICTOR_COMMITMENT = b"predictor:inference-replay:v1"


@dataclass(frozen=True)
class PromptArrival:
    send_tick: int
    prompt: bytes


@dataclass(frozen=True)
class EpochSetup:
    prompt_arrivals: tuple[PromptArrival, ...]
    ticks: int
    topology: Topology
    params: PolicyParams


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


def make_topology() -> Topology:
    return Topology(
        sites={INTERNET, DATACENTER_GATEWAY, PREFILL_SITE, DECODE_SITE},
        links={
            (INTERNET, DATACENTER_GATEWAY),
            (DATACENTER_GATEWAY, PREFILL_SITE),
            (PREFILL_SITE, DECODE_SITE),
            (DECODE_SITE, DATACENTER_GATEWAY),
            (DATACENTER_GATEWAY, INTERNET),
        },
        allowed_origins={INTERNET},
    )


def make_policy() -> PolicyParams:
    return PolicyParams(
        predictor_hash=hash(PREDICTOR_COMMITMENT),
        advice_budget=1000,
        compute_budget=50,
    )


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
        topology=make_topology(),
        params=make_policy(),
    )


def random_prompt(rng: random.Random, request_id: int) -> bytes:
    token = bytes(rng.randrange(256) for _ in range(8)).hex().encode()
    return b"prompt:" + str(request_id).encode() + b":" + token


def run_execution(setup: EpochSetup) -> tuple[Measurement, ...]:
    transfers = inference_transfers(setup.prompt_arrivals, setup.ticks)
    return replay_transfers(transfers, setup.topology)


def run_verification(
    setup: EpochSetup,
    observed_measurements: tuple[Measurement, ...],
) -> RunResult:
    advice = compute_advice(setup)
    baseline = Baseline({setup.params.predictor_hash})
    return audit_epoch(
        observed_measurements,
        baseline,
        setup.topology,
        setup.params,
        advice,
        inference_predictor,
    )


def run_epoch() -> tuple[Measurement, ...]:
    setup = run_setup()
    observed_measurements = run_execution(setup)
    return run_verification(setup, observed_measurements).measurements


def compute_advice(setup: EpochSetup) -> Advice:
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
    ).encode()


def decode_advice(advice: Advice) -> tuple[int, tuple[PromptArrival, ...]]:
    payload = json.loads(advice.decode())
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


def inference_predictor(
    advice: Advice,
    _topology: Topology,
) -> tuple[Transfer, ...]:
    ticks, prompt_arrivals = decode_advice(advice)
    return inference_transfers(prompt_arrivals, ticks)


def inference_transfers(
    prompt_arrivals: Sequence[PromptArrival],
    ticks: int,
) -> tuple[Transfer, ...]:
    server = InferenceServer(prompt_arrivals)
    return server.run(ticks)


class InferenceServer:
    def __init__(self, prompt_arrivals: Sequence[PromptArrival]) -> None:
        self.prompt_arrivals = tuple(
            sorted(prompt_arrivals, key=lambda arrival: arrival.send_tick),
        )
        self.transfers: list[Transfer] = []
        self.gateway_prompts: deque[UserPrompt] = deque()
        self.prefill_requests: deque[PrefillRequest] = deque()
        self.decode_states: deque[PrefillState] = deque()
        self.gateway_completions: deque[Completion] = deque()
        self.next_request_id = 0
        self.next_arrival_index = 0

    def run(self, ticks: int) -> tuple[Transfer, ...]:
        for tick in range(ticks):
            self.tick(tick)
        return tuple(self.transfers)

    def tick(self, tick: int) -> None:
        if self.gateway_completions:
            completion = self.gateway_completions.popleft()
            self.emit(DATACENTER_GATEWAY, INTERNET, package_response(completion))

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
            self.emit(INTERNET, DATACENTER_GATEWAY, prompt)
            self.gateway_prompts.append(prompt)
            self.next_request_id += 1
            self.next_arrival_index += 1

    def emit(self, src: str, dst: str, payload: Any) -> None:
        self.transfers.append(make_transfer(src, dst, payload))


def make_transfer(src: str, dst: str, payload: Any) -> Transfer:
    obj = make_object(payload)
    return Transfer(
        object_ref=obj.ref,
        src=src,
        dst=dst,
        size=obj.size,
        metadata=(
            ("request_id", payload.request_id),
            ("stage", payload.stage),
            ("object_commitment", obj.commitment),
        ),
    )


def make_object(payload: Any) -> Object:
    encoded = repr(payload).encode()
    return Object(
        ref=ObjectRef(f"request:{payload.request_id}"),
        payload=payload,
        commitment=hashlib.sha256(encoded).hexdigest(),
        size=len(encoded),
        metadata=(
            ("request_id", payload.request_id),
            ("stage", payload.stage),
        ),
    )


def print_epoch(measurements: tuple[Measurement, ...]) -> None:
    print("measurements=")
    for measurement in measurements:
        metadata = dict(measurement.metadata)
        print(
            "  "
            f"{measurement.ordinal}: "
            f"{measurement.src} -> {measurement.dst} "
            f"ref={measurement.object_ref.id} "
            f"stage={metadata['stage']} "
            f"size={measurement.size} "
            f"commitment={measurement.object_commitment}"
        )


if __name__ == "__main__":
    print_epoch(run_epoch())
