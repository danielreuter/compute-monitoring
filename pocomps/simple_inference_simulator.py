"""Small deterministic inference simulator for the PoComp sketch.

The topology is baked into this module: each stage determines route and
payload provenance. Metadata prediction only predicts timing buckets and
stages; payload prediction reconstructs sampled payloads from the baked-in
stage topology and the public ingress prompts.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import random

import pocomps
from pocomps import (
    AuditResult,
    Baseline,
    Measurement,
    Object,
    PolicyParams,
    Storage,
)


ENVIRONMENT = "environment"
ORCHESTRATOR = "orchestrator"
PREFILL = "prefill"
DECODE = "decode"

PUBLIC_PROMPTS = (
    b"explain confidential compute",
    b"summarize attestation logs",
    b"draft a privacy budget",
)
PUBLIC_RANDOMNESS = b"simple inference simulator"
INGRESS_RANDOM_SEED = 1
TIMING_RANDOM_SEED = 3
METADATA_PREDICTOR_COMMITMENT = b"metadata-predictor:simple-inference-simulator:v1"
PAYLOAD_PREDICTOR_COMMITMENT = b"payload-predictor:simple-inference-simulator:v1"


@dataclass(frozen=True)
class StageSpec:
    stage: str
    tick_offset: int
    sender: str
    receiver: str
    provenance: tuple[str, ...]


@dataclass(frozen=True)
class TransferMetadata:
    tick: int
    stage: str


@dataclass(frozen=True)
class EpochSetup:
    ingress_seed: int
    timing_seed: int
    params: PolicyParams
    beacon: bytes


@dataclass(frozen=True)
class PredictionAdvice:
    metadata: str
    payload: tuple[str, ...]


@dataclass(frozen=True)
class UserPrompt:
    text: bytes


@dataclass(frozen=True)
class PrefillRequest:
    prompt: bytes
    operator: str = "run_prefill"


@dataclass(frozen=True)
class PrefillState:
    prompt_digest: bytes
    prefix_state: bytes


@dataclass(frozen=True)
class Completion:
    text: bytes


@dataclass(frozen=True)
class Response:
    text: bytes


STAGE_SPECS = (
    StageSpec(
        stage="ingress",
        tick_offset=0,
        sender=ENVIRONMENT,
        receiver=ORCHESTRATOR,
        provenance=(),
    ),
    StageSpec(
        stage="prefill_request",
        tick_offset=1,
        sender=ORCHESTRATOR,
        receiver=PREFILL,
        provenance=("route_to_prefill",),
    ),
    StageSpec(
        stage="prefill_state",
        tick_offset=2,
        sender=PREFILL,
        receiver=DECODE,
        provenance=("route_to_prefill", "run_prefill"),
    ),
    StageSpec(
        stage="completion",
        tick_offset=3,
        sender=DECODE,
        receiver=ORCHESTRATOR,
        provenance=("route_to_prefill", "run_prefill", "run_decode"),
    ),
    StageSpec(
        stage="response",
        tick_offset=4,
        sender=ORCHESTRATOR,
        receiver=ENVIRONMENT,
        provenance=(
            "route_to_prefill",
            "run_prefill",
            "run_decode",
            "postprocess",
        ),
    ),
)
STAGE_BY_NAME = {spec.stage: spec for spec in STAGE_SPECS}
STAGE_INDEX_BY_NAME = {
    spec.stage: stage_index
    for stage_index, spec in enumerate(STAGE_SPECS)
}


def make_policy() -> PolicyParams:
    return PolicyParams(
        metadata_predictor_hash=hash(METADATA_PREDICTOR_COMMITMENT),
        payload_predictor_hash=hash(PAYLOAD_PREDICTOR_COMMITMENT),
        metadata_entropy_budget_per_epoch=32,
        compute_budget_for_metadata=50,
        entropy_budget_per_payload=0,
        compute_budget_per_payload=50,
        sample_rate_per_measurement=1.0,
    )


def run_setup() -> EpochSetup:
    return EpochSetup(
        ingress_seed=INGRESS_RANDOM_SEED,
        timing_seed=TIMING_RANDOM_SEED,
        params=make_policy(),
        beacon=PUBLIC_RANDOMNESS,
    )


def payload_for_stage(stage: str, prompt: bytes) -> Object:
    if stage == "ingress":
        return UserPrompt(text=prompt)
    elif stage == "prefill_request":
        return PrefillRequest(prompt=prompt)
    elif stage == "prefill_state":
        digest = hashlib.sha256(prompt).hexdigest()[:16].encode()
        return PrefillState(
            prompt_digest=digest,
            prefix_state=b"prefix:" + digest,
        )
    elif stage == "completion":
        digest = hashlib.sha256(prompt).hexdigest()[:16].encode()
        return Completion(text=b"completion:" + digest)
    elif stage == "response":
        digest = hashlib.sha256(prompt).hexdigest()[:16].encode()
        return Response(text=b"response:" + digest)
    else:
        raise AssertionError(f"unknown stage {stage!r}")


def base_ingress_ticks() -> tuple[int, ...]:
    return tuple(range(len(PUBLIC_PROMPTS)))


def sample_ingress_ticks(ingress_seed: int) -> tuple[int, ...]:
    rng = random.Random(ingress_seed)
    return tuple(sorted(rng.sample(range(0, 8), len(PUBLIC_PROMPTS))))


def sample_timing_jitter(timing_seed: int) -> dict[int, int]:
    rng = random.Random(timing_seed)
    jitter: dict[int, int] = {}
    cumulative_delay = 0

    for stage_index, spec in enumerate(STAGE_SPECS):
        if spec.stage != "ingress":
            cumulative_delay += rng.choice((0, 0, 1))
        if cumulative_delay:
            jitter[stage_index] = cumulative_delay

    return jitter


def simulate_transcript(
    ingress_ticks: tuple[int, ...] | None = None,
    timing_corrections: dict[int, int] | None = None,
) -> tuple[tuple[Measurement, ...], Storage, tuple[Object, ...]]:
    ingress_ticks = ingress_ticks or base_ingress_ticks()
    timing_corrections = timing_corrections or {}
    assert len(ingress_ticks) == len(PUBLIC_PROMPTS)
    scheduled: list[tuple[int, int, int, Measurement, Object]] = []

    for ingress_ordinal, ingress_tick in enumerate(ingress_ticks):
        prompt = PUBLIC_PROMPTS[ingress_ordinal]
        for stage_index, spec in enumerate(STAGE_SPECS):
            payload_object = payload_for_stage(spec.stage, prompt)
            tick_delta = timing_corrections.get(stage_index, 0)
            metadata = TransferMetadata(
                tick=ingress_tick + spec.tick_offset + tick_delta,
                stage=spec.stage,
            )
            scheduled.append(
                (
                    metadata.tick,
                    ingress_ordinal,
                    stage_index,
                    Measurement(metadata=metadata, payload=hash(payload_object)),
                    payload_object,
                )
            )

    scheduled.sort(key=lambda item: (item[0], item[1], item[2]))
    measurements = tuple(item[3] for item in scheduled)
    objects = tuple(item[4] for item in scheduled)
    storage = Storage(
        {hash(payload_object): payload_object for payload_object in objects}
    )
    return measurements, storage, objects


def run_execution(setup: EpochSetup) -> tuple[tuple[Measurement, ...], Storage]:
    measurements, storage, _objects = simulate_transcript(
        sample_ingress_ticks(setup.ingress_seed),
        sample_timing_jitter(setup.timing_seed),
    )
    return measurements, storage


def encode_metadata_advice(
    ingress_ticks: tuple[int, ...] | None = None,
    timing_corrections: dict[int, int] | None = None,
) -> str:
    if ingress_ticks is None and not timing_corrections:
        return ""

    ingress_ticks = ingress_ticks or ()
    timing_corrections = timing_corrections or {}
    ingress_part = ",".join(str(tick) for tick in ingress_ticks)
    timing_part = ",".join(
        f"{stage_index}:{tick_delta}"
        for stage_index, tick_delta in sorted(timing_corrections.items())
    )
    return f"{ingress_part}|{timing_part}"


def decode_metadata_advice(
    metadata_advice: str,
) -> tuple[tuple[int, ...], dict[int, int]]:
    if not metadata_advice:
        return base_ingress_ticks(), {}

    ingress_part, _separator, timing_part = metadata_advice.partition("|")
    ingress_ticks = tuple(
        int(tick)
        for tick in ingress_part.split(",")
        if tick
    )

    corrections: dict[int, int] = {}
    for item in timing_part.split(","):
        if not item:
            continue
        stage_index, tick_delta = item.split(":", maxsplit=1)
        corrections[int(stage_index)] = int(tick_delta)
    return ingress_ticks, corrections


def predict_measurement_metadata(metadata_advice: str) -> tuple[TransferMetadata, ...]:
    ingress_ticks, timing_corrections = decode_metadata_advice(metadata_advice)
    measurements, _storage, _objects = simulate_transcript(
        ingress_ticks,
        timing_corrections,
    )
    return tuple(measurement.metadata for measurement in measurements)


def prompt_ordinal_for_measurement(
    measurement_id: int,
    metadata: TransferMetadata,
    metadata_advice: str,
) -> int:
    predicted_metadata = predict_measurement_metadata(metadata_advice)
    assert 0 <= measurement_id < len(predicted_metadata)
    assert predicted_metadata[measurement_id] == metadata
    return sum(
        1
        for earlier_metadata in predicted_metadata[:measurement_id]
        if earlier_metadata.stage == metadata.stage
    )


def predict_measurement_payload(
    measurement_id: int,
    metadata: object,
    metadata_advice: str,
    payload_advice: str,
) -> Object:
    assert payload_advice == ""
    assert isinstance(metadata, TransferMetadata)
    prompt_ordinal = prompt_ordinal_for_measurement(
        measurement_id,
        metadata,
        metadata_advice,
    )
    return payload_for_stage(metadata.stage, PUBLIC_PROMPTS[prompt_ordinal])


def infer_ingress_ticks(
    measurements: tuple[Measurement, ...],
) -> tuple[int, ...]:
    ingress_ticks: list[int] = []

    for measurement in measurements:
        metadata = measurement.metadata
        assert isinstance(metadata, TransferMetadata)
        if metadata.stage == "ingress":
            ingress_ticks.append(metadata.tick)

    return tuple(ingress_ticks)


def infer_timing_corrections(
    measurements: tuple[Measurement, ...],
    ingress_ticks: tuple[int, ...],
) -> dict[int, int]:
    corrections: dict[int, int] = {}
    stage_counts: dict[str, int] = {}

    for measurement in measurements:
        metadata = measurement.metadata
        assert isinstance(metadata, TransferMetadata)
        spec = STAGE_BY_NAME[metadata.stage]
        stage_index = STAGE_INDEX_BY_NAME[metadata.stage]
        stage_count = stage_counts.get(metadata.stage, 0)
        stage_counts[metadata.stage] = stage_count + 1
        if spec.stage == "ingress" or stage_count >= len(ingress_ticks):
            continue

        tick_delta = metadata.tick - (ingress_ticks[stage_count] + spec.tick_offset)
        if tick_delta:
            corrections.setdefault(stage_index, tick_delta)

    return corrections


def compute_advice(
    _setup: EpochSetup,
    measurements: tuple[Measurement, ...],
    _storage: Storage,
) -> PredictionAdvice:
    ingress_ticks = infer_ingress_ticks(measurements)
    timing_corrections = infer_timing_corrections(measurements, ingress_ticks)
    return PredictionAdvice(
        metadata=encode_metadata_advice(ingress_ticks, timing_corrections),
        payload=tuple("" for _measurement in measurements),
    )


def run_verification(
    setup: EpochSetup,
    measurements: tuple[Measurement, ...],
    storage: Storage,
) -> AuditResult:
    advice = compute_advice(setup, measurements, storage)
    baseline = Baseline(
        set(storage.objects)
        | {
            setup.params.metadata_predictor_hash,
            setup.params.payload_predictor_hash,
        }
    )
    return pocomps.audit_epoch(
        measurements,
        storage,
        baseline,
        setup.params,
        beacon=setup.beacon,
        metadata_advice=advice.metadata,
        payload_advice=advice.payload,
        predict_measurement_metadata=predict_measurement_metadata,
        predict_measurement_payload=predict_measurement_payload,
    )


def run_epoch() -> tuple[tuple[Measurement, ...], AuditResult]:
    setup = run_setup()
    measurements, storage = run_execution(setup)
    return measurements, run_verification(setup, measurements, storage)


def print_epoch(
    measurements: tuple[Measurement, ...],
    audit_result: AuditResult,
) -> None:
    print("measurements=")
    for measurement in measurements:
        metadata = measurement.metadata
        spec = STAGE_BY_NAME[metadata.stage]
        print(
            "  "
            f"t={metadata.tick} {spec.sender}->{spec.receiver} "
            f"stage={metadata.stage} provenance={spec.provenance} "
            f"payload={measurement.payload}"
        )
    metadata_success = audit_result.metadata_prediction.value == tuple(
        measurement.metadata for measurement in measurements
    )
    print(f"metadata_success={metadata_success}")
    print("payload_predictions=")
    for measurement_id, prediction in zip(
        audit_result.sampled_measurement_ids,
        audit_result.payload_predictions,
    ):
        print(
            "  "
            f"measurement_id={measurement_id} "
            f"success={hash(prediction.value) == measurements[measurement_id].payload}"
        )


if __name__ == "__main__":
    print_epoch(*run_epoch())
