# Building an inference server with verifiable network traffic

Source: https://www.notion.so/f399c8d294c54cb6be98d299b9c8c1f9

## Introduction

We built an inference server that can prove its egress traffic is the expected egress traffic for some inference workload, and thus that no other data is being sent over the verified channel.

This could be useful for verifying an AI slowdown, because we might be able to modify datacenters to not be capable of training frontier models without this showing up in their egress traffic, which our verification would catch. As context for this post, assume:

- Racks can only efficiently communicate over the north-south uplink, and not directly with each other or any other devices (e.g., because we unplugged all other cables, checked that the racks have no wireless transmitters, and have carefully controlled for side channels)
- The north-south uplink is the only high bandwidth communication channel the datacenter has to the external world

Because frontier training runs require multiple racks, if these assumptions were true, in order to participate in a frontier training run a datacenter would have to emit training artifacts (e.g., gradient updates or model weights) over the north-south uplink as egress traffic. These would then have to be sent to other datacenters, or retrieved via the north-south uplink, both of which are mitigated by our verification.

The assumptions from earlier are very load-bearing and non-trivial, because there are lots of weird ways to secretly send information between two computers. A future post will rigorously address both assumptions. This post focuses only on making network traffic verifiable.

## Reproducible traffic is verifiable traffic

If two parties A and B each own a deterministic computer and A wants to convince B that it ran some program, A could send B some artifact resulting from the execution of the claimed program, and ask B to execute the same program. If the artifact sent by A is the same as what B observed in its own execution, B might believe A's claim.

B can't be fully confident however, because A might be sending artifacts from a third party's computer, so B is going to install a trusted measurement device on A's computer and use it to record the artifact A would have otherwise sent. B still doesn't trust A or A's computer, only the measurement device it installed. This is exactly our setting: A (some datacenter) wants to convince B (some verifier, like a government) that it executed only inference. Although the datacenter is completely adversarial, the verifier trusts that a network tap on the north-south uplink is behaving correctly, and can know this because the tap can attest its correct functioning and sometimes be inspected.

The datacenter will tell the verifier what it is going to execute in sufficient detail for the verifier to execute the same workload. The verifier will read their own traffic as well as the datacenter's traffic (via its tap on the north-south uplink). If the traffic is equivalent, then it is fully explained by the workload declared by the datacenter. Because the verifier only accepts inference workloads, this proves that the north-south uplink was used only to send inference traffic.

This has several issues as stated:

- The verifier has to execute the datacenter's entire workload, which might be very expensive
- The datacenter has to tell the prover all of their secrets (their weights, serving stack, inputs, etc.)
- Datacenters do not have deterministic egress traffic, so egress traffic is not verifiable by default

This post focuses entirely on the last point. Future posts will discuss efficient privacy-preserving verification.

## Our implementation

Our implementation can be broken down into three steps:

1. Deterministic containerization using Nix
2. Deterministic inference using vLLM
3. Deterministic networking using an active warden

We show that this combination of infrastructure allows for an inference server to have deterministic traffic.

### Deterministic builds using Nix

- Nix lets us say "to the extent that it is important, these two computers have the same stack"

### vLLM is already very deterministic

- Basically all we do to vLLM is enable batch invariance
- Model weights exfiltration paper + DiFR paper

### Network sanitization via an active warden

- Diagram explaining warden
- Maybe we formally verified that the warden zeroes the covert channel size
- Walk through how we sanitize all of the different header types

## Empirically, the covert egress channel size is ~[N] bits per token

- We did a ton of inference across a few models and the amount of randomness was N bits/token

## Caveats, conclusions and future work

- We made some really strong assumptions at the start that we haven't defended in this post
- Real clusters need to emit logs, and logs could be a covert channel — more on this soon
- We only tested on 8 GPUs, but it was actually really easy to make this work, so we think it's tractable at production scale
- Memory wipes post coming soon
