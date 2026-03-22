# Memory transparency system architecture

Source: https://www.notion.so/31b399515d9e81409a7ad27afc3cbf42

---

This document sketches out the possible architecture of a **memory transparency system (MTS)** — a suite of protocols that aim to **limit the prover's covert memory capacity** — that is, the number of bytes that the prover can hold in memory without the verifier ever learning about them.

It does the following:

1. Disables much of the prover's memory by unplugging it or filling it with synthetic state
2. Periodically overwrites non-disabled memory ("working memory") with verifier-checkable content.
3. Bounds the prover's covert memory capacity to whatever survives each sanitization boundary.

We apply this framework to an NVL72 rack and evaluate three candidate sanitization approaches.

---

> **Limitations:**
> 1. Still figuring out what the memory capacities of the devices on a real rack look like
> 2. Still not sure how practically attainable security properties of the system affect the throughput of meaningful covert workloads
> 3. Still not sure how to implement the working memory sanitization protocol — currently the seemingly-best approach is being sketched out separately
> 4. We don't yet know what workloads actually matter, so we don't know how much memory we can disable

---

## 1. Problem statement

We consider a setting with a developer that operates a rack of AI hardware (**prover**) and an external auditor (**verifier**) that wants to ensure that the prover is not running large-scale covert workloads — that is, workloads that the verifier is unaware of.

### 1.1. Assumptions

- The verifier can **perfectly reproduce any of the prover's declared state**, e.g. because the prover is deterministic and the verifier has access to the prover's declared workload and input data and can replay the computation up to any program step.
- The prover is **isolated (no IO)**. [*We believe this is without loss of generality given a network transparency system, but this may not be quite right — we should consider whether small amounts of IO change the threat model.*]
- The verifier knows the **total memory capacity** of the prover.

> This problem statement simulates a setting in which a **network transparency system (NTS)** is already in place, restricting all external communication.

### 1.2. Threat model

The prover is using all of its compute to do some bad stuff but is not communicating it over the network. Over time it will accumulate covert state (e.g., model checkpoints) and then one day will release it into the wild, terminating the protocol and potentially gaining a decisive strategic advantage over the verifier — which goes against the spirit of cooperation!

### 1.3. Desiderata

1. **Bound C:** Place a tight upper bound on the covert memory capacity — the number of bytes an adversary can hold across a sanitization boundary without the verifier ever learning about them.
2. **Minimize T:** The sanitization procedure should impose minimal reduction in honest computation throughput (target: ~1–7% overhead).

---

## 2. System architecture

### 2.1 Overview

1. The prover and verifier agree on a **working memory allowance** — how much of the rack's memory the prover is permitted to use. Everything outside the allowance gets disabled.
2. **Disable** all non-working memory. Either physically unplug it, or fill it with synthetic state (proof of replication) so there's no room for covert data.
3. The prover **runs its declared workload**.
4. Periodically, **sanitize** all working memory — that is, the prover must overwrite it with verifier-checkable content, squeezing any surviving covert state through a bottleneck of capacity C. Each such **sanitization boundary** takes time T; after the verifier checks, honest state is restored and execution resumes.

### 2.2 Accounting for disabled memory

All memory outside the working memory allowance must be verifiably inert. There are two classes of disabled memory by the protocol's lights:

**Unplugged:** The device is physically removed from the rack.
- *Examples: NVMe SSDs (E1.S cache drives, M.2 boot drives), any other hot-swappable module not required by the working set*
- **Verification strategy:** Physical inspection.

**Stuffed:** The memory remains in the rack but is filled with synthetic state (proof of space), leaving no room for covert data.
- *Examples: HBM capacity beyond the working budget, host LPDDR5X beyond the working budget, DPU DRAM beyond the working budget*
- **Verification strategy:** Continuous proof-of-replication.

### 2.3 Accounting for working memory

Working memory must be periodically sanitized. To understand what sanitization requires, we decompose working memory along two axes:

#### Needed for sanitization?

**Not needed for sanitization:** The sanitization algorithm does not depend on this region's state, so it can be wiped/encrypted as part of the ritual.
- *Examples: the working-set portion of HBM used for model weights or activations, host DRAM used for application data*
- These regions are the easiest to sanitize — the algorithm can freely overwrite them.

**Needed for sanitization:** The prover must retain this state to execute the sanitization algorithm — you can't wipe the thing that's doing the wiping.
- *Examples: sanitization code itself, crypto libraries, stack/heap for the sanitization process, firmware orchestrating the ritual, encryption key buffers*
- This is the bootstrapping problem. These regions are the **irreducible trusted base** — they cannot be sanitized during the ritual because the ritual depends on them. Verification strategies here are limited to: (a) hash-checking against known-good images between rituals, (b) remote attestation of the sanitization environment, (c) accepting as residual and bounding the capacity.

#### Host-addressability

**Host read + write:** The host can read every byte and overwrite with arbitrary data. Encrypt-in-place is possible.
- *Examples: the working-set portion of HBM, host DRAM, DPU DRAM*
- **Verification strategy:** Encrypt-in-place with a verifier-supplied key, then Merkle-commit and spot-check.

**Host read-only:** The host can dump the contents but cannot overwrite them without a signed firmware image from the manufacturer.
- *Examples: SPI NOR firmware flash (GPU VBIOS, CPU UEFI, NIC firmware), BMC flash*
- **Verification strategy:** Hash the contents and compare against a known-good image. An adversary with the manufacturer's signing key could place arbitrary data here and it would pass hash verification against a malicious "known-good" image — so this strategy trusts the manufacturer.

**Host-opaque:** The host has no direct access to the raw storage cells. All reads and writes are mediated by a firmware controller that could lie.
- *Examples: NAND behind a flash translation layer (over-provisioning pools, fake-bad blocks), eMMC behind its controller, write-only GPU registers*
- **Verification strategy:** None via the host interface alone. The firmware controller can report that memory has been overwritten while secretly preserving a hidden partition. Options: (a) physically remove the device if possible, (b) rely on timing/power side-channel analysis to bound hidden capacity, (c) accept as irreducible residual. This is the hardest category.

> Note: We do not rely on power cycling as a verification strategy for volatile memory (e.g. GPU caches, register files, SRAM buffers). While volatile memory is guaranteed to lose state on power removal, cold-boot attacks can recover data from recently powered-off DRAM and SRAM if the off-time and ambient temperature are insufficient. Instead, volatile working memory is treated like any other working memory and must be sanitized by the algorithm.

### Sanitization approaches

We have identified three candidate protocols for sanitizing working memory:

1. **Wipe and reload from network.** Fill working memory with verifier-provided data, then reload honest state from a remote checkpoint server over the network.
2. **Wipe and reload from trusted local storage.** Same fill phase, but reload from trusted SSDs installed in the rack that cryptographically attest I/O integrity.
3. **In-place encoding.** Encode honest state in place under a fresh verifier-provided key (PoRep-inspired), commit via Merkle tree, verifier spot-checks under a tight online deadline, prover decodes to recover.

#### Quick evaluation of different approaches

The table below summarizes sanitization time T across two working memory allowances on an NVL72 rack. Allowance A (HBM only) is the most realistic — most workloads don't use all the host CPU RAM, so Allowance B is likely an overestimate of the working set that actually needs sanitizing.

|  | Allowance A: HBM only (~13.4 TB) | Allowance B: HBM + LPDDR (~30 TB) |
|---|---|---|
| Approach 1 — Network reload | ~30 s – 45 min | ~1 min – 110 min |
| Approach 2 — Trusted local storage | ~15 s – 3 min | ~30 s – 7 min |
| Approach 3 — In-place encoding | ~0.5 s – 3 s | ~3 s – 60 s |

Approach 3 is the clear winner — it directly exploits the massive on-device memory bandwidth (576 TB/s HBM, ~14 TB/s LPDDR) rather than being bottlenecked by network or NVMe I/O. At HBM-only allowances, it achieves ~100–1000× faster sanitization than Approach 1. However, it depends on an unproven cryptographic protocol (in-place PoRep encoding/decoding), and we do not yet have a complete implementation.
