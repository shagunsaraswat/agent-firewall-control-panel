# Governance

This document describes how the **Agent FirewallKit** open-source project is governed. The model is **Benevolent Dictator for Life (BDFL)**: a single final decision-maker stewards the project while encouraging transparent discussion and community contribution.

> **Placeholders:** Names, emails, and exact release channels below are **TBD** until published. Search for `[PLACEHOLDER: …]` and replace when the project goes public.

## Roles

| Role | Responsibility |
|------|----------------|
| **BDFL** | Final authority on technical direction, release approval, and dispute resolution when consensus cannot be reached. |
| **Maintainers** | Day-to-day review of pull requests, issue triage, and execution of the release process as delegated by the BDFL. |
| **Contributors** | Anyone who proposes changes, files issues, or participates in design discussion under the [Code of Conduct](CODE_OF_CONDUCT.md). |

**[PLACEHOLDER: BDFL name and public contact]** — Benevolent Dictator for Life.

**[PLACEHOLDER: Maintainer list and contact]** — Maintainers (optional team under the BDFL).

## Decision process

1. **Routine changes** (bug fixes, docs, small features aligned with existing design) are decided through normal **pull request review**. Maintainers may approve and merge when requirements in [CONTRIBUTING.md](CONTRIBUTING.md) are met.
2. **Non-trivial or cross-cutting changes** (new subsystems, breaking APIs, security-sensitive behavior) should have **visible design discussion**—for example an issue, RFC-style document in [specs/](specs/), or draft PR—before merge.
3. **Deadlock or strong disagreement** between maintainers or between maintainers and contributors is escalated to the **BDFL**, whose decision is final for that matter.
4. **Code of Conduct** matters follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). **[PLACEHOLDER: CoC escalation contact distinct from BDFL if desired]**

The BDFL is expected to exercise authority in the interest of the project and community, not unilaterally override long-term consensus without good cause.

## Proposals

Larger initiatives should be proposed in a form others can review and comment on:

1. **Open an issue** (or discussion, if enabled) summarizing the problem, proposed approach, and impact on users and operators.
2. **Link supporting material** in [specs/](specs/) or [final_prd/](final_prd/) when specifications already exist or should be updated.
3. **Allow time for feedback** before merging substantial changes; the BDFL or maintainers may request an explicit **proposal/RFC** document for the largest shifts.
4. **Implementation** may proceed in parallel with discussion for experimental branches, but **merge to `main`** should reflect settled direction or BDFL approval.

Security-sensitive proposals should use **[PLACEHOLDER: security reporting process / email]** instead of public issues until assessed.

## Release process (overview)

Releases are **versioned artifacts** (crates, binaries, container images, or bindings) cut from a stable branch or tagged commit on `main`, following [Semantic Versioning](https://semver.org/) for public APIs where applicable.

Typical steps:

1. **Freeze window:** Critical fixes only; ensure CI on `main` is green ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).
2. **Changelog:** Summarize user-visible changes since the last release **[PLACEHOLDER: location of CHANGELOG.md or release notes policy]**.
3. **Tag:** Create an annotated git tag (for example `v0.x.y`) on the release commit.
4. **Publish:** **[PLACEHOLDER: crates.io, GitHub Releases, container registry, etc.]**
5. **Announce:** **[PLACEHOLDER: blog, discussion forum, or social account]**

Exact checklists and automation may evolve; this section is the high-level contract.

## Changing governance

Material changes to this governance document (for example moving away from BDFL or expanding the maintainer team) require **public proposal** and **explicit BDFL approval** (and, if the BDFL steps down, a successor or documented transition plan).

## Contact summary (fill in when ready)

| Purpose | Contact |
|---------|---------|
| General maintainer / PR questions | `[PLACEHOLDER: email or link]` |
| Security reports | `[PLACEHOLDER: security contact]` |
| Code of Conduct enforcement | `[PLACEHOLDER: must match CODE_OF_CONDUCT.md]` |
| BDFL (escalation) | `[PLACEHOLDER: email or link]` |
