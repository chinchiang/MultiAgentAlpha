"""The reviewer round (GLOSSARY.md: reviewer round, extraction role, ballot round): every reviewer reports findings on
each batch of the bundle for each dimension, one exchange each with a canary of its own (mara.agents.base). The
findings are numbered in content order and their unknown standard references stripped, then the findings of one
dimension at one place (mara.identity.same_place), equally verified, are merged into the one with the highest-scoring
vector, kept whole with the families that found the place. Every reply is counted through mara.audit
(docs/adr/0008-reply-accounting.md). Its result, the reviewers'
findings, is what the ballot round (mara.ballot_round) rules on. Not pure: run asks the reviewers' providers, counts
in the audit, logs through `say` and reports to `progress`; dedupe is pure.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .agents import reviewer
from .agents.context_agent import ContextView
from .audit import Audit, Count, log_tags
from .config import MaraConfig
from .context.repo_map import RepoContext
from .identity import norm_path, same_place
from .progress import Progress
from .providers.base import Provider
from .schemas import Finding, ModelFamily
from .scoring import cvss4
from .scoring.idcheck import check_finding_refs


@dataclass(frozen=True)
class ReviewerFindings:
    """What the reviewers stage hands in: how many findings the reviewers reported, and the deduplicated findings, each
    with the families that found it (`Finding.finder_families`)."""

    raw_count: int
    findings: list[Finding]


def run(ctx: RepoContext, context_view: ContextView | None, *, cfg: MaraConfig, providers: Mapping[str, Provider],
        audit: Audit, say: Callable[[str], None], progress: Progress, egress_blocked: bool,
        over_exchange_limit: bool = False) -> ReviewerFindings:
    """The reviewer round over the bundle `ctx`, the reviewers shown `context_view` when there is one; none of them is
    asked when the secret preflight blocked source egress (`egress_blocked`) or when the round would pass the review's
    exchange limit (`over_exchange_limit`: a round asked in part would leave some of the bundle unread by some
    reviewer), and the reviewers stage is then reported as skipped. The replies are counted in `audit`, with the raw
    and deduplicated finding counts; every pipeline log line goes to `say`."""
    skipped = egress_blocked or over_exchange_limit
    if skipped:
        progress.skip("reviewers", "source egress blocked by the secret preflight" if egress_blocked
                      else f"the {planned_exchanges(ctx, cfg)} context and reviewer exchanges would pass the exchange limit")
        raw = []
    else:
        progress.begin("reviewers")
        raw = _review(ctx, context_view, cfg=cfg, providers=providers, audit=audit, say=say)
    findings = dedupe(raw)
    if not skipped:
        progress.done("reviewers", f"{len(raw)} raw finding(s), {len(findings)} after deduplication")
    audit.set(Count.FINDINGS_RAW, len(raw))
    audit.set(Count.FINDINGS_DEDUPED, len(findings))
    return ReviewerFindings(raw_count=len(raw), findings=findings)


def planned_exchanges(ctx: RepoContext, cfg: MaraConfig) -> int:
    """The exchanges the reviewer round makes over `ctx` under `cfg`, and before it the context agent when a context
    role is configured: for each batch, one for the context agent (mara.agents.context_agent.run_context_agent) and one
    for each dimension and reviewer."""
    batches = sum(1 for _ in ctx.batches())
    return batches * (int(bool(cfg.roles.context)) + len(cfg.dimensions) * len(cfg.roles.reviewers))


def _review(ctx: RepoContext, context_view: ContextView | None, *, cfg: MaraConfig, providers: Mapping[str, Provider],
            audit: Audit, say: Callable[[str], None]) -> list[Finding]:
    """Every reviewer's findings on each batch of `ctx` for each dimension of `cfg`, numbered in content order, with
    their unknown standard references stripped."""
    raw: list[Finding] = []
    for batch in ctx.batches():
        for dim in cfg.dimensions:
            for name in cfg.roles.reviewers:
                prov = providers[name]
                # every exchange plants a canary of its own (agents.base.extraction_exchange)
                findings, rec = reviewer.review_dimension(prov, batch, dim, context_view=context_view)
                audit.record(rec)
                raw.extend(findings)
                say(f"L2: {dim} × {prov.family.value}: {len(findings)} finding(s)" + log_tags(rec))
    # assign ids and strip unknown standard references. Ids are content-ordered (file, line,
    # cwe, dimension, title) rather than call-ordered: consecutive ids no longer reveal which
    # findings shared a reviewer call, so the blinded view leaks no grouping (judge.md promises
    # no source identity; id clusters are a subtle channel back to it).
    raw.sort(key=lambda f: (norm_path(f.provenance[0].file), f.provenance[0].line, f.cwe, f.dimension, f.title))
    out: list[Finding] = []
    for i, f in enumerate(raw, 1):
        f = f.model_copy(update={"id": f"F-{i:04d}"})
        ref = check_finding_refs(f)
        audit.count(Count.STANDARD_REFS_STRIPPED, len(ref.stripped))
        audit.count(Count.UNKNOWN_CWE, int(ref.unknown_cwe))
        out.append(ref.finding)
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings of one dimension at one place (mara.identity.same_place: one file, one CWE, lines at most
    NEAR_LINES apart). The merged finding is the member with the highest-scoring CVSS vector, the first of them on a
    tie, kept whole: its title, provenance, quote and vector together, with the families that found the place as its
    `finder_families`, sorted by name. Keeping the member whole, not the first member's text under the highest vector,
    means the judges rule on the claim that carries the severity: a weak claim at the same place can no longer keep its
    own title on a stronger finding's severity and take that finding down when the judges read the weak claim. An
    unverified finding (possibly fabricated) is never merged into a verified one, nor a verified one into an unverified
    one: it would inherit the other's acceptance and hide the fabrication."""
    reps: list[Finding] = []
    finders: list[set[ModelFamily]] = []
    for f in findings:
        p = f.provenance[0]
        match = None
        f_ok = all(x.verified for x in f.provenance)
        for i, k in enumerate(reps):
            q = k.provenance[0]
            k_ok = all(x.verified for x in k.provenance)
            if k.dimension == f.dimension and k_ok == f_ok and same_place(q.file, q.line, k.cwe, p.file, p.line, f.cwe):
                match = i
                break
        if match is None:
            reps.append(f)
            finders.append({f.source_family})
        else:
            finders[match].add(f.source_family)
            if cvss4.score(f.cvss4_vector) > cvss4.score(reps[match].cvss4_vector):
                reps[match] = f  # the stronger claim becomes the merged finding, its text and its severity together
    return [k.model_copy(update={"finder_families": sorted(fam, key=lambda x: x.value)})
            for k, fam in zip(reps, finders, strict=True)]
