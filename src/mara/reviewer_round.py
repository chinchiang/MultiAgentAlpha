"""The reviewer round (GLOSSARY.md: reviewer round, extraction role, ballot round): every reviewer reports findings on
each batch of the bundle for each dimension, one exchange each with a canary of its own (mara.agents.base). The
findings are numbered in content order and their unknown standard references stripped, then the findings of one
dimension at one place (mara.identity.same_place), equally verified, are merged, each kept with the families that
found it. Every reply is counted through mara.audit (docs/adr/0008-reply-accounting.md). Its result, the reviewers'
findings, is what the ballot round (mara.ballot_round) rules on. Not pure: run asks the reviewers' providers, counts
in the audit, logs through `say` and reports to `progress`; dedupe is pure.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .agents import reviewer
from .agents.context_agent import ContextView
from .audit import Audit, log_tags
from .config import MaraConfig
from .context.repo_map import RepoContext
from .identity import norm_path, same_place
from .progress import Progress
from .providers.base import Provider
from .schemas import Finding, ModelFamily
from .scoring.idcheck import check_finding_refs


@dataclass(frozen=True)
class ReviewerFindings:
    """What the reviewers stage hands in: how many findings the reviewers reported, and the deduplicated findings, each
    with the families that found it (`Finding.finder_families`)."""

    raw_count: int
    findings: list[Finding]


def run(ctx: RepoContext, context_view: ContextView | None, *, cfg: MaraConfig, providers: Mapping[str, Provider],
        audit: Audit, say: Callable[[str], None], progress: Progress, egress_blocked: bool) -> ReviewerFindings:
    """The reviewer round over the bundle `ctx`, the reviewers shown `context_view` when there is one; none of them is
    asked when the secret preflight blocked source egress (`egress_blocked`), and the reviewers stage is then reported
    as skipped. The replies are counted in `audit`, with the raw and deduplicated finding counts; every pipeline log
    line goes to `say`."""
    if egress_blocked:
        progress.skip("reviewers", "source egress blocked by the secret preflight")
        raw = []
    else:
        progress.begin("reviewers")
        raw = _review(ctx, context_view, cfg=cfg, providers=providers, audit=audit, say=say)
    findings = dedupe(raw)
    if not egress_blocked:
        progress.done("reviewers", f"{len(raw)} raw finding(s), {len(findings)} after deduplication")
    audit["findings_raw"] = len(raw)
    audit["findings_deduped"] = len(findings)
    return ReviewerFindings(raw_count=len(raw), findings=findings)


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
        audit["standard_refs_stripped"] += len(ref.stripped)
        audit["unknown_cwe"] += int(ref.unknown_cwe)
        out.append(ref.finding)
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings of one dimension at one place (mara.identity.same_place: one file, one CWE, lines at most
    NEAR_LINES apart), the first one kept with the families that found it as its `finder_families`, sorted by name;
    an unverified finding is never merged into a verified one, nor a verified one into an unverified one."""
    kept: list[Finding] = []
    finders: dict[str, set[ModelFamily]] = {}
    for f in findings:
        p = f.provenance[0]
        match = None
        f_ok = all(x.verified for x in f.provenance)
        for k in kept:
            q = k.provenance[0]
            k_ok = all(x.verified for x in k.provenance)
            # never merge an unverified (possibly fabricated) finding into a verified one:
            # it would inherit the verified finding's acceptance and hide the fabrication
            if k.dimension == f.dimension and k_ok == f_ok and same_place(q.file, q.line, k.cwe, p.file, p.line, f.cwe):
                match = k
                break
        if match is None:
            kept.append(f)
            finders[f.id] = {f.source_family}
        else:
            finders[match.id].add(f.source_family)
    return [k.model_copy(update={"finder_families": sorted(finders[k.id], key=lambda x: x.value)}) for k in kept]
