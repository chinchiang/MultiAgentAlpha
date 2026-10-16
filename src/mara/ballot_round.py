"""The ballot round (GLOSSARY.md): every ballot role rules on the deduplicated findings. The skeptic first, then the
red team on the findings the skeptic did not refute, then each judge in a forward and a mirrored reverse pass. A
voided reply worth it (mara.audit.worth_retrying) is asked once more, and every reply used is counted through
mara.audit (docs/adr/0008-reply-accounting.md). Its result, the ballots, is what the jury outcome is scored from.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from typing import TypeVar

from .agents import judge, redteam, skeptic
from .audit import Audit, ReplyRecord, log_tags, worth_retrying
from .bias.blinding import blinded_batches
from .bias.diversity import pick_independent
from .config import MaraConfig
from .context.repo_map import MAX_TOTAL_CHARS, RepoContext, bundle_cost
from .progress import Progress
from .providers.base import Provider
from .schemas import Finding, JudgeVote, ModelFamily, RedTeamNote, SkepticVerdict

T = TypeVar("T")

# L3/L4 calls are bounded like the reviewer calls: the skeptic and red team read the evidence files of
# every finding they get, the judges one blinded view per finding. Unbatched, one model's whole share of
# a large review went into one request, overflowed its window or output budget, and left every one of
# those findings unchallenged.
MAX_L3_FINDINGS = 20  # findings per skeptic / red-team call
MAX_L4_FINDINGS = 25  # findings per judge pass


@dataclass(frozen=True)
class Ballots:
    """The skeptic's verdicts and the red team's notes by finding id, the findings the skeptic abstained on (no usable
    verdict reached them), and the judges' votes of both passes."""

    skeptic: dict[str, SkepticVerdict]
    skeptic_abstained: frozenset[str]
    redteam: dict[str, RedTeamNote]
    votes: list[JudgeVote]


def run(ctx: RepoContext, findings: list[Finding], finders: dict[str, set[ModelFamily]], *, cfg: MaraConfig,
        providers: Mapping[str, Provider], audit: Audit, say: Callable[[str], None], progress: Progress) -> Ballots:
    """The ballot round over `findings`, each found by the families in `finders`. The replies used and the discarded
    attempts are counted in `audit`, every pipeline log line goes to `say`, and the skeptic, red team and jury
    stages are reported to `progress`."""
    rounds = _Rounds(cfg, providers, audit, say)
    progress.begin("skeptic")
    sk, abstained = rounds.skeptics(ctx, findings, finders)
    sk_by_id = {v.finding_id: v for v in sk}
    survivors = [f for f in findings if sk_by_id.get(f.id, None) is None or sk_by_id[f.id].verdict != "refuted"]
    progress.done("skeptic", f"{len(sk)} verdict(s) on {len(findings)} finding(s), {len(findings) - len(survivors)} refuted")
    progress.begin("redteam")
    rt = rounds.redteam(ctx, survivors, finders)
    progress.done("redteam", f"{len(rt)} note(s), {sum(n.exploitable == 'yes' for n in rt)} exploitable")
    progress.begin("jury")
    votes = rounds.jury(ctx, findings, sk_by_id, finders)
    progress.done("jury", f"{len(votes)} vote(s) over the forward and reverse passes")
    return Ballots(skeptic=sk_by_id, skeptic_abstained=abstained, redteam={n.finding_id: n for n in rt}, votes=votes)


def l3_chunks(ctx: RepoContext, findings: list[Finding]) -> list[list[Finding]]:
    """Consecutive runs of `findings` whose evidence files fit one request (MAX_TOTAL_CHARS, the reviewer
    bound) and that hold at most MAX_L3_FINDINGS findings. A file shared by several findings is counted
    once per chunk; a finding whose own files exceed the bound still gets a chunk of its own."""
    chunks: list[list[Finding]] = []
    cur: list[Finding] = []
    files: set[str] = set()
    size = 0
    for f in findings:
        own = {p.file for p in f.provenance if p.file in ctx.content}
        new = own - files
        cost = sum(bundle_cost(rel, ctx.content[rel]) for rel in new)
        if cur and (len(cur) >= MAX_L3_FINDINGS or size + cost > MAX_TOTAL_CHARS):
            chunks.append(cur)
            cur, files, size = [], set(), 0
            new = own
            cost = sum(bundle_cost(rel, ctx.content[rel]) for rel in new)
        cur.append(f)
        files |= new
        size += cost
    if cur:
        chunks.append(cur)
    return chunks


def l4_chunks(order: list) -> list[list]:
    """`order` cut into the fewest judge chunks of at most MAX_L4_FINDINGS, of near-equal size. Fixed slices of
    25 left 26 findings as 25 + 1, and a one-finding chunk's reverse pass is its forward pass: that finding was
    judged twice in the same position, so position bias could never show for it."""
    if not order:
        return []
    n = -(-len(order) // MAX_L4_FINDINGS)
    size, extra = divmod(len(order), n)
    out, start = [], 0
    for i in range(n):
        end = start + size + (1 if i < extra else 0)
        out.append(order[start:end])
        start = end
    return out


class _Rounds:
    """One review's skeptic, red-team and jury rounds, over its panel, audit and log."""

    def __init__(self, cfg: MaraConfig, providers: Mapping[str, Provider], audit: Audit, say: Callable[[str], None]):
        self.cfg = cfg
        self.providers = providers
        self.audit = audit
        self.say = say

    def _once_more(self, call: Callable[[], tuple[list[T], ReplyRecord | None]]) -> tuple[list[T], ReplyRecord | None]:
        """`call()` -> (items, reply record), called once more when the reply is worth it (mara.audit.worth_retrying).
        Only the answer used counts; the discarded attempt is recorded as <role>_retries, and the answer used is
        counted by the caller."""
        out, rec = call()
        if rec is not None and worth_retrying(rec):
            self.audit.retried(rec)
            why = ", ".join(sorted(set(rec.log_codes))) or rec.kind
            self.say(f"L3/L4: {rec.role} {rec.family} reply rejected ({why}); asked once more")
            out, rec = call()
        return out, rec

    def _count_and_tag(self, *recs: ReplyRecord | None) -> str:
        """Count the replies used (mara.audit) and give their log tags, each tag once."""
        used = [rec for rec in recs if rec is not None]
        for rec in used:
            self.audit.record(rec)
        return log_tags(*used)

    # ------------------------------------------------------------------ L3
    def skeptics(
        self, ctx: RepoContext, findings: list[Finding], finders: dict[str, set[ModelFamily]]
    ) -> tuple[list[SkepticVerdict], frozenset[str]]:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            # the skeptic must not share a family with ANY finder of this finding
            spec, independent = pick_independent(self.cfg, self.cfg.roles.skeptic, finders[f.id])
            if not independent:
                self.audit["skeptic_same_family"] += 1
                self.say(f"L3: no skeptic outside the finder families of {f.id}; {spec.family.value} reviews it")
            groups[spec.name].append(f)
        verdicts: list[SkepticVerdict] = []
        abstained: set[str] = set()
        for name, fs in ((n, chunk) for n, group in groups.items() for chunk in l3_chunks(ctx, group)):
            fam = self.providers[name].family.value
            v, rec = self._once_more(partial(skeptic.run_skeptic, self.providers[name], ctx, fs))
            tags = self._count_and_tag(rec)
            unverified = rec.count("unverified_controls") if rec else 0
            if not v:
                # no usable verdict for this group - a refusal, a provider failure, or a reply the
                # agent rejected (unparseable, schema-invalid, or not covering every finding exactly
                # once): the findings went unchallenged, so none of them may reach tier B on the
                # skeptic's strength, and the counters above keep the run incomplete
                abstained.update(f.id for f in fs)
            verdicts.extend(v)
            self.say(
                f"L3: skeptic {fam} judged {len(fs)} → {sum(x.verdict == 'refuted' for x in v)} refuted"
                + (f", {unverified} unverifiable control citation(s) downgraded" if unverified else "")
                + tags
            )
        return verdicts, frozenset(abstained)

    def redteam(self, ctx: RepoContext, findings: list[Finding], finders: dict[str, set[ModelFamily]]) -> list[RedTeamNote]:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            spec, independent = pick_independent(self.cfg, self.cfg.roles.redteam, finders[f.id])
            if not independent:
                self.audit["redteam_same_family"] += 1
                self.say(f"L3: no red team outside the finder families of {f.id}; {spec.family.value} reviews it")
            groups[spec.name].append(f)
        notes: list[RedTeamNote] = []
        for name, fs in ((n, chunk) for n, group in groups.items() for chunk in l3_chunks(ctx, group)):
            fam = self.providers[name].family.value
            n, rec = self._once_more(partial(redteam.run_redteam, self.providers[name], ctx, fs))
            tags = self._count_and_tag(rec)
            stripped = rec.count("exploit_code_stripped") if rec else 0
            notes.extend(n)
            self.say(f"L3: red team {fam} probed {len(fs)} → {sum(x.exploitable == 'yes' for x in n)} exploitable"
                     + (f", {stripped} preconditions had exploit code removed" if stripped else "") + tags)
        return notes

    # ------------------------------------------------------------------ L4
    def jury(
        self, ctx: RepoContext, findings: list[Finding], skeptic_by_id: dict[str, SkepticVerdict], finders: dict[str, set[ModelFamily]]
    ) -> list[JudgeVote]:
        votes: list[JudgeVote] = []
        judge_fams = [self.providers[n].family for n in self.cfg.roles.judges]
        min_ind = self.cfg.gate.min_independent_judges

        def independent(f: Finding) -> int:
            return sum(1 for fam in judge_fams if fam not in finders[f.id])

        for name in self.cfg.roles.judges:
            prov = self.providers[name]
            fam = prov.family.value
            # anti self-preference: a family never judges a finding it (co-)produced, unless too few
            # independent families remain, in which case it votes with a discounted weight (self_family).
            eligible, self_ids = [], set()
            for f in findings:
                if prov.family not in finders[f.id]:
                    eligible.append(f)
                elif independent(f) < min_ind:
                    eligible.append(f)
                    self_ids.add(f.id)
                else:
                    self.audit["self_preference_exclusions"] += 1
            self.audit["self_family_fallback_votes"] += len(self_ids)
            if not eligible:
                continue
            # one seeded order over all eligible findings, cut into bounded chunks; each chunk's reverse
            # pass is that chunk mirrored, so every finding is still seen in two mirrored positions
            order, _ = blinded_batches(eligible, skeptic_by_id, ctx.content_hash + prov.family.value)
            for fwd in l4_chunks(order):
                rev = list(reversed(fwd))
                v1, r1 = self._once_more(partial(judge.run_judge, prov, fwd, "forward", self_ids))
                v2, r2 = self._once_more(partial(judge.run_judge, prov, rev, "reverse", self_ids))
                tags = self._count_and_tag(r1, r2)
                votes.extend(v1 + v2)
                self.say(
                    f"L4: judge {fam}: {len(fwd)} finding(s) ({len(self_ids & {b['finding_id'] for b in fwd})} self-family)"
                    f" × 2 passes → {len(v1) + len(v2)} votes" + tags
                )
        return votes
