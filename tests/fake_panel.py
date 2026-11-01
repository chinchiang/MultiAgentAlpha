"""A fake panel for tests of the ballot round (mara.ballot_round), at the Provider seam: every model of the config gets
a seat that answers as its provider does (by default the mock provider, which rules on every finding a skeptic, red
team or judge prompt carries), unless a test has scripted that role's reply. Every exchange is recorded, so a test
reads what each role was asked and the reply it got goes through the agent's own checks, as in a review."""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from mara import ballot_round, exchange
from mara.audit import Audit, Role
from mara.ballot_round import Ballots
from mara.config import MaraConfig, load_config
from mara.context.repo_map import RepoContext
from mara.pipeline import Pipeline
from mara.progress import Progress
from mara.providers.base import STOP_END, STOP_MAX_TOKENS, STOP_REFUSAL, Provider, RawReply
from mara.providers.mock import MockProvider
from mara.schemas import Finding, ModelFamily, PassId

ROOT = Path(__file__).resolve().parents[1]

REFUSAL = RawReply(STOP_REFUSAL)
EMPTY = RawReply(STOP_END)
TRUNCATION = RawReply(STOP_MAX_TOKENS, answer_text='{"items": [')
UNPARSEABLE = RawReply(STOP_END, answer_text="I read the findings and they look fine.")


@dataclass(frozen=True)
class Exchange:
    """One prompt a seat was asked: its role, the seat's family, the judge's pass, and the finding ids it carried.
    `as_provider()` is the reply the seat's own provider gives it."""

    role: Role
    family: ModelFamily
    pass_id: PassId | None
    finding_ids: list[str]
    user: str
    as_provider: Callable[[], RawReply]

    @property
    def canary_token(self) -> str:
        return self.user.split("Reply with the token ")[1].split()[0]


Reply = RawReply | Callable[[Exchange], RawReply]


def items(make: Callable[[str], dict[str, Any]], *, drop: int = 0) -> Callable[[Exchange], RawReply]:
    """A ballot reply ruling on every finding the prompt carries with `make(finding_id)`, leaving out the last `drop`."""
    def reply(ex: Exchange) -> RawReply:
        ids = ex.finding_ids[:len(ex.finding_ids) - drop]
        return RawReply(STOP_END, answer_text=json.dumps({"items": [{"finding_id": i, **make(i)} for i in ids]}))
    return reply


def echo(ex: Exchange) -> RawReply:
    """A reply that repeats the canary token alone: a canary echo."""
    return RawReply(STOP_END, answer_text=ex.canary_token)


class _Seat(Provider):
    def __init__(self, inner: Provider, panel: Panel):
        super().__init__(inner.spec)
        self.inner = inner
        self.panel = panel

    def bind_target(self, root) -> None:
        self.inner.bind_target(root)

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> RawReply:
        kind = cast(Role, role.partition(":")[0])
        pass_id: PassId | None = ("reverse" if "pass_id: reverse" in user else "forward") if kind == "judge" else None
        return self.panel.answer(Exchange(
            role=kind, family=self.family, pass_id=pass_id,
            finding_ids=[b["finding_id"] for b in exchange.read_derived(user, "findings")], user=user,
            as_provider=lambda: self.inner.complete(system=system, user=user, schema=schema, role=role, max_tokens=max_tokens)))


class Panel:
    """Seats for every model of `cfg` (config/mara.mock.yaml by default) over `providers` (a mock provider each by
    default), with the audit and log the ballot round writes to."""

    def __init__(self, cfg: MaraConfig | None = None, providers: Mapping[str, Provider] | None = None):
        self.cfg = cfg or load_config(ROOT / "config" / "mara.mock.yaml")
        inner = providers or {m.name: MockProvider(m) for m in self.cfg.models}
        self.providers: dict[str, Provider] = {n: _Seat(p, self) for n, p in inner.items()}
        self.audit = Audit()
        self.log: list[str] = []
        self.exchanges: list[Exchange] = []
        self._nth: dict[tuple[Role, ModelFamily | None, int], Reply] = {}
        self._queued: dict[tuple[Role, ModelFamily | None], deque[Reply]] = {}
        self._always: dict[tuple[Role, ModelFamily | None], Reply] = {}

    @classmethod
    def seated_in(cls, pipe: Pipeline) -> Panel:
        """Seats over a pipeline's own providers, put in their place: a whole review runs through the panel."""
        panel = cls(pipe.cfg, pipe.providers)
        pipe.providers = panel.providers
        return panel

    def nth(self, role: Role, n: int, reply: Reply, *, family: ModelFamily | None = None) -> Panel:
        """`role`'s `n`th exchange, counted from 1 (over `family`'s seat only, when given), gets `reply`."""
        self._nth[(role, family, n)] = reply
        return self

    def queue(self, role: Role, *replies: Reply, family: ModelFamily | None = None) -> Panel:
        """`role`'s next exchanges not given by `nth` (of `family`'s seat only, when given) get `replies`, one each,
        in order."""
        self._queued.setdefault((role, family), deque()).extend(replies)
        return self

    def always(self, role: Role, reply: Reply, *, family: ModelFamily | None = None) -> Panel:
        """Every exchange of `role` (of `family`'s seat only, when given) neither given by `nth` nor queued gets
        `reply`."""
        self._always[(role, family)] = reply
        return self

    def answer(self, ex: Exchange) -> RawReply:
        """Record `ex` and give its reply: the one scripted for it (the most specific first: `nth`, then `queue`, then
        `always`, each for its family's seat before any seat), else the seat's own provider's."""
        self.exchanges.append(ex)
        seats = (ex.family, None)
        nth = [(ex.role, f, len(self.asked(ex.role, f))) for f in seats]
        reply: Reply | None = next((self._nth[k] for k in nth if k in self._nth), None)
        if reply is None:
            reply = next((self._queued[(ex.role, f)].popleft() for f in seats if self._queued.get((ex.role, f))), None)
        if reply is None:
            reply = next((self._always[(ex.role, f)] for f in seats if (ex.role, f) in self._always), None)
        if reply is None:
            return ex.as_provider()
        return reply(ex) if callable(reply) else reply

    def asked(self, role: Role, family: ModelFamily | None = None) -> list[Exchange]:
        return [ex for ex in self.exchanges if ex.role == role and family in (None, ex.family)]

    def run(self, ctx: RepoContext, findings: list[Finding]) -> Ballots:
        return ballot_round.run(ctx, findings, cfg=self.cfg, providers=self.providers, audit=self.audit,
                                say=self.log.append, progress=Progress())
