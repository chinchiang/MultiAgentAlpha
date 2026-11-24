"""The exchange limit (GLOSSARY.md: exchange limit): how many exchanges one review may make, counted where no caller
gets round it. Each provider of a review is wrapped (Limited), and the wrappers share the review's ExchangeBudget:
once it is spent, a call raises the provider error `provider_exchange_limit_reached` without asking the model, which
the exchange records as an error reply as it does a provider's own failure (mara.exchange.call), never asked again
(mara.audit.worth_retrying). An exchange is one prompt MARA sends, not one HTTP request: a provider's own retries of
a transient failure are inside it. Not pure: a budget counts."""

from __future__ import annotations

import threading

from .base import Provider, RawReply

LIMIT_REACHED = "provider_exchange_limit_reached"  # a code of the shape mara.exchange.PROVIDER_ERROR_RE lets through


class ExchangeBudget:
    """The exchanges a review may still make: `limit` in all (None for no limit), `used` so far, and `refused`, the
    calls turned away after the limit was reached."""

    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self.used = 0
        self.refused = 0
        self._lock = threading.Lock()

    @property
    def left(self) -> int | None:
        """The exchanges left, or None when there is no limit."""
        return None if self.limit is None else max(0, self.limit - self.used)

    def covers(self, exchanges: int) -> bool:
        """Whether `exchanges` more can still be made."""
        return self.limit is None or self.used + exchanges <= self.limit

    def take(self) -> bool:
        """Count one exchange and say whether it may be made; one over the limit is counted as refused instead."""
        with self._lock:
            if self.limit is not None and self.used >= self.limit:
                self.refused += 1
                return False
            self.used += 1
            return True


class Limited(Provider):
    """`inner` under `budget`: every call takes one exchange of it, and is refused with LIMIT_REACHED once none is
    left. Everything else is the inner provider's: its spec, its output limit (a `max_tokens` the caller gives is passed
    on, and none is passed when it gives none), the models it served, the target it is bound to."""

    def __init__(self, inner: Provider, budget: ExchangeBudget) -> None:
        super().__init__(inner.spec)
        self.inner = inner
        self.budget = budget
        self.served_models = inner.served_models  # one set: the provider manifest reads the wrapper

    def bind_target(self, root) -> None:
        self.inner.bind_target(root)

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int | None = None) -> RawReply:
        if not self.budget.take():
            raise RuntimeError(LIMIT_REACHED)
        if max_tokens is None:
            return self.inner.complete(system=system, user=user, schema=schema, role=role)
        return self.inner.complete(system=system, user=user, schema=schema, role=role, max_tokens=max_tokens)
