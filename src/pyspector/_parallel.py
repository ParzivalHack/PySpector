"""
Process-pool helper for PySpector's CPU-bound AST front end.

``ast.parse`` and the JSON encoding of the tree hold the GIL, so threads cannot speed them up;
separate processes can. On a 525k-line corpus, parsing + encoding takes ~8 s in one process and
~1 s on 8 workers.

Workers are always *spawned*, never forked: the parent may already own threads (Rust/rayon
workers, the watch-mode file observer) and forking a multi-threaded process can deadlock. Spawned
workers only import the lightweight modules that define the task function.

The pool is strictly an optimisation. `parallel_map` returns ``None`` whenever it is not worth it
or not possible, and the caller then simply does the work in its own process.

Set the environment variable ``PYSPECTOR_NO_PARALLEL=1`` to disable the pool (for debugging, or
if it ever misbehaves on a particular machine). The number of workers is always chosen
automatically.
"""

from __future__ import annotations

import multiprocessing
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Callable, List, Optional, Sequence

# Starting workers costs roughly 0.2-0.5 s, so small jobs stay in-process. At ~3 MB of source per
# second in one process, 1.5 MB is about where a pool starts to pay off.
MIN_TASKS = 16
MIN_TOTAL_COST = 1_500_000
MAX_WORKERS = 16

_ENV_DISABLE = "PYSPECTOR_NO_PARALLEL"


def _disabled_by_environment() -> bool:
    """True when PYSPECTOR_NO_PARALLEL is set to anything but empty/0/false/no/off."""
    return os.environ.get(_ENV_DISABLE, "").strip().lower() not in ("", "0", "false", "no", "off")


def _cpu_budget() -> int:
    """CPUs this process may actually use (respects affinity/cpuset where the OS exposes it)."""
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def worker_count(n_tasks: int) -> int:
    """How many worker processes to use for *n_tasks* tasks (1 means: do not use a pool)."""
    return max(1, min(_cpu_budget(), MAX_WORKERS, n_tasks))


def parallel_map(
    fn: Callable[[Any], Any],
    tasks: Sequence[Any],
    *,
    costs: Optional[Sequence[int]] = None,
    on_note: Optional[Callable[[str], None]] = None,
) -> Optional[List[Any]]:
    """Return ``[fn(t) for t in tasks]`` computed in worker processes, in input order.

    Returns ``None`` when the pool is not worth starting (too little work), not allowed (frozen
    executable, no interpreter path, one CPU, disabled by PYSPECTOR_NO_PARALLEL) or fails to run.
    The caller must then do the work itself. *fn* must be a picklable module-level function that
    does not raise; *costs* (e.g. source sizes) is used to skip tiny jobs and to start with the
    biggest tasks so the workers finish together. *on_note* receives a short explanation when
    the pool fails unexpectedly.
    """
    if _disabled_by_environment():
        return None
    n = len(tasks)
    if n < MIN_TASKS:
        return None
    if costs is not None and sum(costs) < MIN_TOTAL_COST:
        return None
    # A frozen app (or an embedding host such as the API server) has no usable Python
    # interpreter to spawn: sys.executable would be the host binary itself.
    if getattr(sys, "frozen", False) or not sys.executable:
        return None
    workers = worker_count(n)
    if workers < 2:
        return None

    if costs is not None:
        sizes = list(costs)
        order = sorted(range(n), key=lambda i: sizes[i], reverse=True)
    else:
        order = list(range(n))
    ordered_tasks = [tasks[i] for i in order]
    chunksize = max(1, min(16, n // (workers * 16)))

    def note(exc: BaseException) -> None:
        if on_note is not None:
            on_note(
                f"Parallel parsing unavailable ({type(exc).__name__}: {exc}); using one process."
            )

    try:
        executor = ProcessPoolExecutor(
            max_workers=workers, mp_context=multiprocessing.get_context("spawn")
        )
    except Exception as exc:  # e.g. no semaphores/pipes in a restricted sandbox
        note(exc)
        return None
    try:
        done = list(executor.map(fn, ordered_tasks, chunksize=chunksize))
    except Exception as exc:  # a worker died or could not start: the caller falls back
        executor.shutdown(wait=False, cancel_futures=True)
        note(exc)
        return None
    except BaseException:  # KeyboardInterrupt and friends: stop the workers, then propagate
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    executor.shutdown()

    results: List[Any] = [None] * n
    for position, index in enumerate(order):
        results[index] = done[position]
    return results
