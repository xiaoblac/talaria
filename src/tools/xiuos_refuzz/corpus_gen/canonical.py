"""Canonical form for slot-rename equivalence.

Two programs that differ only by slot index permutation (within the valid
range) are considered equivalent. Invalid slot values (outside [0, 3]) are
left untouched because they exercise a distinct enforcement path in worker.

Sem, mutex, and msgq slots live in separate namespaces —
`SEM_CREATE(slot=0)`, `MUTEX_CREATE(slot=0)`, and `MSGQ_CREATE(slot=0)`
do not collide.
"""

from __future__ import annotations

from worker_abi import ApiId


VALID_SLOT_MAX = 3


SEM_APIS = frozenset(
    {
        int(ApiId.SEM_CREATE),
        int(ApiId.SEM_DELETE),
        int(ApiId.SEM_OBTAIN),
        int(ApiId.SEM_ABANDON),
        int(ApiId.SEM_SET_VALUE),
    }
)


MUTEX_APIS = frozenset(
    {
        int(ApiId.MUTEX_CREATE),
        int(ApiId.MUTEX_DELETE),
        int(ApiId.MUTEX_OBTAIN),
        int(ApiId.MUTEX_ABANDON),
    }
)


MSGQ_APIS = frozenset(
    {
        int(ApiId.MSGQ_CREATE),
        int(ApiId.MSGQ_DELETE),
        int(ApiId.MSGQ_SEND),
        int(ApiId.MSGQ_RECV),
        int(ApiId.MSGQ_URGENT_SEND),
        int(ApiId.MSGQ_REINIT),
    }
)


EVENT_APIS = frozenset(
    {
        int(ApiId.EVENT_CREATE),
        int(ApiId.EVENT_DELETE),
        int(ApiId.EVENT_TRIGGER),
        int(ApiId.EVENT_PROCESS),
    }
)


TIMER_APIS = frozenset(
    {
        int(ApiId.TIMER_CREATE),
        int(ApiId.TIMER_DELETE),
        int(ApiId.TIMER_START_RUN),
        int(ApiId.TIMER_QUIT_RUN),
        int(ApiId.TIMER_MODIFY),
    }
)


def canonical_key(calls) -> tuple:
    sem_rename: dict[int, int] = {}
    mutex_rename: dict[int, int] = {}
    msgq_rename: dict[int, int] = {}
    event_rename: dict[int, int] = {}
    timer_rename: dict[int, int] = {}
    next_sem = 0
    next_mutex = 0
    next_msgq = 0
    next_event = 0
    next_timer = 0
    normalized: list[tuple] = []

    for call in calls:
        api_id = int(call.api_id)
        args = list(int(a) for a in call.args)

        if args:
            slot = args[0]
            if 0 <= slot <= VALID_SLOT_MAX:
                if api_id in SEM_APIS:
                    if slot not in sem_rename:
                        sem_rename[slot] = next_sem
                        next_sem += 1
                    args[0] = sem_rename[slot]
                elif api_id in MUTEX_APIS:
                    if slot not in mutex_rename:
                        mutex_rename[slot] = next_mutex
                        next_mutex += 1
                    args[0] = mutex_rename[slot]
                elif api_id in MSGQ_APIS:
                    if slot not in msgq_rename:
                        msgq_rename[slot] = next_msgq
                        next_msgq += 1
                    args[0] = msgq_rename[slot]
                elif api_id in EVENT_APIS:
                    if slot not in event_rename:
                        event_rename[slot] = next_event
                        next_event += 1
                    args[0] = event_rename[slot]
                elif api_id in TIMER_APIS:
                    if slot not in timer_rename:
                        timer_rename[slot] = next_timer
                        next_timer += 1
                    args[0] = timer_rename[slot]

        normalized.append((api_id, tuple(args)))

    return tuple(normalized)
