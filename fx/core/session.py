# Author: Futhark1393
# Description: Session state machine for forensic workflow enforcement.
# States: NEW → CONTEXT_BOUND → ACQUIRING → VERIFYING → SEALED → DONE

from enum import Enum, auto


class SessionState(Enum):
    NEW = auto()
    CONTEXT_BOUND = auto()
    ACQUIRING = auto()
    VERIFYING = auto()
    SEALED = auto()
    DONE = auto()


class SessionStateError(Exception):
    """Raised when an illegal state transition is attempted."""
    pass


# Valid transitions: from_state → set of allowed to_states
_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.NEW: {SessionState.CONTEXT_BOUND},
    SessionState.CONTEXT_BOUND: {SessionState.ACQUIRING},
    SessionState.ACQUIRING: {SessionState.VERIFYING, SessionState.SEALED, SessionState.CONTEXT_BOUND},
    SessionState.VERIFYING: {SessionState.SEALED},
    SessionState.SEALED: {SessionState.DONE},
    SessionState.DONE: set(),
}


class Session:
    """
    Forensic workflow state machine.

    Enforces: NEW → CONTEXT_BOUND → ACQUIRING → VERIFYING → SEALED → DONE
    (ACQUIRING may skip directly to SEALED when verification is not requested.)

    GUI and engine code call these transition methods instead of managing
    ad-hoc boolean flags.
    """

    def __init__(self):
        self._state = SessionState.NEW
        self.case_no: str | None = None
        self.examiner: str | None = None
        self.evidence_dir: str | None = None

    @property
    def state(self) -> SessionState:
        return self._state

    def _transition(self, target: SessionState) -> None:
        allowed = _TRANSITIONS.get(self._state, set())
        if target not in allowed:
            raise SessionStateError(
                f"Illegal transition: {self._state.name} → {target.name}. "
                f"Allowed: {', '.join(s.name for s in allowed) or 'NONE'}"
            )
        self._state = target

    # ── Public transition methods ───────────────────────────────────────

    def bind_context(self, case_no: str, examiner: str, evidence_dir: str) -> None:
        """NEW → CONTEXT_BOUND"""
        self._transition(SessionState.CONTEXT_BOUND)
        self.case_no = case_no
        self.examiner = examiner
        self.evidence_dir = evidence_dir

    def begin_acquisition(self) -> None:
        """CONTEXT_BOUND → ACQUIRING"""
        self._transition(SessionState.ACQUIRING)

    def begin_verification(self) -> None:
        """ACQUIRING → VERIFYING"""
        self._transition(SessionState.VERIFYING)

    def seal(self) -> None:
        """ACQUIRING|VERIFYING → SEALED"""
        self._transition(SessionState.SEALED)

    def finalize(self) -> None:
        """SEALED → DONE"""
        self._transition(SessionState.DONE)

    def abort(self) -> None:
        """ACQUIRING → CONTEXT_BOUND (allows retry after stop/error)."""
        self._transition(SessionState.CONTEXT_BOUND)

    def reset(self) -> None:
        """Reset session to NEW state for reuse (F5 / new acquisition)."""
        self._state = SessionState.NEW
        self.case_no = None
        self.examiner = None
        self.evidence_dir = None