import time
import secrets
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class KeyRotationManager:
    """Manage a time-based password that rotates every interval_seconds.

    This class is framework-agnostic. The GUI should call `tick()` regularly
    (e.g., every 1000 ms) and react to `on_new_password`/`on_tick` callbacks.
    """

    interval_seconds: int = 30
    on_new_password: Optional[Callable[[str], None]] = None
    on_tick: Optional[Callable[[str, int], None]] = None  # (password, seconds_left)

    _current_password: str = field(default_factory=str, init=False)
    _next_rotation_ts: float = field(default=0.0, init=False)

    def start(self) -> None:
        """Initialize the first password and rotation timestamp."""
        self._rotate_password(initial=True)

    @property
    def current_password(self) -> str:
        return self._current_password

    @property
    def seconds_until_rotation(self) -> int:
        remaining = int(self._next_rotation_ts - time.time())
        return max(0, remaining)

    def _generate_password(self) -> str:
        # URL-safe random token, reasonably long for high entropy
        return secrets.token_urlsafe(24)

    def _rotate_password(self, initial: bool = False) -> None:
        self._current_password = self._generate_password()
        self._next_rotation_ts = time.time() + self.interval_seconds

        if self.on_new_password is not None:
            self.on_new_password(self._current_password)

        if self.on_tick is not None:
            # Immediately notify current state
            self.on_tick(self._current_password, self.seconds_until_rotation)

    def tick(self) -> None:
        """Call this periodically (e.g., once per second) from the GUI.

        If it's time to rotate the password, generate a new one.
        Always sends an on_tick update for the GUI.
        """
        now = time.time()
        if now >= self._next_rotation_ts:
            self._rotate_password()
        else:
            if self.on_tick is not None:
                self.on_tick(self._current_password, self.seconds_until_rotation)
