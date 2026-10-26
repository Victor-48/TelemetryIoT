import time
from datetime import datetime, timezone, timedelta


class VirtualClock:
    """
    Virtual Clock for synchronizing physical telemetry simulation with OS log injection.
    Supports both wall-clock accelerated playback and explicit time advancement for stepping.
    """
    def __init__(self, speed_factor: float = 1.0, manual_mode: bool = False):
        self.speed_factor = speed_factor
        self.manual_mode = manual_mode
        self.manual_elapsed = 0.0
        self.wall_start_time = time.time()
        self.sim_start_time = datetime.now(timezone.utc)

    def advance(self, seconds: float):
        """Advances the virtual timeline by a fixed amount of seconds."""
        self.manual_elapsed += seconds

    def elapsed_sim_seconds(self) -> float:
        if self.manual_mode:
            return self.manual_elapsed
        wall_elapsed = time.time() - self.wall_start_time
        return (wall_elapsed * self.speed_factor) + self.manual_elapsed

    def current_sim_time(self) -> datetime:
        return self.sim_start_time + timedelta(seconds=self.elapsed_sim_seconds())

    def current_iso_time(self) -> str:
        return self.current_sim_time().isoformat()

    def reset(self):
        self.manual_elapsed = 0.0
        self.wall_start_time = time.time()
        self.sim_start_time = datetime.now(timezone.utc)
