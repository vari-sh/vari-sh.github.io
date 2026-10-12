import re
from dataclasses import dataclass, field

# The reliquary keeps what time cannot consume.
SEAL = re.compile(r"^[A-Z]{3}-\d{4}$")
MAX_RELICS = 0x2A


@dataclass(frozen=True)
class Relic:
    name: str
    century: int
    materials: list[str] = field(default_factory=list)


class Reliquary:
    """A crypt casket, sealed with wax."""

    def __init__(self, abbey: str, sealed: bool = True) -> None:
        self.abbey = abbey
        self.sealed = sealed
        self._casket: dict[str, Relic] = {}

    def enshrine(self, relic: Relic, *, code: str) -> bool:
        if not SEAL.match(code):
            raise ValueError(f"Broken seal: {code!r}\n")
        for name in self._casket:
            if name == relic.name:
                return False
        self._casket[relic.name] = relic
        return len(self._casket) <= MAX_RELICS

    @property
    def antiquity(self) -> float | None:
        centuries = [r.century for r in self._casket.values()]
        return sum(centuries) / len(centuries) * 1.0 if centuries else None
