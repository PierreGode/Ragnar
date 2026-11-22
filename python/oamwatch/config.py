"""oamwatch configuration. Strict validation: unknown keys are an error, not
a silently ignored typo (the dead-knob trap)."""

import json

DEFAULTS = {
    # Slow-protocol rate cap the standard sets, in OAMPDU/second.
    "rate_limit_pdus_per_sec": 10,
    # Seconds between repeat OAM-070 reports while a flood continues.
    "rate_report_cooldown_sec": 10.0,
    # Failure-flag assertions within the window that make it flapping.
    "flap_threshold": 3,
    "flap_window_sec": 300.0,
    # Report every Loopback Control enable, or only the first per peer.
    "report_every_loopback": True,
    # Treat any non-zero trailing octets as smuggled data, disabling the
    # probable-FCS allowance in the parser.
    "strict_tail": False,
    # Emit posture findings (OAM-02x). They are NOTE-discipline preconditions,
    # not verdicts.
    "posture_enabled": True,
    # Suppress these finding codes entirely.
    "suppress": [],
}

_INT_KEYS = ("rate_limit_pdus_per_sec", "flap_threshold")
_FLOAT_KEYS = ("rate_report_cooldown_sec", "flap_window_sec")
_BOOL_KEYS = ("report_every_loopback", "strict_tail", "posture_enabled")


class ConfigError(ValueError):
    pass


class Config:
    __slots__ = tuple(DEFAULTS)

    def __init__(self, **kw):
        for k, v in DEFAULTS.items():
            setattr(self, k, list(v) if isinstance(v, list) else v)
        unknown = set(kw) - set(DEFAULTS)
        if unknown:
            raise ConfigError(
                "unknown configuration key(s): %s" % ", ".join(sorted(unknown)))
        for k, v in kw.items():
            setattr(self, k, v)
        self.validate()

    def validate(self):
        from .registry import REGISTRY
        for k in _INT_KEYS:
            v = getattr(self, k)
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise ConfigError("%s must be a positive integer, got %r" % (k, v))
        for k in _FLOAT_KEYS:
            v = getattr(self, k)
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
                raise ConfigError("%s must be a positive number, got %r" % (k, v))
        for k in _BOOL_KEYS:
            if not isinstance(getattr(self, k), bool):
                raise ConfigError("%s must be a boolean" % k)
        if not isinstance(self.suppress, (list, tuple)):
            raise ConfigError("suppress must be a list of finding codes")
        bad = [c for c in self.suppress if c not in REGISTRY]
        if bad:
            raise ConfigError(
                "suppress names unknown finding code(s): %s" % ", ".join(bad))
        self.suppress = list(self.suppress)
        return self

    @classmethod
    def load(cls, path):
        with open(path, "r") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ConfigError("configuration file must contain a JSON object")
        return cls(**data)

    def as_dict(self):
        return {k: getattr(self, k) for k in DEFAULTS}
