"""Typed failures raised by Agent Workspace Guard."""

from __future__ import annotations


class GuardError(RuntimeError):
    """Base class for expected safety and integrity failures."""


class PolicyDenied(GuardError):
    """The requested plan violates a hard policy boundary."""


class StalePlan(GuardError):
    """The real or staged workspace changed after the plan was created."""


class ApprovalError(GuardError):
    """An approval token is missing, invalid, expired, or for another plan."""


class IntegrityError(GuardError):
    """Signed state or an audit chain failed verification."""


class UnsafePath(GuardError):
    """A path failed normalization, containment, or root-safety checks."""
