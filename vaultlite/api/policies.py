"""Path-based Access Control List (ACL) policies.  OWNER: Student B (Mohammed Siraj).

This module implements VaultLite's authorization engine. Access control is
enforced per-path and per-operation before any cryptographic or storage
action is performed.

Design principles:
- Default deny: If no rule explicitly grants access to a path and capability,
  the operation is denied.
- Least privilege: Policies restrict callers to specific path prefixes
  (e.g., 'db/*', 'app/*') and actions (e.g., read vs write).
- Path matching: Glob patterns (fnmatch) support exact paths ('db/password')
  and subtree wildcards ('db/*').
"""
import fnmatch
from dataclasses import dataclass
from typing import Iterable, Optional


# Standard capabilities supported by the system
CAP_READ = "read"
CAP_WRITE = "write"
CAP_LIST = "list"
CAP_DELETE = "delete"
CAP_ADMIN = "admin"

ALL_CAPABILITIES = frozenset({CAP_READ, CAP_WRITE, CAP_LIST, CAP_DELETE, CAP_ADMIN})


def _normalize_path(path: str) -> str:
    """Normalize path by stripping whitespace and redundant slashes."""
    if not isinstance(path, str):
        raise ValueError("path must be a string")
    return path.strip().strip("/")


@dataclass(frozen=True)
class PathRule:
    """A rule mapping a path pattern to a set of allowed capabilities."""
    pattern: str
    capabilities: frozenset[str]

    def allows(self, path: str, capability: str) -> bool:
        """Return True if this rule matches `path` and permits `capability`."""
        normalized = _normalize_path(path)
        pattern_norm = _normalize_path(self.pattern)
        if pattern_norm == "*" or fnmatch.fnmatchcase(normalized, pattern_norm):
            return capability in self.capabilities
        return False


@dataclass(frozen=True)
class Policy:
    """A named set of path rules representing an authorization policy."""
    name: str
    rules: tuple[PathRule, ...]

    def allows(self, path: str, capability: str) -> bool:
        """Evaluate rules against the given path and capability.

        Returns True on the first rule that allows access. Defaults to False.
        """
        for rule in self.rules:
            if rule.allows(path, capability):
                return True
        return False


# Built-in system policies
BUILTIN_POLICIES: dict[str, Policy] = {
    "root": Policy(
        name="root",
        rules=(
            PathRule(pattern="*", capabilities=ALL_CAPABILITIES),
        ),
    ),
    "admin": Policy(
        name="admin",
        rules=(
            PathRule(pattern="*", capabilities=ALL_CAPABILITIES),
        ),
    ),
    "dev-read": Policy(
        name="dev-read",
        rules=(
            PathRule(pattern="db/*", capabilities=frozenset({CAP_READ, CAP_LIST})),
            PathRule(pattern="app/*", capabilities=frozenset({CAP_READ, CAP_LIST})),
        ),
    ),
    "dev-write": Policy(
        name="dev-write",
        rules=(
            PathRule(pattern="db/*", capabilities=frozenset({CAP_READ, CAP_WRITE, CAP_LIST})),
            PathRule(pattern="app/*", capabilities=frozenset({CAP_READ, CAP_WRITE, CAP_LIST})),
        ),
    ),
}


class PolicyEngine:
    """Registry and evaluator for access control policies."""

    def __init__(self) -> None:
        self._policies: dict[str, Policy] = dict(BUILTIN_POLICIES)

    def register_policy(self, name: str, rules: Iterable[PathRule]) -> None:
        """Register a custom policy."""
        if not name or not name.strip():
            raise ValueError("policy name must be non-empty")
        self._policies[name.strip()] = Policy(name.strip(), tuple(rules))

    def get_policy(self, name: str) -> Optional[Policy]:
        """Look up a policy by name, or return None if not found."""
        return self._policies.get(name)

    def check_permission(self, policy_name: str, path: str, capability: str) -> bool:
        """Evaluate whether `policy_name` permits `capability` on `path`.

        Returns False if the policy is unknown or the rule check fails.
        """
        policy = self.get_policy(policy_name)
        if policy is None:
            return False
        return policy.allows(path, capability)
