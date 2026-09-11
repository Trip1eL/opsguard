from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SandboxState:
    isolated_hosts: set[str] = field(default_factory=set)
    disabled_users: set[str] = field(default_factory=set)
    blocked_domains: set[str] = field(default_factory=set)


class ResponseSimulator:
    """Side-effect-free response adapter for the local prototype."""

    def __init__(self, state: SandboxState | None = None) -> None:
        self.state = state or SandboxState()

    def isolate_host(self, host: str) -> str:
        self.state.isolated_hosts.add(host)
        return f"simulated host isolation: {host}"

    def disable_user(self, user: str) -> str:
        self.state.disabled_users.add(user)
        return f"simulated user disable: {user}"

    def block_domain(self, domain: str) -> str:
        self.state.blocked_domains.add(domain)
        return f"simulated domain block: {domain}"

