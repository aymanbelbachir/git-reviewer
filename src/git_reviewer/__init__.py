"""git-reviewer: a local, security-first code reviewer for git.

Importing the package hardens the process environment before anything else runs, so that no
module imported later (LangChain, httpx, the Ollama client) can pick up tracing, telemetry or
proxy settings (docs/ARCHITECTURE.md §9, SECURITY.md T-24 and T-25).
"""

import os

__version__ = "0.1.0"

_TRACING_OFF = {
    "LANGCHAIN_TRACING_V2": "false",
    "LANGCHAIN_TRACING": "false",
    "LANGSMITH_TRACING": "false",
    "LANGSMITH_TRACING_V2": "false",
}
# OLLAMA_API_KEY is an Ollama cloud credential; the ollama client sends it on every request.
_REMOVED_EXACT = frozenset(
    {"LANGCHAIN_API_KEY", "LANGCHAIN_ENDPOINT", "LANGCHAIN_PROJECT", "OLLAMA_API_KEY"}
)
_REMOVED_PREFIXES = ("LANGSMITH_",)
_PROXY_VARS = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"})


def _harden_process_environment() -> None:
    for name in list(os.environ):
        upper = name.upper()
        if upper in _REMOVED_EXACT or upper in _PROXY_VARS or upper.startswith(_REMOVED_PREFIXES):
            del os.environ[name]
    os.environ.update(_TRACING_OFF)


_harden_process_environment()
