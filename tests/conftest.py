"""Shared fixtures. Ordinary tests must never reach AWS or a real Decider."""

from __future__ import annotations

import pytest

from opsguard.bedrock_client import reset_client_cache


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("OPSGUARD_BEDROCK_ENABLED", "OPSGUARD_BEDROCK_MODEL_ID", "AWS_REGION", "AWS_DEFAULT_REGION",
                 "OPSGUARD_MODEL_ASSISTED_UNKNOWN", "OPSGUARD_MIN_MODEL_CONFIDENCE"):
        monkeypatch.delenv(name, raising=False)
    reset_client_cache()
    try:  # make an accidental real AWS client fail loudly instead of reaching the network
        import boto3

        def _no_aws(*args, **kwargs):
            raise AssertionError("A test tried to create a real AWS client.")

        monkeypatch.setattr(boto3, "client", _no_aws)
    except ImportError:
        pass
