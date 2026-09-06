"""Adapter between the FastAPI request models and the ARGUS-ONE detector."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


# ``argus_one.py`` lives beside the ARGUS-ONE application directory. Include
# that project root so the API works when Uvicorn starts from either folder.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from argus_one import ArgusOneDetector  # noqa: E402


detector = ArgusOneDetector()


def detect_flow(flow: Any) -> list[dict[str, Any]]:
    """Process one validated API flow through the streaming ARGUS-ONE engine."""
    # Pydantic v2 uses model_dump; the fallback supports Pydantic v1.
    flow_data = flow.model_dump() if hasattr(flow, "model_dump") else flow.dict()
    return detector.process_flow(flow_data)


def detect_flows(flows: list[Any]) -> list[dict[str, Any]]:
    """Process an ordered collection of validated flows as one replay batch."""
    flow_data = [
        flow.model_dump() if hasattr(flow, "model_dump") else flow.dict()
        for flow in flows
    ]
    return detector.process_batch(flow_data)
