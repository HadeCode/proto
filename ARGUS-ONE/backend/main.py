"""Local ARGUS-ONE API used by the React dashboard and flow collectors."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Literal

# Ensure project root (work/), ARGUS-ONE/, and backend/ are always in sys.path
_CURRENT_DIR = Path(__file__).resolve().parent
_ARGUS_DIR = _CURRENT_DIR.parent
_WORK_DIR = _ARGUS_DIR.parent
for _p in [str(_WORK_DIR), str(_ARGUS_DIR), str(_CURRENT_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

try:
    from .schemas import Flow
    from .service import service
except (ImportError, ValueError):
    from schemas import Flow  # type: ignore
    from service import service  # type: ignore

app = FastAPI(title="ARGUS-ONE Backend", version="1.1.0")


def dump(flow):
    return flow.model_dump(exclude_none=True)


def call(action, *args):
    try:
        return action(*args)
    except KeyError as exc:
        raise HTTPException(404, "Record or scenario not found") from exc
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, TypeError, OverflowError) as exc:
        raise HTTPException(422, str(exc)) from exc


@app.get("/")
def root():
    return {"system": "ARGUS-ONE", "status": "running"}


@app.post("/api/flows")
def receive_flow(flow: Flow):
    return {"success": True, "alerts": call(service.ingest, [dump(flow)])}


@app.post("/api/flows/batch")
def receive_flows(flows: list[Flow]):
    if len(flows) > 20000:
        raise HTTPException(413, "Maximum batch size is 20,000 flows")
    return {"success": True, "alerts": call(service.ingest, [dump(f) for f in flows])}


@app.get("/api/health")
def health():
    return service.health_report()


@app.get("/api/health/report")
def health_historical_report(window: str = "1h"):
    return service.historical_health_report(window=window)


@app.get("/api/state")
def state():
    return service.snapshot()


@app.get("/api/alerts")
def alerts():
    return service.snapshot()["alerts"]


class AlertUpdate(BaseModel):
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"]


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: str, update: AlertUpdate):
    return call(service.set_alert_status, alert_id, update.status)


@app.get("/api/config")
def configuration():
    with service.lock:
        return service.config_dict()


@app.put("/api/config")
def update_configuration(values: dict[str, Any]):
    return call(service.configure, values)


@app.post("/api/baseline/fit")
def fit_baseline(flows: list[Flow]):
    if not 1 <= len(flows) <= 20000:
        raise HTTPException(422, "Provide 1–20,000 known-benign flows")
    return call(service.fit_baseline, [dump(f) for f in flows])


@app.post("/api/simulate/{scenario}", status_code=202)
def simulate(scenario: str):
    return call(service.start_simulation, scenario)


@app.post("/api/stop")
def stop():
    return service.stop_simulation()


class MLTrainRequest(BaseModel):
    runs_per_class: int = 14


class MLSwitchRequest(BaseModel):
    model_type: Literal["meta_controller", "random_forest", "xgboost"]


@app.get("/api/ml/status")
def ml_status():
    return service.ml_status()


@app.post("/api/ml/train")
def train_ml(req: MLTrainRequest | None = None):
    runs = req.runs_per_class if req else 14
    return call(service.train_ml, runs)


@app.post("/api/ml/evaluate")
def evaluate_ml():
    return call(service.evaluate_ml)


@app.post("/api/ml/switch-model")
def switch_model(req: MLSwitchRequest):
    return call(service.switch_ml_model, req.model_type)


@app.post("/api/ml/predict")
def predict_flow(flow: dict[str, Any]):
    return call(service.predict_flow, flow)


class MLFeedbackRequest(BaseModel):
    alert_id: str | None = None
    flow: dict[str, Any] | None = None
    true_class: str = "Benign"
    feedback_type: Literal["FALSE_POSITIVE", "RECLASSIFIED", "CONFIRMED", "MISSED_THREAT"] = "FALSE_POSITIVE"
    notes: str = ""


@app.post("/api/ml/feedback")
def submit_feedback(req: MLFeedbackRequest):
    return call(service.record_feedback, req.alert_id, req.flow, req.true_class, req.feedback_type, req.notes)


@app.get("/api/ml/feedback")
def get_feedback():
    return service.get_feedback_summary()


@app.post("/api/ml/retrain-self")
def retrain_self(req: MLTrainRequest | None = None):
    runs = req.runs_per_class if req else 14
    return call(service.retrain_ml_with_feedback, runs)


@app.get("/api/ml/dataset")
def dataset_info():
    return service.dataset_info()


@app.get("/api/ml/dataset/preview")
def dataset_preview():
    return service.dataset_preview()


@app.get("/api/sensor")
def sensor_info():
    return service.sensor_info()


@app.get("/api/ml/models")
def model_registry():
    return service.get_model_registry()


class MLRollbackRequest(BaseModel):
    model_name: str
    target_version: str


@app.post("/api/ml/models/rollback")
def rollback_model(req: MLRollbackRequest):
    return call(service.rollback_model, req.model_name, req.target_version)


class MLActivateRequest(BaseModel):
    model_name: str
    version: str


@app.post("/api/ml/models/activate")
def activate_model(req: MLActivateRequest):
    return call(service.activate_model_version, req.model_name, req.version)


class MLCandidateTrainRequest(BaseModel):
    runs_per_class: int = 14


@app.post("/api/ml/candidate/train")
def train_candidate(req: MLCandidateTrainRequest | None = None):
    runs = req.runs_per_class if req else 14
    return call(service.train_candidate_model, runs)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)



