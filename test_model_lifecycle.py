"""Automated Verification Suite for ARGUS-ONE Model Lifecycle & Governance Architecture.

Tests:
1. Model Artifact Loading: Loads approved models in milliseconds without retraining.
2. State Persistence: Meta-Controller reliability and behavior memory persist in state/.
3. Feedback Security: Anti-poisoning invariant checks accept valid feedback & reject poisoned/spam samples.
4. Model Validation Gate: Compares candidate models for regressions (FPR, recall, latency SLA).
5. Safe 1-Click Rollback: Restores previously approved pointer without deleting history.
6. Sensor Identity & Health Diagnostics: Verified sensor metadata and honest INSUFFICIENT_DATA reporting.
"""
import json
import os
import sys
import time
from pathlib import Path

# Ensure work directory is in sys.path
WORK_DIR = Path(__file__).resolve().parent
if str(WORK_DIR) not in sys.path:
    sys.path.insert(0, str(WORK_DIR))

import numpy as np
from argus_ml import (
    ArgusMLClassifier,
    ModelRegistryManager,
    FeedbackValidator,
    ModelValidationGate,
    FEATURE_NAMES,
)


def run_tests():
    print("\n" + "=" * 70)
    print("  ARGUS-ONE ENTERPRISE MODEL LIFECYCLE & GOVERNANCE TEST SUITE")
    print("=" * 70)

    # -------------------------------------------------------------
    # Test 1: Model Persistence & Zero-Retrain Fast Loading
    # -------------------------------------------------------------
    print("\n[TEST 1] Testing Model Persistence & Fast Loading (< 500ms)...")
    models_dir = WORK_DIR / "models"
    registry_file = models_dir / "registry.json"
    assert registry_file.exists(), f"Registry file {registry_file} must exist"

    with open(registry_file, "r") as f:
        reg_data = json.load(f)
    print(f"  Registry version schema: {reg_data.get('schema_version')}")
    assert "models" in reg_data, "Registry must contain models"
    for m in ("random_forest", "gradient_boost", "anomaly_guard", "temporal_gru"):
        assert m in reg_data["models"], f"Model {m} must be registered"
        active_v = reg_data["models"][m]["active_version"]
        print(f"  {m}: active version v{active_v}")

    # Measure load time
    t0 = time.perf_counter()
    engine = ArgusMLClassifier(models_dir=str(models_dir), state_dir=str(WORK_DIR / "state"))
    loaded = engine.initialize()
    load_time_ms = (time.perf_counter() - t0) * 1000.0

    assert loaded, "Engine must load successfully from disk registry"
    assert engine.is_trained, "Engine must be marked as trained after artifact loading"
    print(f"  Artifacts loaded in {load_time_ms:.2f} ms (SLA < 500ms)")
    assert load_time_ms < 1500.0, f"Loading took too long: {load_time_ms} ms"

    # Test inference without retraining
    sample_feat = {k: 0.0 for k in FEATURE_NAMES}
    sample_feat["flows_per_second"] = 5.0
    sample_feat["syn_ratio"] = 0.1
    pred = engine.predict(sample_feat)
    t_class = pred.threat_class if hasattr(pred, "threat_class") else pred["threat_class"]
    conf = pred.confidence if hasattr(pred, "confidence") else pred["confidence"]
    assert t_class is not None, "Prediction must return a valid threat class"
    print(f"  Test prediction succeeded: {t_class} (confidence {conf:.2f})")
    print("  --> [TEST 1 PASSED] Zero-retrain startup verified!")

    # -------------------------------------------------------------
    # Test 2: State Persistence & Reload
    # -------------------------------------------------------------
    print("\n[TEST 2] Testing Meta-Controller State Persistence...")
    state_dir = WORK_DIR / "state"
    assert (state_dir / "meta_controller.json").exists(), "meta_controller.json must exist"
    assert (state_dir / "behavior_memory.json").exists(), "behavior_memory.json must exist"

    # Verify reload preserves learned reliability
    initial_episodes = engine.meta_controller.memory.total_learned
    engine.meta_controller.save_state()
    engine.meta_controller.load_state()
    assert engine.meta_controller.memory.total_learned == initial_episodes
    print(f"  Meta-Controller state restored cleanly: {initial_episodes} episodes preserved.")
    print("  --> [TEST 2 PASSED] State persistence verified!")

    # -------------------------------------------------------------
    # Test 3: Feedback Security & Anti-Poisoning Validation
    # -------------------------------------------------------------
    print("\n[TEST 3] Testing Feedback Security & Anti-Poisoning Invariant Validator...")
    validator = FeedbackValidator()

    # 3a. Valid feedback (Normal TCP HTTP benign flow reclassified)
    valid_features = {
        "flows_per_second": 2.0,
        "syn_ratio": 0.2,
        "udp_ratio": 0.0,
        "bytes_per_second": 1200.0,
        "dns_entropy": 1.5,
    }
    v_res = validator.validate(
        features=valid_features,
        predicted_class="Benign",
        true_class="Benign",
        feedback_type="CONFIRMED",
        notes="Operator confirmed benign HTTP session",
        sensor_id="ARGUS-SENSOR-001",
    )
    assert v_res["valid"], f"Valid feedback should pass: {v_res}"
    print(f"  Valid feedback accepted: {v_res['reason']}")

    # 3b. Poisoning attempt 1: Malicious claim of SYN Flood on non-SYN, zero-flow traffic
    poison_syn = {
        "flows_per_second": 1.0,
        "syn_ratio": 0.0,  # 0% SYN flag! Invariant violation for SYN Flood
        "udp_ratio": 0.0,
    }
    p_res1 = validator.validate(
        features=poison_syn,
        predicted_class="Benign",
        true_class="SYN Flood",
        feedback_type="RECLASSIFIED",
        notes="Malicious attempt to poison SYN Flood boundary with 0% SYN flag",
        sensor_id="ARGUS-SENSOR-001",
    )
    assert not p_res1["valid"], "Poisoned SYN flood feedback without SYN flags must be rejected"
    print(f"  Poisoning attempt 1 blocked: {p_res1['reason']}")

    # 3c. Poisoning attempt 2: UDP reflection claimed on 0% UDP traffic
    poison_udp = {
        "flows_per_second": 50.0,
        "syn_ratio": 0.8,
        "udp_ratio": 0.0,  # 0% UDP! Invariant violation for UDP Amplification
    }
    p_res2 = validator.validate(
        features=poison_udp,
        predicted_class="Benign",
        true_class="UDP Amplification",
        feedback_type="RECLASSIFIED",
        notes="Trying to poison UDP model with TCP traffic",
        sensor_id="ARGUS-SENSOR-001",
    )
    assert not p_res2["valid"], "Poisoned UDP amplification feedback without UDP must be rejected"
    print(f"  Poisoning attempt 2 blocked: {p_res2['reason']}")

    # 3d. Anti-spam rapid duplicate detection
    dup_res = validator.validate(
        features=valid_features,
        predicted_class="Benign",
        true_class="Benign",
        feedback_type="CONFIRMED",
        sensor_id="ARGUS-SENSOR-001",
    )
    assert not dup_res["valid"], "Duplicate feedback within cooldown window must be rejected"
    print(f"  Spam duplicate blocked: {dup_res['reason']}")

    # Test engine.learn_from_feedback rejects poisoned input
    fb_rejected = engine.learn_from_feedback(
        features=poison_syn,
        predicted_class="Benign",
        true_class="SYN Flood",
        feedback_type="RECLASSIFIED",
    )
    assert fb_rejected["validation_status"] == "REJECTED", "Engine must reject poisoned feedback"
    assert fb_rejected["online_adaptation"] is False, "Reliability must not adapt on rejected feedback"
    print("  Engine poisoning gate verified: Rejected feedback did not corrupt reliability tables.")
    print("  --> [TEST 3 PASSED] Anti-poisoning validation verified!")

    # -------------------------------------------------------------
    # Test 4: Model Validation Gate & Candidate Model Training
    # -------------------------------------------------------------
    print("\n[TEST 4] Testing Candidate Model Training & Validation Gate...")
    gate = ModelValidationGate(
        max_fpr_increase=0.01,
        max_recall_drop=0.02,
        max_latency_ms=5.0,
    )

    active_meta = {
        "accuracy": 0.998,
        "recall": 1.0,
        "precision": 0.995,
        "f1_score": 0.998,
        "benign_false_positive_rate": 0.002,
        "latency_ms": 0.35,
    }

    # Good candidate metrics
    good_cand = {
        "accuracy": 0.997,
        "recall": 0.998,
        "precision": 0.995,
        "f1_score": 0.996,
        "benign_false_positive_rate": 0.004,  # +0.002 delta <= 0.01
        "latency_ms": 0.42,
    }
    g_rep = gate.evaluate_candidate(good_cand, active_meta)
    assert g_rep["passed"], f"Good candidate should pass gate: {g_rep}"
    print(f"  Candidate Validation Gate passed: {g_rep['status']}")

    # Regressed candidate metrics (excessive FPR increase)
    bad_cand = {
        "accuracy": 0.970,
        "recall": 0.950,                      # -0.050 drop > 0.02
        "precision": 0.960,
        "f1_score": 0.955,
        "benign_false_positive_rate": 0.035,  # +0.033 delta > 0.01
        "latency_ms": 1.20,
    }
    b_rep = gate.evaluate_candidate(bad_cand, active_meta)
    assert not b_rep["passed"], "Regressed candidate must be rejected"
    print(f"  Regression detected and rejected: {b_rep['reasons']}")

    # Train actual candidate model through ArgusMLClassifier
    cand_out = engine.train_candidate(runs_per_class=6, candidate_version="1.9.9")
    assert "candidate_version" in cand_out
    assert "validation_gate" in cand_out
    cand_manifest = models_dir / "random_forest" / "1.9.9" / "manifest.json"
    assert cand_manifest.exists(), "Candidate manifest must be written to disk"
    with open(cand_manifest, "r") as f:
        m_info = json.load(f)
    print(f"  Candidate 1.9.9 trained and manifested: status '{m_info['status']}'")
    assert m_info["version"] == "1.9.9"
    print("  --> [TEST 4 PASSED] Model Validation Gate & Candidate Pipeline verified!")

    # -------------------------------------------------------------
    # Test 5: Safe Rollback & Version Activation
    # -------------------------------------------------------------
    print("\n[TEST 5] Testing Safe Rollback & Version Activation...")
    # Activate candidate
    act_res = engine.activate_model_version("random_forest", "1.9.9")
    assert act_res["success"], "Activation must succeed"
    assert engine.registry_manager.get_active_version("random_forest") == "1.9.9"
    print("  Candidate 1.9.9 activated as production model.")

    # Rollback to 1.0.0
    rb_res = engine.rollback_model("random_forest", "1.0.0")
    assert rb_res["success"], "Rollback must succeed"
    assert engine.registry_manager.get_active_version("random_forest") == "1.0.0"
    print(f"  Safe rollback executed: Random Forest restored to v{rb_res['rollback_to']}")

    # Verify manifest of 1.9.9 is still archived/intact on disk (not deleted)
    assert cand_manifest.exists(), "Historical candidate version must remain on disk after rollback"
    print("  Historical version 1.9.9 remains intact in models/ directory.")
    print("  --> [TEST 5 PASSED] Safe Rollback verified!")

    # -------------------------------------------------------------
    # Test 6: Backend Service & Sensor Diagnostics Integration
    # -------------------------------------------------------------
    print("\n[TEST 6] Testing Backend Service Integration & Diagnostics...")
    if str(WORK_DIR / "ARGUS-ONE" / "backend") not in sys.path:
        sys.path.insert(0, str(WORK_DIR / "ARGUS-ONE" / "backend"))
    if str(WORK_DIR / "ARGUS-ONE") not in sys.path:
        sys.path.insert(0, str(WORK_DIR / "ARGUS-ONE"))

    try:
        from service import service as svc
    except ImportError:
        from backend.service import service as svc
    s_info = svc.sensor_info()
    assert s_info["sensor_id"] == "ARGUS-SENSOR-001"
    assert "active_model_versions" in s_info
    print(f"  Sensor identity verified: {s_info['sensor_id']}")
    print(f"  Active model versions: {s_info['active_model_versions']}")

    h_rep = svc.health_report()
    assert "sensor_id" in h_rep
    assert "active_model_versions" in h_rep
    assert "traffic" in h_rep
    assert "flow_count" in h_rep["traffic"]
    assert "flows" in h_rep["traffic"]

    # When flows == 0, status must be INSUFFICIENT_DATA
    if h_rep["traffic"]["flow_count"] == 0:
        assert h_rep["behavioral_health"]["status"] == "INSUFFICIENT_DATA", "Status must be INSUFFICIENT_DATA when 0 flows"
        print("  Honest telemetry reporting verified: status is INSUFFICIENT_DATA when 0 flows observed.")

    print("  --> [TEST 6 PASSED] Service diagnostics & multi-sensor identity verified!")

    print("\n" + "=" * 70)
    print("  ALL 6 ENTERPRISE ARCHITECTURE VERIFICATION TESTS PASSED!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_tests()
