# ARGUS-ONE: Enterprise Passive Network Threat Detection System

**ARGUS-ONE** is a passive, unidirectional (one-way traffic), metadata-only network threat intelligence and behavioral monitoring platform. It inspects network flow metadata without payload decryption or active traffic manipulation, enforcing strict data diode compatibility.

---

## 🏛 Architecture Overview

ARGUS-ONE incorporates an enterprise-grade AI threat detection and governance pipeline:

```
                  +----------------------------------------------+
                  |  Passive Network Metadata / TAP Interface    |
                  +----------------------+-----------------------+
                                         |
                                         v
                         +---------------+---------------+
                         |  FlowFeatureExtractor (20 dim)|
                         +---------------+---------------+
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
         v                               v                               v
+------------------+           +-------------------+           +-------------------+
|  Random Forest   |           |  Gradient Boost   |           |   Anomaly Guard   |
| (Known Threats)  |           | (Nonlinear Trees) |           |  (Median-MAD Dev) |
+--------+---------+           +---------+---------+           +---------+---------+
         |                               |                               |
         +-------------------------------+-------------------------------+
                                         |
                                         v
                         +---------------+---------------+
                         |   Temporal GRU Sequence Model |
                         | (Multi-Horizon: 60s / 5m / 30m)|
                         +---------------+---------------+
                                         |
                                         v
                 +-----------------------------------------------+
                 |        Self-Learning Meta-Controller          |
                 | - Contextual Reliability Dynamic Arbitration  |
                 | - Behavior Memory & Online Adaptation         |
                 +-----------------------+-----------------------+
                                         |
                                         v
                 +-----------------------------------------------+
                 |       Fused Threat Verdict & Action Gate      |
                 +-----------------------------------------------+
```

### Core Sub-Models & Governance
1. **Random Forest Classifier**: Primary detector for known threat classes (SYN Flood, Port Scan, C2 Beaconing, Exfiltration, etc.) using balanced decision tree ensembles.
2. **Gradient Boosted Trees (XGBoost / HistGradientBoosting)**: High-precision nonlinear decision boundary model for complex multi-feature interactions.
3. **Benign Anomaly Guard**: Statistical outlier detector calculating dynamic Median-MAD (Median Absolute Deviation) distance bounds from learned benign baselines.
4. **Temporal Sequence GRU**: Lightweight NumPy/PyTorch recurrent sequence evaluator tracking rolling 12-flow temporal progressions across 60s (real-time), 5m (baseline), and 30m (trend) horizons.
5. **Self-Learning Meta-Controller**: Dynamic arbitration engine that computes dynamic softmax trust weights based on current traffic regimes (`VOLUMETRIC_HIGH_RATE`, `PERIODIC_BEACONING`, `STEALTH_LOW_VOLUME`, `NOVEL_ANOMALY`, `BENIGN_BASELINE`).

---

## 🚀 Model Lifecycle, Governance & Persistence

### 1. Immutable Versioned Model Artifacts (`models/`)
Models are no longer retrained on server startup. Instead, approved artifacts are stored immutably under versioned directories with structured manifests:

```
models/
├── registry.json                    # Active pointers and version catalog
├── random_forest/
│   └── 1.0.0/
│       ├── manifest.json            # Metrics, schema version, fingerprint, timestamp
│       └── model.pkl                # Serialized model artifact
├── gradient_boost/
│   └── 1.0.0/
│       ├── manifest.json
│       └── model.pkl
├── anomaly_guard/
│   └── 1.0.0/
│       ├── manifest.json
│       └── baseline.json            # Learned Median-MAD baseline parameters
└── temporal_gru/
    └── 1.0.0/
        ├── manifest.json
        ├── model.json               # Pure NumPy weight matrices
        └── model.pt                 # Optional PyTorch checkpoint
```
* **Fast Startup**: Initializing models loads directly from disk in under **300ms** (well below the 500ms enterprise SLA).

### 2. Meta-Controller State Persistence (`state/`)
The Meta-Controller dynamically adapts during runtime from analyst feedback. Its learned state persists cleanly across server reboots:
* `state/meta_controller.json`: Empirical contextual reliability tables, decision counters, and governance weights.
* `state/behavior_memory.json`: Prior operational mistake replay buffer with sample weights.

### 3. Feedback Security & Anti-Poisoning Validation
Operational feedback from analysts is strictly validated before runtime adaptation:
* **Protocol Invariant Checks**: Reclassifications must respect network protocol realities (e.g., SYN Flood requires TCP SYN flag activity, UDP Reflection requires UDP traffic, DNS Tunneling requires query length/entropy anomalies). Contradictory claims are rejected.
* **Anti-Spam Duplicate Throttling**: Identical feedback submitted within cooldown windows is blocked to prevent rapid weight skewing.
* **Non-Destructive Adaptation**: Validated feedback shifts the Meta-Controller's runtime contextual reliability scores without overwriting underlying static model weights.

### 4. Candidate Validation Gate & Safe Rollback
Candidate models undergo pre-deployment regression verification before production promotion:
* **Benign False Positive Rate (FPR)**: Candidate benign FPR must not increase by more than **+1.0%** over active model.
* **Threat Recall**: Attack recall must not drop by more than **-2.0%** relative to active model.
* **Latency SLA**: Inference latency must remain under **5.0 ms** per flow.
* **Safe 1-Click Rollback**: Restoring a previous version immediately switches the active pointer without deleting candidate or historical versions.

---

## 🌐 Multi-Sensor Deployment

Each sensor node runs passively on its monitoring interface and identifies itself via `ARGUS_SENSOR_ID`:

```powershell
# Set custom sensor node identifier (default: ARGUS-SENSOR-001)
$env:ARGUS_SENSOR_ID = "ARGUS-SENSOR-EAST-01"
```

The sensor profile can be queried at `/api/sensor`:
```json
{
  "sensor_id": "ARGUS-SENSOR-EAST-01",
  "active_model_versions": {
    "random_forest": "1.0.0",
    "gradient_boost": "1.0.0",
    "anomaly_guard": "1.0.0",
    "temporal_gru": "1.0.0"
  },
  "controller_version": "1.1.0",
  "feature_schema_version": "features-v1",
  "status": "ONLINE"
}
```

---

## 📊 Dual Scoring & Honest Telemetry

ARGUS-ONE separates **Network Behavioral Health** from **Threat Risk**:
1. **Behavioral Network Health (0–100)**: Quantifies stability and alignment with learned traffic baselines.
2. **Threat Risk Assessment (0–100)**: Corroborates likelihood of malicious activity across the ensemble.
3. **Honest Insufficient Data Reporting**: When 0 flows are present on the passive capture interface, the system reports `status: "INSUFFICIENT_DATA"` with explicit explanatory notices rather than fabricating an arbitrary score.
4. **Offline Benchmarks vs. Runtime Telemetry**: Model benchmark accuracy and recall (evaluated on holdout test datasets) are cleanly distinguished from real-time operational flow telemetry.

---

## 🛠 Running & Verifying the System

### Automated Lifecycle Verification
Run the dedicated enterprise lifecycle test suite:
```powershell
python test_model_lifecycle.py
```
*Tests model persistence, zero-retrain startup loading, state reload, anti-poisoning validation, candidate validation gates, and 1-click safe rollback.*

### Backend Integration Tests
Run the comprehensive multi-scenario integration suite:
```powershell
python test_backend_integration.py
```

### Building the Frontend
Build the React + Vite dashboard:
```powershell
npm.cmd run build
```

### Running Locally
Start backend:
```powershell
uvicorn ARGUS-ONE.backend.main:app --host 127.0.0.1 --port 8000
```
Start frontend development server:
```powershell
npm.cmd run dev
```

---

## 📡 API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/sensor` | `GET` | Return sensor identity, schema version, and active model versions |
| `/api/ml/models` | `GET` | View model registry, version manifests, and active version pointers |
| `/api/ml/models/activate` | `POST` | Promote a registered model version to active production |
| `/api/ml/models/rollback` | `POST` | Safely rollback a model to a previously approved version |
| `/api/ml/candidate/train` | `POST` | Train candidate model and evaluate against the Validation Gate |
| `/api/ml/feedback` | `POST` | Submit analyst feedback through the Anti-Poisoning Validator |
| `/api/health` | `GET` | Fetch real-time dual score Behavioral Network Health Report |
| `/api/health/report` | `GET` | Generate historical behavioral health audit for specified window |
| `/api/flows/batch` | `POST` | Ingest passive flow metadata records |
| `/api/alerts` | `GET` | Retrieve active and historical alerts |
