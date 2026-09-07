"""Exercise the dashboard API on an isolated port and temporary database."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent


def main():
    with tempfile.TemporaryDirectory(prefix="argus-test-") as directory:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = {**os.environ, "ARGUS_DB_PATH": str(Path(directory) / "test.sqlite3")}
        process = None

        def request(path, method="GET", data=None, expected=200):
            req = Request(f"http://127.0.0.1:{port}/api{path}", method=method,
                          data=None if data is None else json.dumps(data).encode(),
                          headers={"Content-Type": "application/json"})
            try:
                with urlopen(req, timeout=30) as response:
                    assert response.status == expected
                    return json.load(response)
            except HTTPError as error:
                assert error.code == expected, error.read().decode()
                return json.load(error)

        def start():
            child = subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", str(port)],
                                     cwd=ROOT / "ARGUS-ONE", env=env, stdout=subprocess.DEVNULL,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            for _ in range(100):
                if child.poll() is not None:
                    raise RuntimeError("Test server failed to start")
                try:
                    request("/state")
                    return child
                except URLError:
                    time.sleep(.1)
            child.terminate()
            child.wait()
            raise RuntimeError("Test server was not ready")

        def simulate(scenario):
            request("/simulate/" + scenario, "POST", expected=202)
            for _ in range(200):
                state = request("/state")
                simulation = state["simulation"]
                if simulation["status"] not in {"running", "stopping"}:
                    assert simulation["status"] == "complete", simulation
                    assert not simulation["missing"], simulation
                    return state
                time.sleep(.1)
            raise AssertionError("Simulation timed out")

        try:
            process = start()
            initial = request("/state")
            assert initial["alerts"] == [] and initial["flows"] == []
            state = simulate("all")
            assert len(state["simulation"]["detected"]) == 9
            assert state["summary"]["flows_processed"] == 5559
            assert state["dns"] and state["tls"]
            assert all(f["origin"] == "simulation" for f in state["flows"])
            print("PASS: all nine scenarios, flows, DNS/TLS and engine statistics")
            alert = state["alerts"][0]
            request("/alerts/"+alert["alert_id"], "PATCH", {"status": "ACKNOWLEDGED"})
            request("/alerts/"+alert["alert_id"], "PATCH", {"status": "RESOLVED"})
            request("/alerts/missing", "PATCH", {"status": "OPEN"}, expected=404)
            request("/alerts/"+alert["alert_id"], "PATCH", {"status": "INVALID"}, expected=422)
            request("/config", "PUT", {"scan_min_ports": 2})
            request("/config", "PUT", {"scan_min_ports": -1}, expected=422)
            request("/config", "PUT", {"scan_min_ports": 2.5}, expected=422)
            request("/config", "PUT", {"unknown": 2}, expected=422)
            flow = dict(timestamp="2026-09-05T00:00:00Z", src_ip="10.1.2.3", dst_ip="10.3.2.1", src_port=50000, dst_port=20, protocol="TCP", bytes_out=60, bytes_in=0, packets_out=1, packets_in=0, tcp_flags="S")
            request("/flows", "POST", {**flow, "src_ip": "invalid"}, expected=422)
            request("/flows", "POST", {**flow, "timestamp": "2026-09-05T00:00:00"}, expected=422)
            request("/flows", "POST", flow)
            result = request("/flows", "POST", {**flow, "timestamp": "2026-09-05T00:00:03Z", "dst_port": 21})
            assert any(a["detector"] == "fanout_scan" for a in result["alerts"])
            request("/baseline/fit", "POST", [{**flow, "tcp_flags": "A", "bytes_in": 120, "packets_in": 1}])
            process.terminate(); process.wait(); process = None
            process = start()
            state = request("/state")
            assert state["config"]["scan_min_ports"] == 2
            assert state["baseline"]["flows"] == 1
            assert next(a for a in state["alerts"] if a["alert_id"] == alert["alert_id"])["status"] == "RESOLVED"
            print("PASS: alert updates, validation, configuration effects and restart persistence")
            request("/config", "PUT", {"scan_min_ports": 20})
            count = len(state["alerts"])
            state = simulate("all")
            assert len(state["alerts"]) > count
            for detector in state["detectors"]:
                simulate(detector["id"])
            print("PASS: repeat all-attacks run and each of nine individual scenarios")
            health = request("/health")
            assert "behavioral_health" in health
            assert "threat_risk" in health
            assert "traffic" in health
            assert "behavior" in health
            assert "models" in health
            assert "governance" in health
            assert "explanation" in health
            assert 0 <= health["behavioral_health"]["score"] <= 100
            assert 0 <= health["threat_risk"]["score"] <= 100
            assert "60s" in health["behavior"]["horizons"]
            assert "5m" in health["behavior"]["horizons"]
            assert "30m" in health["behavior"]["horizons"]
            print("PASS: Behavioral network health scoring & multi-horizon diagnostics")

            report_1h = request("/health/report?window=1h")
            assert "title" in report_1h
            assert "overall_health" in report_1h
            assert "threat_risk" in report_1h
            assert "conclusion" in report_1h
            assert "ai_analysis" in report_1h
            print("PASS: Behavioral network health historical report generation")
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
