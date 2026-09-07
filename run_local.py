"""Start the local API and React dashboard; Ctrl+C stops both processes."""
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    node = shutil.which("node")
    vite = root / "node_modules" / "vite" / "bin" / "vite.js"
    if not node or not vite.exists():
        raise SystemExit("Install Node.js and run npm install in this folder first.")
    for port in (8000, 8443):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                raise SystemExit(f"Port {port} is already in use. Stop the previous server before starting both services.")
    processes = []
    try:
        processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"], cwd=root / "ARGUS-ONE"))
        processes.append(subprocess.Popen([node, str(vite), "--host", "127.0.0.1", "--port", "8443"], cwd=root))
        print("Dashboard: http://127.0.0.1:8443\nOpen Dashboard > Run simulation > All nine attacks.\nCtrl+C stops both services.", flush=True)
        while all(p.poll() is None for p in processes):
            time.sleep(.5)
        raise SystemExit("A server exited. Check the error above.")
    except KeyboardInterrupt:
        print("\nStopping ARGUS-ONE...")
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
