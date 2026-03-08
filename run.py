"""
IDS Console — Unified Launcher
================================
Starts the FastAPI backend, IDS packet capture engine,
and opens the dashboard in the default browser.

Usage:
    uv run python run.py
"""

import subprocess
import sys
import os
import time
import webbrowser
import signal
import platform


# ── Paths ──────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
SRC_DIR = os.path.join(BASE_DIR, "src")
DASHBOARD = os.path.join(BASE_DIR, "frontend", "pages", "dashboard.html")

# ── Config ─────────────────────────────────────────
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8000


def banner():
    print(r"""
    ╔══════════════════════════════════════════════════╗
    ║        IDS Console — Unified Launcher            ║
    ╠══════════════════════════════════════════════════╣
    ║  [1] FastAPI Backend   →  http://127.0.0.1:8000  ║
    ║  [2] IDS Capture Engine                          ║
    ║  [3] Dashboard         →  Opening in browser     ║
    ╠══════════════════════════════════════════════════╣
    ║  Press Ctrl+C to stop all services               ║
    ╚══════════════════════════════════════════════════╝
    """)


def kill_port(port):
    """Kill any process using the given port (Windows & Linux)."""
    os_name = platform.system().lower()
    try:
        if os_name == "windows":
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    subprocess.run(
                        ["taskkill", "/PID", pid, "/F"],
                        capture_output=True
                    )
                    print(f"  ⚡ Killed old process on port {port} (PID {pid})")
        else:
            subprocess.run(
                ["fuser", "-k", f"{port}/tcp"],
                capture_output=True
            )
    except Exception:
        pass


def main():
    banner()
    processes = []

    # ── Free port if occupied ──────────────────────
    print("  🔍 Checking port availability...")
    kill_port(BACKEND_PORT)
    time.sleep(0.5)

    # ── 1. Start FastAPI backend ───────────────────
    print(f"  🚀 Starting FastAPI backend on port {BACKEND_PORT}...")
    backend_proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "app:app",
            "--host", BACKEND_HOST,
            "--port", str(BACKEND_PORT),
            "--reload"
        ],
        cwd=BACKEND_DIR
    )
    processes.append(backend_proc)

    # Give backend time to start
    time.sleep(2)

    # ── 2. Start IDS Engine (packet capture) ───────
    print("  🛡️  Starting IDS Capture Engine...")
    ids_proc = subprocess.Popen(
        [sys.executable, "-u", "main.py"],
        cwd=SRC_DIR
    )
    processes.append(ids_proc)

    # ── 3. Open Dashboard in browser ───────────────
    time.sleep(1)
    dashboard_url = f"file:///{DASHBOARD.replace(os.sep, '/')}"
    print(f"  🌐 Opening Dashboard in browser...")
    webbrowser.open(dashboard_url)

    print("\n  ✅ All services running! Press Ctrl+C to stop.\n")

    # ── Wait / Handle Ctrl+C ──────────────────────
    try:
        # Keep alive — monitor subprocesses
        while True:
            # If IDS engine exits (e.g. capture limit reached), keep backend alive
            if ids_proc.poll() is not None:
                print("\n  📊 IDS Capture Engine finished (packet limit reached).")
                print("  💡 Backend still running. Analyze results on the Dashboard.")
                print("     Press Ctrl+C to shut down.\n")
                backend_proc.wait()
                break
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n  🛑 Shutting down all services...")

    finally:
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

        print("  ✅ All services stopped. Goodbye!\n")


if __name__ == "__main__":
    main()
