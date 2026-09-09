"""Exercise the shipped issuer/server/client binaries without exposing credential bytes."""
import concurrent.futures
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time

issuer, server, client = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix="aether-echo-") as temporary:
    root = pathlib.Path(temporary)
    credentials = root / "credentials"
    subprocess.run([issuer, str(credentials)], check=True, capture_output=True, timeout=10)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = str(reservation.getsockname()[1])
    log_path = root / "server.log"
    with log_path.open("w") as log:
        process = subprocess.Popen([server, str(credentials / "server.key"), port], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while "listening" not in log_path.read_text():
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("echo server did not start: " + log_path.read_text())
                time.sleep(0.02)

            def echo(index):
                message = f"authenticated-client-{index}"
                result = subprocess.run([client, str(credentials / f"client-{index}.credential"),
                                         "localhost", port, message], text=True, capture_output=True, timeout=15)
                if result.returncode or f"echo: {message}" not in result.stdout:
                    raise RuntimeError(f"client {index} failed: {result.stderr}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                list(executor.map(echo, [1, 2]))
            # A previously spent credential must not establish a second session.
            replay = subprocess.run([client, str(credentials / "client-1.credential"), "localhost", port],
                                    text=True, capture_output=True, timeout=15)
            if replay.returncode == 0:
                raise RuntimeError("spent credential unexpectedly established another connection")
        finally:
            if process.poll() is None:
                if sys.platform == "win32":
                    process.terminate()
                else:
                    process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    if sys.platform != "win32" and process.returncode != 0:
        raise RuntimeError("echo server failed: " + log_path.read_text())
print("Authenticated echo processes passed: two clients and spent-token rejection")
