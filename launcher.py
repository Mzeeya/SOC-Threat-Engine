"""Desktop launcher for the SOC Log Analyzer web interface."""

import os
import threading
import webbrowser

from werkzeug.serving import make_server

from app import app


def main():
    server = make_server("127.0.0.1", 0, app, threaded=True)
    url = f"http://127.0.0.1:{server.server_port}/"
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    print("SOC Threat Engine is running in your browser.", flush=True)
    print(f"Address: {url}", flush=True)
    print("Keep this window open while using the app.", flush=True)
    print("Press Enter or Ctrl+C here to close the app.", flush=True)
    if os.environ.get("SOC_LOG_ANALYZER_NO_BROWSER") != "1":
        webbrowser.open(url)

    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        server.shutdown()
        server_thread.join()
        server.server_close()


if __name__ == "__main__":
    main()
