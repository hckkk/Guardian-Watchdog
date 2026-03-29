import time
import threading
import guardian_v0

def run_loop():
    stop_event = threading.Event()
    guardian_v0.watchdog_loop(stop_event)

# Mock is_remote_tool_running to return True, "Notepad"
guardian_v0.is_remote_tool_running = lambda: (True, "Notepad")
guardian_v0.SENSITIVE_KEYWORDS = ["Test"]

# Mock get_active_window_title to return "Test Window"
guardian_v0.get_active_window_title = lambda: "Test Window"

# Mock kill_sensitive_window
guardian_v0.kill_sensitive_window = lambda: print("Mock kill")

guardian_v0.main()
