try:
    from win11toast import notify
except Exception as e:
    # When running under a Windows Service, the Python environment can differ
    # from an interactive shell. Avoid failing the service on startup just
    # because toast notifications aren't available.
    def notify(*args, **kwargs):  # type: ignore[no-redef]
        return None
    

def force_alert_popup(title, message):
    """
    Displays a system-modal message box that forces itself on top of all windows
    and ignores Windows Do Not Disturb (Focus Assist) settings.
    Runs in a separate thread so it doesn't block the main watchdog loop.
    """
    def _show_msgbox():
        # MB_OK (0) | MB_ICONWARNING (0x30) | MB_SYSTEMMODAL (0x1000)
        flags = 0 | 0x30 | 0x1000
        ctypes.windll.user32.MessageBoxW(0, message, title, flags)

    threading.Thread(target=_show_msgbox, daemon=True).start()

import psutil
import time
import threading
import sys
import servicemanager
import win32gui
import win32con
import ctypes
import win32serviceutil
import logging
import os

# --- Logging Configuration ---
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'guardian.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)


# --- Configuration ---
# List of process names considered "Remote Tools"
REMOTE_TOOLS = [
    "TeamViewer.exe",
    "TeamViewer_Service.exe",  # Holds actual remote session connections
    "SunloginClient.exe",
    "AnyDesk.exe",
    "Notepad.exe"  # For testing purposes
]

# Process names that don't use TCP connections - treat as "active" if running at all.
# Use for testing (e.g. Notepad) or tools that use other protocols.
# Matching is case-insensitive (Windows/psutil may return different casings).
PROCESS_ONLY_DETECT = frozenset({"notepad.exe", "notepad"})  # some systems omit .exe
_remote_lower = {n.lower() for n in REMOTE_TOOLS}
_remote_lower.add("notepad")  # psutil may return "Notepad" without .exe
REMOTE_TOOLS_LOWER = frozenset(_remote_lower)

# List of keywords that indicate a sensitive window
SENSITIVE_KEYWORDS = [
    "Chase", 
    "Bank", 
    "Login", 
    "PayPal"
]

# Minimum EXTERNAL (non-localhost) ESTABLISHED TCP connections = active session.
# Idle: 1 connection to relay. Active: 2+ (relay + peer). Exclude 127.0.0.1.
MIN_EXTERNAL_ESTABLISHED_FOR_ACTIVE = 2



def _is_external_established(c):
    """True if connection is ESTABLISHED and remote is not localhost."""
    if c.status != 'ESTABLISHED' or not c.raddr:
        return False
    return c.raddr.ip not in ('127.0.0.1', '::1')


def is_remote_tool_running():
    """
    Checks if any process in the REMOTE_TOOLS list has an active remote session.
    Counts only EXTERNAL ESTABLISHED connections (excludes localhost).
    Idle: 1 external (relay). Active: 2+ external.
    """
    for proc in psutil.process_iter(['name']):
        try:
            proc_name = proc.info.get('name') or ""
            proc_lower = proc_name.lower()
            if proc_lower not in REMOTE_TOOLS_LOWER:
                continue
            # Process-only detection (e.g. Notepad for testing): no TCP check needed
            if proc_lower in PROCESS_ONLY_DETECT:
                return True, proc_name
            try:
                conns = proc.net_connections(kind='tcp')
                external_count = sum(1 for c in conns if _is_external_established(c))
                if external_count >= MIN_EXTERNAL_ESTABLISHED_FOR_ACTIVE:
                    return True, proc_name
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass  # Treat as idle, continue to next process
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False, None


def debug_list_processes():
    """Print all running processes - use to verify Notepad's actual name on your system."""
    logging.info("Running processes (looking for Notepad or similar):")
    logging.info("-" * 50)
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            name = proc.info.get('name') or "?"
            exe = proc.info.get('exe') or ""
            # Show anything with 'note' or 'notepad' or '记事本' in name/path
            if "note" in name.lower() or "note" in exe.lower() or "记事本" in exe:
                logging.info(f"  {name!r}  (exe: {exe})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    logging.info("-" * 50)
    logging.info("Run this with Notepad OPEN to see its process name.")


def get_active_window_title():
    """
    Retrieves the title of the currently active (foreground) window.
    Returns: str - Title of the window, or empty string on error.
    """
    try:
        window_handle = win32gui.GetForegroundWindow()
        title = win32gui.GetWindowText(window_handle)
        return title
    except Exception:
        return ""



def main():
    logging.info("Starting Guardian Watchdog...")
    logging.info(f"Toast notifications initialized.")
    logging.info(f"Monitoring for processes: {REMOTE_TOOLS}")
    logging.info(f"Blocking keywords: {SENSITIVE_KEYWORDS}")
    logging.info("-" * 30)

    stop_event = threading.Event()
    try:
        watchdog_loop(stop_event)
    except KeyboardInterrupt:
        logging.info("Stopping Guardian Watchdog.")
        stop_event.set()


def watchdog_loop(stop_event: threading.Event):
    last_time = time.time()
    last_alert_key = None

    while not stop_event.is_set():
        try:
            now = time.time()
            # logging.debug(f"Loop interval since last: {now - last_time:.2f}s")
            last_time = now
            # Step 1: Check for Remote Tool
            is_running, tool_name = is_remote_tool_running()

            if is_running:
                # Step 2: Remote Tool Detected - Check Active Window
                active_title = get_active_window_title()

                # Check for sensitive keywords (case-insensitive)
                is_sensitive = any(
                    keyword.lower() in active_title.lower()
                    for keyword in SENSITIVE_KEYWORDS
                )

                if is_sensitive:
                    alert_key = (tool_name, active_title)

                    # Step 3: Danger - Sensitive Window Open
                    if alert_key != last_alert_key:
                        logging.warning(
                            f"!!! DANGER !!! Remote Tool '{tool_name}' active while visiting sensitive site: '{active_title}'"
                        )
                        kill_sensitive_window()
                        # Windows notification to inform user calmly
                        time.sleep(1)
                        force_alert_popup(
                            "Guardian Watchdog Alert",
                            f"Remote tool '{tool_name}' detected. Sensitive window minimized for safety.",
                        )
                        last_alert_key = alert_key
                    else:
                        kill_sensitive_window()
                        logging.info(
                            f"Alert already sent for '{active_title}' while '{tool_name}' is active. Waiting for window/tool change."
                        )
                else:
                    # Remote tool is running, but window is safe
                    logging.info(
                        f"Warning: Remote Tool '{tool_name}' active. Current Window: '{active_title}'"
                    )
                    last_alert_key = None
            else:
                # Step 4: System Safe
                # logging.debug("System Safe (No remote tools detected)")
                last_alert_key = None

        except Exception as e:
            # Keep running even after transient errors
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)

        # Sleep to reduce CPU usage (interruptible)
        stop_event.wait(2)



def kill_sensitive_window():
    try:
        hwnd = win32gui.GetForegroundWindow()
        if hwnd:
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
            logging.info("[KILL SWITCH] Sensitive window minimized.")
            switch_to_desktop()
        else:
            logging.warning("[KILL SWITCH ERROR] No active window to minimize.")
    except Exception as e:
        logging.error(f"[KILL SWITCH ERROR] Could not minimize/close window: {e}")


def switch_to_desktop():
    try:
        import win32com.client
        shell = win32com.client.Dispatch("Shell.Application")
        shell.ToggleDesktop()
        logging.info("[SAFE SWITCH] Switched focus to desktop.")
    except Exception as e:
        logging.error(f"[SAFE SWITCH ERROR] Could not switch to desktop: {e}")

class GuardianService(win32serviceutil.ServiceFramework):
    _svc_name_ = "GuardianWatchdog"
    _svc_display_name_ = "Guardian Watchdog"
    _svc_description_ = "Monitors for remote tooling activity and minimizes sensitive windows."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = threading.Event()

    def SvcStop(self):
        self.stop_event.set()
        self.ReportServiceStopped()

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("Guardian Watchdog service starting.")
        try:
            watchdog_loop(self.stop_event)
        except Exception as e:
            servicemanager.LogErrorMsg(f"Guardian Watchdog service crashed: {e}")
        finally:
            servicemanager.LogInfoMsg("Guardian Watchdog service stopped.")


if __name__ == "__main__":
    # Windows Service integration (pywin32).
    # - Run interactively in a console: `python guardian_v0.py`
    # - Debug (list processes to find Notepad name): `python guardian_v0.py --debug`
    # - Install/start as a service (starts on boot):
    #     `python guardian_v0.py --startup auto install`
    #     `python guardian_v0.py start`
    # Note: Guardian interacts with the active desktop session; for some environments you may
    # need `--interactive` when installing the service.
    #
    # Restart-on-failure (recommended):
    #   `sc failure GuardianWatchdog reset= 86400 actions= restart/5000`
    if len(sys.argv) > 1 and sys.argv[1] == "--debug":
        debug_list_processes()
    elif len(sys.argv) > 1:
        win32serviceutil.HandleCommandLine(GuardianService)
    else:
        main()
