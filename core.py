import psutil
import time

# List of process names we consider "Remote Tools"
# Note: TeamViewer usually runs as "TeamViewer.exe"
REMOTE_TOOLS = ["TeamViewer.exe", "SunloginClient.exe", "AnyDesk.exe", "Notepad.exe"] 
# I added "Notepad.exe" so you can test this right now without installing TeamViewer!

def is_remote_tool_running():
    # Iterate over all running processes
    for proc in psutil.process_iter(['name']):
        try:
            # Check if process name is in our blacklist
            if proc.info['name'] in REMOTE_TOOLS:
                return True, proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False, None

print("Starting Watchdog...")
while True:
    running, name = is_remote_tool_running()
    if running:
        print(f"⚠️  ALERT: Remote Tool Detected: {name}")
    else:
        print("✅  System Safe")
    
    time.sleep(2) # Check every 2 seconds to save CPU