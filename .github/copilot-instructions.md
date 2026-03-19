# Copilot Instructions

## Project Overview
This is a security watchdog that monitors for remote access tools running on Windows. It uses `psutil` to scan running processes and alerts when remote tools are detected.

## Architecture
- **Single-file design**: [core.py](../core.py) contains the entire application logic
- **Continuous monitoring loop**: Checks every 2 seconds via `time.sleep(2)`
- **Process detection**: Uses `psutil.process_iter(['name'])` to enumerate running processes

## Key Patterns

### Remote Tool Detection
The `REMOTE_TOOLS` list in [core.py](../core.py) defines monitored processes:
```python
REMOTE_TOOLS = ["TeamViewer.exe", "SunloginClient.exe", "AnyDesk.exe", "Notepad.exe"]
```
- Process names must match exactly (case-sensitive on Linux/macOS)
- "Notepad.exe" is included for testing without installing remote tools
- Add new tools by appending to this list

### Error Handling
Always wrap `proc.info['name']` access in try-except for these specific exceptions:
```python
except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
    pass
```
This handles processes that terminate mid-iteration or lack permissions.

## Dependencies
- **psutil**: Core dependency for process enumeration - handles cross-platform process access
- **venv**: Virtual environment exists at project root (don't commit `venv/`)

## Running the Application
```bash
# Activate virtual environment first
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# Run the watchdog
python core.py
```

## Development Conventions
- Output uses emoji prefixes: `⚠️` for alerts, `✅` for safe status
- Sleep interval (2 seconds) is a balance between responsiveness and CPU usage - document any changes
- Function returns tuple `(bool, str|None)` - presence flag and process name

## Testing Approach
- Open Notepad.exe to trigger alerts without installing remote tools
- Test should verify both detection (True) and no-detection (False) paths
- Mock `psutil.process_iter()` for unit tests to avoid dependency on actual processes
