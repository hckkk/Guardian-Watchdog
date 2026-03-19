# diagnostic_tv_connections.py - Run this with TeamViewer IDLE and again with an ACTIVE session
import psutil

PROC_NAMES = ["TeamViewer.exe", "TeamViewer_Service.exe"]

for proc in psutil.process_iter(['name', 'pid']):
    try:
        if proc.info['name'] not in PROC_NAMES:
            continue
        conns = proc.net_connections(kind='tcp')
        established = [c for c in conns if c.status == 'ESTABLISHED']
        print(f"\n{proc.info['name']} (PID {proc.info['pid']}):")
        print(f"  ESTABLISHED count: {len(established)}")
        for c in established:
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "?"
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
            print(f"    {laddr} -> {raddr}")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass