import argparse
import ctypes
import psutil
import time
import re
import sys
import win32evtlogutil
import win32evtlog
import win32ts
import winreg
from dissect import cstruct

# ---------------- Global Config ----------------

__author__ = "Brian Maloney"
__version__ = "2025.11.19"
__email__ = "bmmaloney97@gmail.com"

cparser = cstruct.cstruct()
log_name = "ConsentMonitor"
source_name = "ConsentMonitorSource"

WRITE_TO_CONSOLE = False

blob = '''

typedef struct _blob_buf{
    uint32 buf_size;
    char data[buf_size-4];
} blob_buf;

'''

cparser.load(blob)

# ---------------- Utility Functions ----------------


def get_sessions():
    sessions = win32ts.WTSEnumerateSessions()
    sess_info = ""
    for session in sessions:
        sid = session['SessionId']
        user = win32ts.WTSQuerySessionInformation(None, sid, win32ts.WTSUserName)
        domain = win32ts.WTSQuerySessionInformation(None, sid, win32ts.WTSDomainName)

        # Skip empty sessions
        if not user and not domain:
            continue

        # Format properly, avoid a dangling backslash
        if domain:
            sess_info += f"{sid} {domain}\\{user}\r\n"
        else:
            sess_info += f"{sid} {user}\r\n"
    return sess_info

def get_process_user(pid):
    try:
        return psutil.Process(pid).username()
    except Exception:
        return "Unknown"

# ------- Event log register -------

def event_source_exists(log_name, source_name):
    key_path = fr"SYSTEM\CurrentControlSet\Services\EventLog\{log_name}\{source_name}"

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False

# ------- Event log writer ---------

def write_event(message, event_id=1000, level="info"):
    if WRITE_TO_CONSOLE:
        # Console output mode
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level.upper()}] ({event_id}) {message}")
        return

    if level == "info":
        evt_type = win32evtlog.EVENTLOG_INFORMATION_TYPE
    elif level == "warning":
        evt_type = win32evtlog.EVENTLOG_WARNING_TYPE
    else:
        evt_type = win32evtlog.EVENTLOG_ERROR_TYPE

    try:
        win32evtlogutil.ReportEvent(
            source_name,
            eventID=event_id,
            eventCategory=1,
            eventType=evt_type,
            strings=[message]
        )
    except Exception as e:
        print("[!] Failed to write to event log:", e)

# ------- Memory reading ---------

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
ReadProcessMemory = kernel32.ReadProcessMemory
CloseHandle = kernel32.CloseHandle


def read_process_memory(pid, address, size):
    h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError(f"OpenProcess failed: {ctypes.get_last_error()}")
    try:
        buf = (ctypes.c_ubyte * size)()
        br = ctypes.c_size_t(0)
        if not ReadProcessMemory(h, ctypes.c_void_p(address),
                                 buf, size, ctypes.byref(br)):
            raise OSError(f"RPM failed: {ctypes.get_last_error()}")
        return bytes(buf[:br.value])
    finally:
        CloseHandle(h)


def parse_buf(buf):
    results = cparser.blob_buf(buf)
    output = cstruct.hexdump(buf, palette=[], output="string")
    return "\r\n".join(output.splitlines()) + "\r\n"
    #return cstruct.dumpstruct(results, color=False, output="string")


def decode_buffer(b):
    try:
        return b.decode("utf-16-le", errors="ignore")
    except Exception:
        return b.decode("utf-8", errors="ignore")

# ------- Monitor Loop ---------

def monitor():
    seen = set()
    print(f"ConsentMonitor v{__version__}")
    print("[*] Monitoring for consent.exe...")

    while True:
        try:
            for p in psutil.process_iter(["name", "cmdline", "pid"]):
                if p.info["name"] and p.info["name"].lower() == "consent.exe":
                    pid = p.info["pid"]
                    if pid in seen:
                        continue
                    seen.add(pid)

                    cmdline = " ".join(p.info["cmdline"])
                    user = get_process_user(pid)
                    session = get_sessions()

                    write_event(
                        f"---------- Active Sessions ----------\r\n"
                        f"{session}\r\n"
                        f"Detected consent.exe PID={pid}, User={user}, CMD={cmdline}",
                        event_id=5
                    )

                    # parse arguments
                    match = re.search(r"(\d+)\s+(\d+)\s+([0-9A-Fa-f]+)", cmdline)
                    if not match:
                        write_event(
                            "Could not parse consent.exe command line",
                            event_id=3,
                            level="error")
                        continue

                    parent_pid = int(match.group(1))
                    length = int(match.group(2))
                    pointer = int(match.group(3), 16)

                    try:
                        buf = read_process_memory(parent_pid, pointer, length)
                        text = decode_buffer(buf).replace("\x00", "")
                        decode = parse_buf(buf).replace("\033[1;0m", "")

                        write_event(
                            f"{decode}\r\n\r\nExtracted Buffer:\r\n{text}",
                            event_id=1
                        )

                    except Exception as e:
                        write_event(
                            f"Failed reading parent memory: {e}",
                            event_id=3,
                            level="error"
                        )

            time.sleep(0.2)

        except KeyboardInterrupt:
            print("\n[*] Monitor stopped.")
            return  # clean exit from the loop

        except Exception as e:
            # Catch unexpected errors w/o killing the entire monitor
            write_event(f"Monitor error: {e}", level="error", event_id=9999)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Consent Monitor")
        parser.add_argument(
            "--console", "-c",
            action="store_true",
            help="Write output to console instead of Windows Event Log"
        )
        args = parser.parse_args()

        WRITE_TO_CONSOLE = args.console

        if not WRITE_TO_CONSOLE:
            if not event_source_exists(log_name, source_name):
                win32evtlogutil.AddSourceToRegistry(
                    appName=source_name,
                    msgDLL=r"%SystemRoot%\System32\EventCreate.exe",      # default message file
                    eventLogType=log_name
                )
                print(f"Event log '{log_name}' and source '{source_name}' registered.")

        monitor()

    except KeyboardInterrupt:
        print("\n[*] Exiting cleanly...")
        sys.exit(0)
