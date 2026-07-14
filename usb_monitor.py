

import os, time, datetime, json, csv, hashlib, subprocess

# ── SETTINGS ─────────────────────────────────────────────
SCAN_INTERVAL  = 5
MAX_SCANS      = 10
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
LOG_FILE       = os.path.join(SCRIPT_DIR, "usb_events.log")
REPORT_FILE    = os.path.join(SCRIPT_DIR, "usb_report.csv")
WHITELIST_FILE = os.path.join(SCRIPT_DIR, "usb_whitelist.json")
BASELINE_FILE  = os.path.join(SCRIPT_DIR, "usb_baseline.json")

# ── HELPERS ──────────────────────────────────────────────
def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(message, level="INFO"):
    entry = f"[{get_timestamp()}] [{level:5}]  {message}"
    print(entry)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")

def print_banner():
    print()
    print("=" * 60)
    print("   USB Device Control & Monitoring Framework  v1.0")
    print("=" * 60)
    print()

# ── USB DETECTION ────────────────────────────────────────
def parse_wmic_logical_drives(output):
    drives = {}
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return drives

    try:
        rows = list(csv.reader(lines))
    except csv.Error:
        return drives

    if len(rows) < 2:
        return drives

    header = [col.strip().lower() for col in rows[0]]
    for row in rows[1:]:
        if not row:
            continue

        values = {}
        for index, key in enumerate(header):
            if index < len(row):
                values[key] = row[index].strip()

        device_id = values.get("deviceid") or values.get("caption") or ""
        if not device_id:
            continue

        drive = device_id if device_id.endswith(":") else f"{device_id}:"
        label = values.get("volumename") or values.get("volume name") or values.get("caption") or "No Label"
        serial = values.get("volumeserialnumber") or values.get("serialnumber") or "UNKNOWN"
        size_raw = values.get("size") or "0"
        free_raw = values.get("freespace") or "0"

        try:
            size = int(size_raw)
            free = int(free_raw)
        except (TypeError, ValueError):
            continue

        if size <= 0:
            continue

        drives[drive] = {
            "drive": drive,
            "label": label or "No Label",
            "serial": serial or "UNKNOWN",
            "size_gb": round(size / (1024**3), 2),
            "free_gb": round(free / (1024**3), 2),
        }

    return drives


def get_drive_info(letter):
    try:
        result = subprocess.run(
            ["wmic", "logicaldisk", "where", f"DeviceID='{letter}:'",
             "get", "DeviceID,VolumeName,VolumeSerialNumber,Size,FreeSpace", "/format:csv"],
            capture_output=True, text=True, timeout=5)
        drives = parse_wmic_logical_drives(result.stdout)
        if drives:
            return next(iter(drives.values()))
    except Exception:
        pass
    return None


def get_connected_usb_drives():
    try:
        result = subprocess.run(
            ["wmic", "logicaldisk", "where", "DriveType=2",
             "get", "DeviceID,VolumeName,VolumeSerialNumber,Size,FreeSpace", "/format:csv"],
            capture_output=True, text=True, timeout=7)
        return parse_wmic_logical_drives(result.stdout)
    except Exception:
        return {}

# ── WHITELIST ────────────────────────────────────────────
def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            data = json.load(f)
        trusted = data.get("trusted", [])
        log(f"Whitelist loaded — {len(trusted)} trusted device(s)")
        return trusted
    log("No whitelist found — all USBs will be flagged as UNKNOWN", "WARN")
    return []

def save_whitelist(trusted_list):
    with open(WHITELIST_FILE, "w") as f:
        json.dump({"trusted": trusted_list}, f, indent=2)
    log(f"Whitelist saved — {len(trusted_list)} trusted device(s)")

def is_trusted(serial, whitelist):
    return serial in whitelist

def add_to_whitelist(serial, label):
    whitelist = load_whitelist()
    if serial not in whitelist:
        whitelist.append(serial)
        save_whitelist(whitelist)
        log(f"Added to whitelist: {label} (Serial: {serial})", "OK")
    else:
        log(f"Already in whitelist: {label}", "INFO")
    return whitelist

# ── BASELINE ─────────────────────────────────────────────
def create_baseline():
    drives = get_connected_usb_drives()
    with open(BASELINE_FILE, "w") as f:
        json.dump(drives, f, indent=2)
    log(f"Baseline created — {len(drives)} drive(s) saved to {BASELINE_FILE}", "OK")
    return drives

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        log("No baseline found — creating one now...", "WARN")
        return create_baseline()
    with open(BASELINE_FILE, "r") as f:
        data = json.load(f)
    log(f"Baseline loaded — {len(data)} drive(s) in baseline")
    return data

def get_baseline_checksum():
    if not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# ── CHANGE DETECTION ─────────────────────────────────────
def detect_changes(old, new, whitelist):
    events = []
    for drive, info in new.items():
        if drive not in old:
            trusted = is_trusted(info["serial"], whitelist)
            events.append({"timestamp": get_timestamp(), "event_type": "CONNECTED",
                           "drive": drive, "label": info["label"],
                           "serial": info["serial"], "size_gb": info["size_gb"],
                           "trusted": "Yes" if trusted else "No",
                           "alert": "" if trusted else "UNKNOWN USB — Not in whitelist!"})
            if trusted:
                log(f"USB CONNECTED (Trusted): {drive} — {info['label']} "
                    f"[{info['size_gb']} GB] Serial: {info['serial']}", "OK")
            else:
                log(f"USB CONNECTED (UNKNOWN!): {drive} — {info['label']} "
                    f"[{info['size_gb']} GB] Serial: {info['serial']}", "ALERT")
                log(f"  --> This USB is NOT in your trusted whitelist!", "ALERT")
    for drive, info in old.items():
        if drive not in new:
            events.append({"timestamp": get_timestamp(), "event_type": "DISCONNECTED",
                           "drive": drive, "label": info["label"],
                           "serial": info["serial"], "size_gb": info["size_gb"],
                           "trusted": "Yes" if is_trusted(info["serial"], whitelist) else "No",
                           "alert": ""})
            log(f"USB DISCONNECTED: {drive} — {info['label']} Serial: {info['serial']}", "WARN")
    return events

# ── REPORTING ────────────────────────────────────────────
def save_to_csv(event):
    fields = ["timestamp","event_type","drive","label","serial","size_gb","trusted","alert"]
    file_exists = os.path.exists(REPORT_FILE)
    with open(REPORT_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if not file_exists:
            writer.writeheader()
        writer.writerow(event)

def print_summary(all_events):
    print("\n" + "=" * 60)
    log("FINAL SUMMARY", "INFO")
    print("=" * 60)
    connected    = [e for e in all_events if e["event_type"] == "CONNECTED"]
    disconnected = [e for e in all_events if e["event_type"] == "DISCONNECTED"]
    unknown      = [e for e in all_events if e["trusted"] == "No" and e["event_type"] == "CONNECTED"]
    log(f"Total events:         {len(all_events)}")
    log(f"Devices connected:    {len(connected)}")
    log(f"Devices disconnected: {len(disconnected)}")
    log(f"Unknown USB devices:  {len(unknown)}", "ALERT" if unknown else "INFO")
    if unknown:
        log("UNKNOWN DEVICES FOUND:", "ALERT")
        for e in unknown:
            log(f"  Drive:{e['drive']}  Label:{e['label']}  Serial:{e['serial']}", "ALERT")
    log(f"Report saved to: {REPORT_FILE}")
    log(f"Log saved to:    {LOG_FILE}")
    print("=" * 60)

# ── CONTINUOUS MONITOR ───────────────────────────────────
def continuous_monitor(whitelist, scans=MAX_SCANS, interval=SCAN_INTERVAL):
    label = "forever" if scans == 0 else str(scans)
    log(f"Monitoring started — interval={interval}s — scans={label}")
    print("-" * 60)
    print("  Plug in or remove a USB drive to test!")
    print("  Press Ctrl+C to stop at any time.")
    print("-" * 60)
    all_events = []; previous = get_connected_usb_drives(); count = 0
    try:
        while True:
            count += 1
            log(f"--- Scan #{count} ---")
            current = get_connected_usb_drives()
            events  = detect_changes(previous, current, whitelist)
            if not events:
                log("No USB changes in this scan.")
            for e in events:
                save_to_csv(e)
            all_events.extend(events)
            previous = current
            if scans and count >= scans:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        log("Monitoring stopped by user (Ctrl+C).", "WARN")
    print_summary(all_events)
    return all_events

# ── MAIN MENU ────────────────────────────────────────────
def main():
    print_banner()
    whitelist = load_whitelist()
    while True:
        print()
        print("  ┌─ MENU ──────────────────────────────────────────────┐")
        print("  │  1. List currently connected USB drives             │")
        print("  │  2. Create Baseline snapshot                        │")
        print("  │  3. Start continuous USB monitoring                 │")
        print("  │  4. Add a USB drive to whitelist (trust it)         │")
        print("  │  5. View whitelist (trusted devices)                │")
        print("  │  6. Show baseline checksum (SHA-256)                │")
        print("  │  7. One-time scan vs baseline                       │")
        print("  │  0. Exit                                            │")
        print("  └─────────────────────────────────────────────────────┘")
        print()
        choice = input("  Enter choice (0-7): ").strip()

        if choice == "1":
            print("-" * 60)
            drives = get_connected_usb_drives()
            if not drives:
                log("No external drives found right now.")
            else:
                log(f"Found {len(drives)} drive(s):")
                for drive, info in drives.items():
                    status = "TRUSTED" if is_trusted(info["serial"], whitelist) else "UNKNOWN"
                    level  = "OK" if status == "TRUSTED" else "ALERT"
                    log(f"  {drive}  {info['label']:15}  {info['size_gb']:6.2f} GB  "
                        f"Serial: {info['serial']:10}  [{status}]", level)
        elif choice == "2":
            print("-" * 60); create_baseline()
        elif choice == "3":
            print("-" * 60)
            try:
                scans    = int(input("  Scans? (0=forever, recommended: 10): ").strip() or "10")
                interval = int(input(f"  Seconds between scans? (press Enter for {SCAN_INTERVAL}s): ").strip() or SCAN_INTERVAL)
            except ValueError:
                scans, interval = 10, SCAN_INTERVAL
            whitelist = load_whitelist()
            continuous_monitor(whitelist, scans, interval)
        elif choice == "4":
            print("-" * 60)
            drives = get_connected_usb_drives()
            if not drives:
                log("No USB drives connected. Plug one in first.", "WARN")
            else:
                items = list(drives.items())
                log("Connected drives:")
                for i, (d, info) in enumerate(items):
                    print(f"  {i+1}. {d} — {info['label']} (Serial: {info['serial']})")
                try:
                    pick = int(input("  Which drive to trust? Enter number: ").strip()) - 1
                    if 0 <= pick < len(items):
                        _, info = items[pick]
                        whitelist = add_to_whitelist(info["serial"], info["label"])
                    else:
                        log("Invalid choice.", "WARN")
                except ValueError:
                    log("Invalid input.", "WARN")
        elif choice == "5":
            print("-" * 60)
            if whitelist:
                log(f"Trusted devices ({len(whitelist)}):")
                for i, serial in enumerate(whitelist, 1):
                    print(f"  {i}. Serial: {serial}")
            else:
                log("No trusted devices yet. Use option 4 to add one.", "WARN")
        elif choice == "6":
            print("-" * 60)
            chk = get_baseline_checksum()
            if chk:
                log("Baseline SHA-256:"); log(f"  {chk}")
            else:
                log("No baseline file. Run option 2 first.", "WARN")
        elif choice == "7":
            print("-" * 60)
            baseline = load_baseline(); current = get_connected_usb_drives()
            events   = detect_changes(baseline, current, whitelist)
            if not events:
                log("No changes vs baseline.", "OK")
            else:
                log(f"{len(events)} change(s) detected vs baseline:", "WARN")
                for e in events: save_to_csv(e)
        elif choice == "0":
            log("Exiting. Goodbye!"); break
        else:
            print("  Invalid choice. Please enter 0 to 7.")

if __name__ == "__main__":
    main()
