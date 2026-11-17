from pathlib import Path
import pandas as pd

REQUIRED = {"timestamp", "source_ip", "event_type", "status"}
SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "samples" / "sample_security_events.csv"

def normalize_dataframe(df):
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")
    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out["source_ip"] = out["source_ip"].astype("string").fillna("unknown")
    out["event_type"] = out["event_type"].astype("string").str.lower().fillna("unknown")
    out["status"] = out["status"].astype("string").str.lower().fillna("unknown")
    if "destination_port" in out.columns:
        out["destination_port"] = pd.to_numeric(out["destination_port"], errors="coerce")
    return out.dropna(subset=["timestamp"])

def load_sample():
    return normalize_dataframe(pd.read_csv(SAMPLE_PATH))

def analyze_dataframe(df, failed_threshold=5, scan_threshold=10, window_minutes=10):
    data = normalize_dataframe(df)
    findings = []
    failed = data[data.event_type.isin(["login","authentication","auth"]) &
                   data.status.isin(["failed","failure","denied","invalid"])]
    for ip, group in failed.groupby("source_ip"):
        times = group.sort_values("timestamp").timestamp.tolist()
        left = max_count = 0
        for right, current in enumerate(times):
            while current - times[left] > pd.Timedelta(minutes=window_minutes):
                left += 1
            max_count = max(max_count, right-left+1)
        if max_count >= failed_threshold:
            findings.append({
                "timestamp": group.timestamp.max(), "source_ip": ip, "rule_id": "AUTH-001",
                "alert": "Repeated failed authentication", "count": max_count,
                "severity": "High" if max_count >= failed_threshold*2 else "Medium",
                "recommended_action": "Validate account activity; review MFA and identity-provider logs."
            })
    if "destination_port" in data.columns:
        scans = data[data.event_type.isin(["connection_attempt","port_scan","network_connection"])]
        for ip, group in scans.groupby("source_ip"):
            ports = int(group.destination_port.nunique())
            if ports >= scan_threshold:
                findings.append({
                    "timestamp": group.timestamp.max(), "source_ip": ip, "rule_id": "NET-001",
                    "alert": "Possible port scanning", "count": ports,
                    "severity": "High" if ports >= scan_threshold*2 else "Medium",
                    "recommended_action": "Review firewall/flow records and confirm whether scanning was authorized."
                })
    for ip, group in data.groupby("source_ip"):
        if len(group) >= 100:
            findings.append({
                "timestamp": group.timestamp.max(), "source_ip": ip, "rule_id": "VOL-001",
                "alert": "High event volume from one source", "count": len(group),
                "severity": "Medium",
                "recommended_action": "Compare with baseline and inspect event distribution."
            })
    cols = ["timestamp","source_ip","rule_id","alert","count","severity","recommended_action"]
    return pd.DataFrame(findings, columns=cols).sort_values(["severity","count"], ascending=[True,False], ignore_index=True)

def analyze_csv_in_chunks(file_obj, failed_threshold=5, scan_threshold=10, window_minutes=10, chunksize=100_000):
    chunks = [normalize_dataframe(c) for c in pd.read_csv(file_obj, chunksize=chunksize)]
    if not chunks:
        raise ValueError("The uploaded CSV is empty.")
    data = pd.concat(chunks, ignore_index=True)
    return data, analyze_dataframe(data, failed_threshold, scan_threshold, window_minutes)
