import pandas as pd
from src.siem import analyze_dataframe, normalize_dataframe

def test_failed_auth_detection():
    df = pd.DataFrame({
        "timestamp": pd.date_range("2026-11-01", periods=5, freq="min", tz="UTC"),
        "source_ip": ["198.51.100.20"]*5, "event_type": ["login"]*5,
        "status": ["failed"]*5, "destination_port": [22]*5
    })
    assert "AUTH-001" in analyze_dataframe(df)["rule_id"].tolist()

def test_port_scan_detection():
    df = pd.DataFrame({
        "timestamp": pd.date_range("2026-11-01", periods=12, freq="min", tz="UTC"),
        "source_ip": ["203.0.113.9"]*12, "event_type": ["port_scan"]*12,
        "status": ["blocked"]*12, "destination_port": list(range(20,32))
    })
    assert "NET-001" in analyze_dataframe(df)["rule_id"].tolist()

def test_rejects_missing_schema():
    try:
        normalize_dataframe(pd.DataFrame({"source_ip":["1.2.3.4"]}))
        assert False
    except ValueError as exc:
        assert "Missing required columns" in str(exc)
