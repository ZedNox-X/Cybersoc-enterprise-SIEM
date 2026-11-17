# Architecture

CSV security events -> schema validation and normalization -> detection engine (AUTH-001 / NET-001 / VOL-001) -> alert queue and triage guidance -> Streamlit dashboard and CSV exports.

Future production extensions: durable event storage, scheduled ingestion, threat intelligence enrichment, role-based access control, audit trails, alert acknowledgement and notification integrations.
