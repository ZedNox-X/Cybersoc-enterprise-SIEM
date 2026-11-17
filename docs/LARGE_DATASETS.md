# Large dataset guidance

The uploader parses CSV in 100,000-row chunks to reduce peak parsing memory. The prototype then concatenates chunks for dashboard summaries and correlation, so total memory can still be several times the CSV file size.

For files around 200 MB or larger:
- Prefer local execution on a machine with adequate RAM.
- Split data into time-based files and analyze one period at a time.
- Consider Parquet plus DuckDB for efficient local analytics.
- For production, persist events to a database or queue and query aggregates instead of keeping all records in Streamlit memory.
- Hosting platforms enforce upload, memory, CPU and runtime limits; verify current limits before deployment.

Do not increase upload limits without planning memory requirements.
