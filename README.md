# Office LAN Network Monitor — Cisco 2911

Minimal stack: goflow2 (NetFlow collector) + Vector (syslog + log shipping) + ClickHouse (storage) + Grafana (dashboards).

## 1. Router-side config (Cisco 2911, IOS)

Apply the NetFlow and syslog config from the earlier message, pointing at this
monitoring box's IP. Replace `10.0.0.50` with your actual box IP in both the
`flow exporter` and `logging host` lines.

## 2. Bring up the stack

```bash
cd office-netmon
docker compose up -d
```

Check everything started:

```bash
docker compose ps
docker compose logs -f goflow2   # confirm it's receiving flow packets
docker compose logs -f vector    # confirm syslog/flow ingestion into ClickHouse
```

## 3. Verify data is landing in ClickHouse

```bash
docker exec -it netmon-clickhouse clickhouse-client

-- inside the client:
SELECT count() FROM netmon.syslog;
SELECT count() FROM netmon.flows;
SELECT * FROM netmon.flows ORDER BY ts DESC LIMIT 10;
```

**Important:** goflow2's JSON field names can vary slightly by version
(e.g. `SrcAddr` vs `src_addr` vs nested under a different key). Once you have
real flow data landing, run:

```bash
docker exec -it netmon-goflow2 tail -n 5 /data/flows.log
```

and confirm the field names in `vector/vector.toml`'s `flow_parse` transform
actually match what goflow2 is emitting — adjust the `parsed.FieldName`
references if they don't line up. I've used the field names from goflow2's
common JSON output format, but I haven't been able to test against a live
Cisco 2911 flow export, so treat this as a starting point to verify rather
than a guaranteed-correct mapping.

## 4. Connect Grafana to ClickHouse

1. Open `http://<box-ip>:3000` (default login: admin/admin, change immediately)
2. Add data source → ClickHouse plugin (auto-installed via compose env var)
3. Server: `clickhouse`, Port: `8123`, Database: `netmon`

## 5. Starter queries for dashboards

**Top talkers (last hour):**
```sql
SELECT src_addr, dst_addr, sum(bytes) AS total_bytes
FROM netmon.flows
WHERE ts > now() - INTERVAL 1 HOUR
GROUP BY src_addr, dst_addr
ORDER BY total_bytes DESC
LIMIT 20
```

**Bandwidth over time by source host:**
```sql
SELECT toStartOfMinute(ts) AS minute, src_addr, sum(bytes) AS bytes
FROM netmon.flows
WHERE ts > now() - INTERVAL 6 HOUR
GROUP BY minute, src_addr
ORDER BY minute
```

**Firewall denies / syslog errors (last 24h):**
```sql
SELECT ts, host, severity, message
FROM netmon.syslog
WHERE severity IN ('err', 'warning', 'crit')
  AND ts > now() - INTERVAL 1 DAY
ORDER BY ts DESC
```

**Possible port scan detection (one source hitting many distinct destination
ports in a short window):**
```sql
SELECT src_addr, count(DISTINCT dst_port) AS distinct_ports, count() AS flow_count
FROM netmon.flows
WHERE ts > now() - INTERVAL 5 MINUTE
GROUP BY src_addr
HAVING distinct_ports > 20
ORDER BY distinct_ports DESC
```

## 6. Next steps once this is stable

- Add DNS query logging (source depends on what resolves DNS in your office —
  let me know and I'll add the config)
- Add a threat-intel IP list (e.g. Feodo Tracker) as a ClickHouse dictionary,
  join against `flows.dst_addr` to flag known-bad destinations
- Add Grafana alert rules on top of the queries above (bandwidth threshold,
  port-scan query, syslog error rate)
- Consider Suricata on a mirrored switch port if you want signature-based IDS
  in addition to flow-level visibility
