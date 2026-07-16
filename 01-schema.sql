CREATE DATABASE IF NOT EXISTS netmon;

-- NetFlow records from goflow2 (fields match FNF record config on the 2911)
CREATE TABLE IF NOT EXISTS netmon.flows
(
    ts              DateTime DEFAULT now(),
    src_addr        String,
    dst_addr        String,
    src_port        UInt16,
    dst_port        UInt16,
    proto           UInt8,
    in_if           UInt32,
    out_if          UInt32,
    bytes           UInt64,
    packets         UInt64,
    sampler_address String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, src_addr, dst_addr)
TTL ts + INTERVAL 30 DAY;   -- adjust retention as needed; flow volume grows fast

-- Syslog events from the Cisco 2911 (and anything else pointed at Vector's syslog listener)
CREATE TABLE IF NOT EXISTS netmon.syslog
(
    ts        DateTime DEFAULT now(),
    host      String,
    severity  String,
    facility  String,
    message   String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, host)
TTL ts + INTERVAL 90 DAY;   -- syslog is much lighter volume, keep longer for audit purposes
