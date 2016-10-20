--<<<<<<<<<<<<<SSH attack detection>>>>>>>>>>>>>>
--Step 1: Identify SSH attacker
select
    srcip
from (
select
    a.srcip,
    count(distinct(a.dstip)) as dst_num
from (
select 
    f.srcip,
    f.dstip,
    sum(f.flowcount) as flowcount
from flow_summary_h f
--join threat_feeds t
--on f.srcip = t.ip_address
where f.conn_dir = 1
    and customer_id = 3 -- Workday id
    and issrcpublic = True and isdstpublic = False
    and f.dstport = 22
    and f.proto = 6
    and f.ts >= 1476082800000
    and f.ts <= 1476169200000
    -- brute force usually need a large number of attempts, so ignore src->dst with low count
    -- and with high ratio
    -- exclude flows for port scanning
    and f.flowcount >= 20
    and f.bytes_vol / f.pkt_vol > 80 
    and not f.bytes_vol % f.pkt_vol = 0
group by
    f.srcip, f.dstip
) a
group by
    a.srcip
)
where dst_num >= 40
order by dst_num desc
;


-- examine raw flow log between ssh attacker 
-- to Workday host for SSH Attack research
-- Check the Dstips for a specified Srcip
select
    dstip 
    , count(*) as num_attacks
from (
select
    f_unixts_to_timestamp(ts,'ms') as ts,
    f_unixts_to_timestamp(ts_end,'ms') as ts_end,   
    ts as ts_unix,
    ts_end as ts_end_unix,
    ts_end - ts as ts_delta,
    f_friendly_ip(srcip) as srcip_str,
    srcport,
    f.srcip, f.conn_dir, f.dstip,
    bytes_vol / pkt_vol as ratio,
    bytes_vol as bpf,
    pkt_vol as ppf,
    bytes_vol - pkt_vol * 40 as dpf
from raw_flow_logs f
where f.conn_dir = 1
    and f.customer_id = 3 -- workday id
    and f.bytes_vol / f.pkt_vol > 80
    and f.srcip = -574476336      -- potential ssh attacker ip
--  and f.srcip = 782629787       -- potential legitimate ip
    and f.issrcpublic = true
    and f.isdstpublic = false
--  and f.srcip = 1541447811
    and f.dstport = 22
    and f.ts >= 1476082800000       
    and f.ts <= 1476169200000       
--  and f.dstip = -1062729170
)
group by
    dstip
;


-- examine raw flow log between ssh attacker 
-- to Workday host for SSH Attack research
-- Get the data for drawing the flow metrics for a {dstip, srcip} pair
select
    f_unixts_to_timestamp(ts,'ms') as ts,
    f_unixts_to_timestamp(ts_end,'ms') as ts_end,   
    ts as ts_unix,
    ts_end as ts_end_unix,
    ts_end - ts as ts_delta,
    f_friendly_ip(srcip) as srcip_str,
    f.srcip, f.dstip,
    bytes_vol / pkt_vol as ratio,
    bytes_vol as bpf,
    pkt_vol as ppf,
    bytes_vol - pkt_vol * 40 as dpf
from (
select
    min(a.ts) as ts,
    max(a.ts_end) as ts_end,
    a.srcip,
    a.srcport,
    a.dstip,
    sum(a.bytes_vol) as bytes_vol,
    sum(a.pkt_vol) as pkt_vol
from raw_flow_logs a
where a.conn_dir = 0
    and a.customer_id = 3 -- workday id
    and a.srcip = 2111109205     -- potential ssh attacker ip
--  and f.srcip = 782629787         -- potential legitimate ip
    and a.issrcpublic = true
    and a.isdstpublic = false
    and a.dstport = 22
    and a.ts >= 1476082800000       
    and a.ts <= 1476169200000       
    and a.dstip = 182212684
group by
    a.srcip,
    a.srcport,
    a.dstip
) f
order by ts_unix asc
;




--Step 2: monitor the track
-- raw flow data of SSH traffic from public to private Workday of a day
select 
    ts,
    ts_end,
    (ts_end - ts) as ts_delta,
    srcip,
    srcport,
    dstip,
    conn_dir,
    bytes_vol,
    pkt_vol
from raw_flow_logs f
where (conn_dir =1 or conn_dir = 0)
    and f.customer_id = 3 -- workday id
    and f.issrcpublic = true
    and f.isdstpublic = false
    and f.dstport = 22
    and f.ts >= 1476082800000
    and f.ts <= 1476169200000
order by ts asc
;

-- grouping across a whole day is not good ==> introducing too many noisy positive spikes.
select
    ts,
    ts_end,
    (ts_end - ts) as ts_delta,
    srcip,
    srcport,
    dstip,
    conn_dir,
    bytes_vol / pkt_vol as ratio,
    bytes_vol as bpf,
    pkt_vol as ppf,
    bytes_vol - pkt_vol * 40 as dpf
from (
select
    min(a.ts) as ts,
    max(a.ts_end) as ts_end,
    a.srcip,
    a.srcport,
    a.dstip,
    a.conn_dir,
    sum(a.bytes_vol) as bytes_vol,
    sum(a.pkt_vol) as pkt_vol
from raw_flow_logs a
where (conn_dir =1 or conn_dir = 0)
    and a.customer_id = 3 -- workday id
    and a.issrcpublic = true
    and a.isdstpublic = false
    and a.dstport = 22
    and a.ts >= 1476082800000
    and a.ts <= 1476169200000
group by
    a.srcip,
    a.srcport,
    a.dstip,
    a.conn_dir
) f
;
