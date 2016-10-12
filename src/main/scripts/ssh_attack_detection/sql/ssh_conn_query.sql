select * from flow_logs where conn_dir = 0 or conn_dir = 1 limit 10;
select
    srcip,
    dstip,
    srcport,
    dstport,
    proto,
    pkt,
    bytes,
    to_time,
    ts,
    conn_dir,
    (to_time - ts) as time_length 
from flow_logs where conn_dir = 0 or conn_dir = 1 limit 100;


-- examine flow log
select
    f.srcip,
    f.dstip,
    f.srcport,
    f.dstport,
    f.proto,
    f.pkt,
    f.bytes,
    f.to_time,
    f.ts,
    f.conn_dir,
    (f.to_time - f.ts) as time_length,
    f.observer_id,
    f.latest_rkl_ingestion_ts,
    (f.bytes / f.pkt) as ratio
from (
    select
        srcip,
        dstip,
        srcport,
        dstport,
        proto,
        pkt,
        bytes,
        to_time,
        ts,
        conn_dir,
        observer_id,
        max(rkl_ingestion_ts) as latest_rkl_ingestion_ts
    from flow_logs
    group by
        srcip,
        dstip,
        srcport,
        dstport,
        proto,
        pkt,
        bytes,
        to_time,
        ts,
        conn_dir,
        observer_id
) f
join threat_feeds t
on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 1)
    and f.src
--  and f.pkt <= 10
--  and (f.bytes / f.pkt) <= 80
--  and EXISTS(SELECT 1 FROM flow_logs fl WHERE f.dstip=fl.dstip and f.srcip=fl.srcip and f.srcport=fl.srcport and f.dstport=fl.dstport and f.proto=fl.proto and f.conn_dir=1-fl.conn_dir)
--limit 100
;



-- examine raw flow log between our office and RedLock AWS
-- All traffic should be legitimate flows, and we can use this to show all hosts in RedLock AWS
-- And also we can apply our rules to filter out low-ratio flows and see how many host we can detect.
select
    f.dstip,
    f.dstport
from (
    select
        srcip,
        dstip,
        srcport,
        dstport,
        proto,
        pkt,
        bytes,
        to_time,
        ts,
        conn_dir,
        observer_id,
        max(rkl_ingestion_ts) as latest_rkl_ingestion_ts
    from flow_logs
    group by
        srcip,
        dstip,
        srcport,
        dstport,
        proto,
        pkt,
        bytes,
        to_time,
        ts,
        conn_dir,
        observer_id
) f
where (f.conn_dir = 0 or f.conn_dir = 1)
    and f.srcip = 854153670
--  and f.pkt <= 10
    and (f.bytes / f.pkt) <= 80
group by f.dstip, f.dstport
;

-- examine aggregated flow log between our office and RedLock AWS
-- All traffic should be legitimate flows, and we can use this to show all hosts in RedLock AWS
-- And also we can apply our rules to filter out low-ratio flows and see how many host we can detect.
select
    count(distinct f.dstip)
--  , f.dstip
    , f.dstport
from flow_summary_h f
where (f.conn_dir = 0 or f.conn_dir = 0)
    and f.customer_id = 2 -- redlock id
    and (f.bytes_vol / f.pkt_vol) > 40
--  and f.srcip = 854153670
--  and (f.srcip = 854153670 or f.issrcpublic = false)      -- gateway ip of redlock office since 8/22/2016
    and f.issrcpublic = true
    and f.isdstpublic = false
    and f.ts >= 1473638400000       -- 9/12/2016 00:00:00 GMT
    and not f.dstip = -1062729189  -- ip of W Close 192.168.10.27
--  and not f.dstip = -1062729170  -- ip of W Open 192.168.10.46
    and not f.dstip = -1062729179  -- ip of W Close 192.168.10.37 (terminated)
group by 
    f.dstport
--  , f.dstip
;

--select count(*)
--from (
select
    f.dstip
    , f.dstport
    , max(f.bytes_vol / f.pkt_vol)
from flow_summary_h f
where (f.conn_dir = 0 or f.conn_dir = 0)
    and f.customer_id = 3 -- redlock=2, workday=3
    and f.issrcpublic = true and f.isdstpublic = false
    and f.ts >= 1473638400000       -- 8/22/2016 00:00:00 GMT
    and not f.dstip = -1062729189  -- ip of W Close 192.168.10.27
--  and not f.dstip = -1062729170  -- ip of W Open 192.168.10.46
    and not f.dstip = -1062729179  -- ip of W Close 192.168.10.37 (terminated)
group by 
    f.dstport,
    f.dstip

except

select
    f.dstip
    , f.dstport
    , max(f.bytes_vol / f.pkt_vol)
from flow_summary_h f
where (f.conn_dir = 0 or f.conn_dir = 0)
    and f.customer_id = 3 -- redlock=2, workday=3
    and ((f.bytes_vol / f.pkt_vol) > 54 or not (f.bytes_vol % f.pkt_vol) = 0)
    and f.issrcpublic = true and f.isdstpublic = false
    and f.ts >= 1473638400000       -- 8/22/2016 00:00:00 GMT
    and not f.dstip = -1062729189  -- ip of W Close 192.168.10.27
--  and not f.dstip = -1062729170  -- ip of W Open 192.168.10.46
    and not f.dstip = -1062729179  -- ip of W Close 192.168.10.37 (terminated)
group by 
    f.dstport,
    f.dstip
--)
;


select  f_unixts_to_timestamp(ts, 'ms'), flowcount, proto, srcip, dstip, dstport, conn_dir, bytes_vol, pkt_vol,  (bytes_vol / pkt_vol) as ratio, region_id
from flow_summary_h
where
    (conn_dir = 0 or conn_dir = 1)
    and customer_id = 3 -- redlock=2, workday=3
--  and dstport in (22)
    and dstport = 444
    and proto = 6
    and ts >= 1473638400000
--  and dstip in (182212856, 182207730, 182221210, 182214266, 182210189)
--  and dstip in (182206492, 182206762, 182206955, 182216765)
    and dstip = 182217573
    and issrcpublic = true and isdstpublic = false
--  and not dstip in (-1407319136, -1407319950, -1407316283)
    and not dstip = -1062729189  -- ip of W Close 192.168.10.27
--  and not dstip = -1062729170  -- ip of W Open 192.168.10.46
    and not dstip = -1062729179  -- ip of W Close 192.168.10.37 (terminated)
;

select
    f.dstip
    , f.dstport
    , f.srcip
from flow_summary_h f
where (f.conn_dir = 0 or f.conn_dir = 0)
    and f.customer_id = 2 -- redlock id
    and (f.bytes_vol / f.pkt_vol) > 80
--  and f.srcip = 854153670
--  and (f.srcip = 854153670 or f.issrcpublic = false)      -- gateway ip of redlock office since 8/22/2016
--  and f.issrcpublic = true
    and f.issrcpublic = false
    and f.isdstpublic = true
    and f.dstport = 443
    and f.ts >= 1473638400000       -- 8/22/2016 00:00:00 GMT
    and not f.dstip = -1062729189  -- ip of W Close 192.168.10.27
--  and not f.dstip = -1062729170  -- ip of W Open 192.168.10.46
    and not f.dstip = -1062729179  -- ip of W Close 192.168.10.37 (terminated)
group by 
    f.dstport,
    f.dstip,
    f.srcip
;


select *
from flow_summary_h f
where (f.conn_dir = 0 or f.conn_dir = 1) 
    and f.customer_id = 2 -- redlock id
    and (f.bytes_vol / f.pkt_vol) <= 80
    and dstport = 80
    and f.issrcpublic = false
    and f.ts >= 1473638400000       -- 8/22/2016 00:00:00 GMT
    and not f.dstip = -1062729189  -- ip of W Close 192.168.10.27
    and not f.dstip = -1062729179  -- ip of W Close 192.168.10.37 (terminated)
;


-- check the attack flow statistic
select
    f.dstport,
    count(*) as flow_count,
    count()
from (
    select
        srcip,
        dstip,
        srcport,
        dstport,
        proto,
        pkt,
        bytes,
        to_time,
        ts,
        conn_dir,
        observer_id,
        max(rkl_ingestion_ts) as latest_rkl_ingestion_ts,
        (f.bytes / f.pkt) as ratio
    from flow_logs
    group by
        srcip,
        dstip,
        srcport,
        dstport,
        proto,
        pkt,
        bytes,
        to_time,
        ts,
        conn_dir,
        observer_id
) f
join threat_feeds t
on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 1)
--  and f.pkt <= 10
--  and (f.bytes / f.pkt) <= 80
--  and EXISTS(SELECT 1 FROM flow_logs fl WHERE f.dstip=fl.dstip and f.srcip=fl.srcip and f.srcport=fl.srcport and f.dstport=fl.dstport and f.proto=fl.proto and f.conn_dir=1-fl.conn_dir)
--  and f.srcip = 854153670
--  and ts >= 1471824000000
group by f.dstport
--limit 100
;



-- check the attack flow statistic
select
    f.dstport,
    f.conn_dir,
    count(case when f.ratio <= 50 then 1 end) as ratio_0_50,
    count(case when f.ratio > 50 and f.ratio <= 60 then 1 end) as ratio_50_60,
    count(case when f.ratio > 60 and f.ratio <= 70 then 1 end) as ratio_60_70,
    count(case when f.ratio > 70 and f.ratio <= 80 then 1 end) as ratio_70_80,
    count(case when f.ratio > 80 and f.ratio <= 100 then 1 end) as ratio_80_100,
    count(case when f.ratio > 100 and f.ratio <= 150 then 1 end) as ratio_100_150,
    count(case when f.ratio > 150 and f.ratio <= 200 then 1 end) as ratio_150_200,
    count(case when f.ratio > 200 then 1 end) as ratio_200_inf,
    count(*) as flow_count,
    sum(f.pkt) / count(*) as ave_pkt_per_flow
from (
    select
        srcip,
        dstip,
        srcport,
        dstport,
        proto,
        pkt,
        bytes,
        to_time,
        ts,
        conn_dir,
        observer_id,
        max(rkl_ingestion_ts) as latest_rkl_ingestion_ts,
        (bytes / pkt) as ratio
    from flow_logs
    group by
        srcip,
        dstip,
        srcport,
        dstport,
        proto,
        pkt,
        bytes,
        to_time,
        ts,
        conn_dir,
        observer_id,
        ratio
) f
join threat_feeds t
on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 1)
--  and f.pkt <= 10
--  and (f.bytes / f.pkt) <= 80
--  and f.srcip = 854153670
--  and ts >= 1471824000000
group by f.dstport, f.conn_dir
--limit 100
;


-- check attacked port in the case of workday
select
--  f.srcip,
    f.dstport,
    sum(flowcount) as flowcount
from flow_summary_h f
--join threat_feeds t
--on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 0)
    and f.customer_id = 2 -- workday id
--  and (f.bytes_vol / f.pkt_vol) <= 80
--  and f.srcip = 854153670     -- gateway ip of redlock office since 8/22/2016
    and f.ts >= 1471824000000       -- 8/22/2016 00:00:00 GMT
group by 
    f.dstport
--  , f.srcip
;

select *
from flow_summary_h f
where (f.conn_dir = 0 or f.conn_dir = 0)
    and f.customer_id = 2 -- workday id
    and f.ts >= 1471824000000       -- 8/22/2016 00:00:00 GMT
    and f.dstport = 80
    and issrcpublic
;

-- check the connections from new office to RedLock AWS
-- these connection should be legitimate connections
-- return the false positive ratio.
select sum(CASE WHEN 
            ((f.bytes_vol / f.pkt_vol) <= 80
            and (f.pkt_vol / f.flowcount) <= 10) 
            THEN f.flowcount END)::float / 
       sum(f.flowcount) as FP
from (
    select *
    from flow_summary_h
    where (conn_dir = 0 or conn_dir = 1)
        and customer_id = 2
        and srcip = 854153670   
        and ts >= 1471392000000     -- 8/17/2016 00:00:00 GMT
) f
;

-- check the connections to W Close
select
    ts, flowcount, proto, srcip, dstip, dstport, conn_dir, bytes_vol, pkt_vol,  (bytes_vol / pkt_vol) as ratio 
from flow_summary_h f
--join threat_feeds t
--on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 1)
    and issrcpublic = True
    and f.dstip = -1062729189  -- ip of W Close 192.168.10.27
--  and f.dstip = -1062729170  -- ip of W Open 192.168.10.46
    and not f.srcip = 854153670 
--  and f.dstport = 2020
;


-- check the SSH connections to W Close
select
    max(ts) - min(ts) as time_len,
    sum(flowcount) as total_flowcount,
    proto, srcip, f_friendly_ip(srcip) as srcip_str,
    dstip, dstport, conn_dir,
    sum(bytes_vol) as total_bytes_vol,
    sum(pkt_vol) as total_pkt_vol, 
    min(bytes_vol / pkt_vol) as min_ratio,
    max(bytes_vol / pkt_vol) as max_ratio,
    (sum(bytes_vol) / sum(pkt_vol)) as avg_ratio,
    min(pkt_vol / flowcount) as min_ppf,
    max(pkt_vol / flowcount) as max_ppf,
    (sum(pkt_vol) / sum(flowcount)) as avg_ppf,
    min((bytes_vol - pkt_vol * 40) / flowcount) as min_dpf,
    max((bytes_vol - pkt_vol * 40) / flowcount) as max_dpf,
    (sum((bytes_vol - pkt_vol * 40)) / sum(flowcount)) as avg_dpf
from flow_summary_h f
--join threat_feeds t
--on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 0)
    and issrcpublic = True and isdstpublic = False
--  and f.dstip = -1062729189  -- ip of W Close 192.168.10.27
    and f.dstip = -1062729170  -- ip of W Open 192.168.10.46
    and not f.srcip = 854153670 
    and f.dstport = 22
    and f.ts >= 1474506000000  -- 09/21/2016 6pm the time enable password authentication
group by 
    proto, srcip, dstip, dstport, conn_dir
;


-- check the SSH connections to W Open
select
    f_unixts_to_timestamp(ts,'ms') as ts,
    flowcount, proto, f_friendly_ip(srcip) as srcip_str, f.srcip,
    dstip, dstport, conn_dir, bytes_vol, pkt_vol, 
    (bytes_vol / pkt_vol) as ratio, (pkt_vol / flowcount) as ppf, (bytes_vol - pkt_vol * 40) / flowcount as dpf
from flow_summary_h f
--join threat_feeds t
--on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 0)
    and issrcpublic = True and isdstpublic = False
--  and f.dstip = -1062729189  -- ip of W Close 192.168.10.27
    and f.dstip = -1062729170  -- ip of W Open 192.168.10.46
    and not f.srcip = 854153670 
--  and f.srcip = 872292498
    and f.dstport = 22
    and f.ts >= 1474506000000  -- 09/21/2016 6pm the time enable password authentication
;



-- check the SSH connections to Workday
select
    f_unixts_to_timestamp(ts,'ms') as ts,
    flowcount, proto, f_friendly_ip(srcip) as srcip_str, f.srcip,
    dstip, dstport, conn_dir, bytes_vol, pkt_vol, 
    (bytes_vol / pkt_vol) as ratio, (pkt_vol / flowcount) as ppf, (bytes_vol - pkt_vol * 40) / flowcount as dpf
from flow_summary_h f
join threat_feeds t
on f.srcip = t.ip_address
where (f.conn_dir = 1 or f.conn_dir = 1)
    and customer_id = 3 -- Workday id
    and issrcpublic = True and isdstpublic = False
--  and f.srcip = 2111109205
    and f.dstport = 22
    and f.ts >= 1473638400000  -- 09/12/2016 0am GMT
;


-- check the SSH connections to Workday aggregation resuly by src -> dst
-- for finding attackers that are running brute force attack
select
    avg(c.fc) as fc_per_h,
    f_friendly_ip(c.srcip) as srcip_str, c.srcip, c.dstport, c.conn_dir,
    
    c.avg_bpf,
    sqrt(sum(pow(c.bpf - c.avg_bpf, 2) * c.fc) / sum(c.fc)) / c.avg_bpf * 100 as sd_bpf,
    
    c.avg_ratio, 
    sqrt(sum(pow(c.ratio - c.avg_ratio, 2) * c.fc) / sum(c.fc)) / c.avg_ratio * 100 as sd_ratio,
    
    c.avg_ppf, 
    sqrt(sum(pow(c.ppf - c.avg_ppf, 2) * c.fc) / sum(c.fc)) / c.avg_ppf * 100 as sd_ppf,
    
    c.avg_dpf,
    sqrt(sum(pow(c.dpf - c.avg_dpf, 2) * c.fc) / sum(c.fc)) / c.avg_dpf * 100 as sd_dpf,
    
    count(distinct(c.dstip)) as dst_num
--  , listagg(c.dstip, ', ') as dstip_array
from (
    select
        a.fc,
        a.srcip, a.dstport, a.conn_dir, a.dstip,
        a.bpf,
        b.avg_bpf,
        a.ratio,
        b.avg_ratio,
        a.ppf,
        b.avg_ppf,
        a.dpf,
        b.avg_dpf
    from (
        select
            f.flowcount as fc,
            f.srcip, f.dstport, f.conn_dir, f.dstip,
            bytes_vol / f.flowcount as bpf,
            bytes_vol / pkt_vol as ratio,
            pkt_vol / f.flowcount as ppf,
            (bytes_vol - pkt_vol * 40) / f.flowcount as dpf
        from flow_summary_h f
--      join threat_feeds t
--      on f.srcip = t.ip_address
        where (f.conn_dir = 1 or f.conn_dir = 1)
            and customer_id = 3 -- Workday id
            and issrcpublic = True and isdstpublic = False
        --  and f.srcip = 2111109205
            and f.dstport = 22
            and f.proto = 6
            and f.ts >= 1476082800000
            -- brute force usually need a large number of attempts, so ignore src->dst with low count
            -- and with high ratio
            -- exclude flows for port scanning
            and f.flowcount >= 5 
            and f.bytes_vol / f.pkt_vol > 70 
            and not f.bytes_vol % f.pkt_vol = 0
    ) a
    join (
        select
            f.srcip, f.dstport, f.conn_dir,
            sum(bytes_vol) / sum(f.flowcount) as avg_bpf,           
            sum(bytes_vol / pkt_vol * f.flowcount) / sum(f.flowcount) as avg_ratio,             
            sum(pkt_vol) / sum(f.flowcount) as avg_ppf,             
            sum(bytes_vol - pkt_vol * 40) / sum(f.flowcount) as avg_dpf
        from flow_summary_h f
        where (f.conn_dir = 1 or f.conn_dir = 1)
            and customer_id = 3 -- Workday id
            and issrcpublic = True and isdstpublic = False
        --  and f.srcip = 2111109205
            and f.dstport = 22
            and f.proto = 6
            and f.ts >= 1476082800000
            -- brute force usually need a large number of attempts, so ignore src->dst with low count
            -- and with high ratio
            -- exclude flows for port scanning
            and f.flowcount >= 5 
            and f.bytes_vol / f.pkt_vol > 70 
            and not f.bytes_vol % f.pkt_vol = 0
        group by
            f.srcip, f.dstport, f.conn_dir
    ) b
    on b.srcip = a.srcip
        and b.conn_dir = a.conn_dir
        and b.dstport = a.dstport
) c
group by 
    c.srcip, c.dstport, c.conn_dir, c.avg_bpf, c.avg_ratio, c.avg_ppf, c.avg_dpf
;



-- count recall
select
    count(distinct(CASE WHEN f.pkt <= 10 and (f.bytes / f.pkt) <= 80 THEN f.srcip END)) as recall,
    count(distinct(f.srcip)) as total
--  (recal / total) as ratio
from flow_logs f
join threat_feeds t
on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 1)
;


select
    count(*) as count 
from flow_logs 
where (conn_dir = 0 or conn_dir = 1) and 
    pkt <= 10 and
    (bytes / pkt) <= 80
;

select count(*) as count
from flow_logs;

select max(ts) as max_time, min(ts) as min_time
from flow_logs
where customer_id = 2;


-- query data aggregated by src port
SELECT COUNT(*) AS flowcount,srcip,dstip,dstport,issrcpublic,isdstpublic,conn_dir,SUM(bytes) AS bytes_vol,SUM(pkt) AS pkt_vol,
        customer_id,account_id,region_id,observer_id,EXISTS(SELECT 1 FROM threat_feeds WHERE ip_address=srcip) AS srcMatchedThreatFeed, 
        EXISTS(SELECT 1 FROM threat_feeds WHERE ip_address=dstip) AS dstMatchedThreatFeed FROM flow_logs 
WHERE 
        customer_id IN (2) AND 
        conn_dir BETWEEN 0 AND 1 AND
        ts BETWEEN 1470009600000 AND 1470787200000 
GROUP BY 
        srcip,dstip,dstport,issrcpublic,isdstpublic,conn_dir,customer_id,account_id,region_id,observer_id
--limit 100
;



-- examine raw flow log between our office and W Open for SSH Attack research
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
--join threat_feeds t
--on f.srcip = t.ip_address
where (f.conn_dir = 1 or f.conn_dir = 1)
    and f.customer_id = 2 -- redlock id
--  and (f.bytes_vol / f.pkt_vol) > 40
    and (f.srcip = 854153670)       -- gateway ip of redlock office since 8/22/2016
    and f.issrcpublic = true
    and f.isdstpublic = false
--  and f.srcip = 1541447811
    and f.dstport = 2020
    and f.ts >= 1476229800000       
--  and f.ts <= 1476135054750       
--  and f.dstip = -1062729170  -- ip of W Open 192.168.10.46
    and f.dstip = -1062729189  -- ip of W Close 192.168.10.27
;


-- examine raw flow log between ssh attacker to Workday host for SSH Attack research
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
--join threat_feeds t
--on f.srcip = t.ip_address
where (f.conn_dir = 1 or f.conn_dir = 1)
    and f.customer_id = 3 -- workday id
    and (f.bytes_vol / f.pkt_vol) > 80
    and (f.srcip = 2111109205)      -- potential ssh attacker ip
--  and f.srcip = 782629787     -- potential legitimate ip
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

-- examine raw flow log between ssh attacker to Workday host for SSH Attack research
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
--join threat_feeds t
--on f.srcip = t.ip_address
where f.conn_dir = 0
    and f.customer_id = 3 -- workday id
--  and (f.bytes_vol / f.pkt_vol) > 40
    and (f.srcip = 2111109205)      -- potential ssh attacker ip
--  and f.srcip = 782629787         -- potential legitimate ip
    and f.issrcpublic = true
    and f.isdstpublic = false
--  and f.srcip = 1541447811
    and f.dstport = 22
    and f.ts >= 1476082800000       
--  and f.ts <= 1476169200000       
    and f.dstip = 182212684
;



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
--  and f.ts >= 1475305200000
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


-- raw flow data of SSH traffic from public to private Workday of a day
select * from raw_flow_logs f
where 
    f.customer_id = 3 -- workday id
    and f.issrcpublic = true
    and f.isdstpublic = false
    and f.dstport = 22
    and f.ts >= 1476082800000
    and f.ts <= 1476169200000
;

