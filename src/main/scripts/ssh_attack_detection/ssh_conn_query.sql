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
    and f.srcip = 872292498
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
    sqrt(sum(pow(c.bpf - c.avg_bpf, 2) * c.fc) / sum(c.fc)) / c.avg_bpf as sd_bpf,
    
    c.avg_ratio, 
    sqrt(sum(pow(c.ratio - c.avg_ratio, 2) * c.fc) / sum(c.fc)) / c.avg_ratio as sd_ratio,
    
    c.avg_ppf, 
    sqrt(sum(pow(c.ppf - c.avg_ppf, 2) * c.fc) / sum(c.fc)) / c.avg_ppf as sd_ppf,
    
    c.avg_dpf,
    sqrt(sum(pow(c.dpf - c.avg_dpf, 2) * c.fc) / sum(c.fc)) / c.avg_dpf as sd_dpf,
    
    count(c.dstip) as dst_num,
    listagg(c.dstip, ', ') as dstip_array
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
        join threat_feeds t
        on f.srcip = t.ip_address
        where (f.conn_dir = 1 or f.conn_dir = 1)
            and customer_id = 3 -- Workday id
            and issrcpublic = True and isdstpublic = False
        --  and f.srcip = 2111109205
            and f.dstport = 22
            and f.proto = 6
            and f.ts >= 1473638400000  -- 09/12/2016 0am GMT
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
            and f.ts >= 1473638400000  -- 09/12/2016 0am GMT
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




-- Result of simulated SSH attack from office to W Open
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
where f.conn_dir = 1
    and f.customer_id = 2 -- redlock id
    and f.srcip = 854153670    -- gateway ip of redlock office since 8/22/2016
    and f.issrcpublic = true
    and f.isdstpublic = false
    and f.dstport = 22
    and f.ts >= 1475795102000       -- 2016-10-06 23:05:02 GMT
    and f.ts <= 1475796903000       -- 2016-10-06 23:35:03 GMT
    and f.dstip = -1062729170  -- ip of W Open 192.168.10.46
;
