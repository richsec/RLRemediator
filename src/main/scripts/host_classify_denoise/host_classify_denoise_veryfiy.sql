-- Check instances we exclude from classification by applying 
-- the rule:
--      exclude flows with 
--          bytes_vol / pkt_vol <= ratio_threshold
--          and
--          bytes_vol % pkt_vol == 0    
--          (server should return the same-size response for 
--          client if there is no service on the port.
--          Server also may reply the same size response for scanners)
-- We can modify the rule in the following query for tuning.
-- Note two scenarios:
-- 1. When f.issrcpublic = true and f.isdstpublic = false
--      Flows are from outside public ips to AWS instances inside VPC
--      a. We can check whether the excluded instances are not real hosts
--      b. We can check whether the instances not excluded are real hosts
-- 2. f.issrcpublic = false and f.isdstpublic = false
--      Flows between internal instances. In most of cases, 
--      the connection should be established, 
--      but there may be some special cases.
--      Approximately, the excluded instances here are False Negatives.
--      Ideally, we should keep it at zero, but in practice,
--      maybe below 1% is acceptable.
select count(*)
from (
select
    f.dstip
    , f.dstport
    , max(f.bytes_vol / f.pkt_vol)
from flow_summary_h f
where f.conn_dir = 0    -- only classify instances with dst-to-src traffic
    and f.customer_id = 3 -- redlock=2, workday=3
    and f.issrcpublic = true and f.isdstpublic = false
    and f.ts >= 1473638400000       -- 9/12/2016 00:00:00 GMT
    and not f.dstip = -1062729189  -- ip of W Close 192.168.10.27
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
where f.conn_dir = 0
    and f.customer_id = 3 -- redlock=2, workday=3
    -- the rule
    and ((f.bytes_vol / f.pkt_vol) > 48 or not (f.bytes_vol % f.pkt_vol) = 0)
    and f.issrcpublic = true and f.isdstpublic = false
    and f.ts >= 1473638400000       -- 9/12/2016 00:00:00 GMT
    and not f.dstip = -1062729189  -- ip of W Close 192.168.10.27
    and not f.dstip = -1062729179  -- ip of W Close 192.168.10.37 (terminated)
group by 
    f.dstport,
    f.dstip
)
;



-- Query for examine flows to some specified {dstip, dstport} pairs
select  f_unixts_to_timestamp(ts, 'ms'), 
    flowcount, proto, srcip, dstip, 
    dstport, conn_dir, bytes_vol, pkt_vol,  
    (bytes_vol / pkt_vol) as ratio, region_id
from flow_summary_h
where
    (conn_dir = 0 or conn_dir = 1)
    and customer_id = 3 -- redlock=2, workday=3
    and dstport = 444
    and proto = 6
    and ts >= 1473638400000
    and dstip = 182206922
    and issrcpublic = true and isdstpublic = false
    and not dstip = -1062729189  -- ip of W Close 192.168.10.27
    and not dstip = -1062729179  -- ip of W Close 192.168.10.37 (terminated)
;