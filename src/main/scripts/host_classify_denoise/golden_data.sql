-- legitimate data from redlock 
-- (all or most of them are negative data)
-- aggregated data
select *
from flow_summary_h
where (conn_dir = 0 or conn_dir = 1)
    and customer_id = 2
    and srcip = 854153670       -- gateway ip of office
    and ts >= 1471392000000     -- 8/17/2016 00:00:00 GMT (date of moving in new office)
;


-- get connections to W Close
-- because no service on port 80, 443, and 22 for W Close,
-- so all TCP connections to these ports should get RST
-- Thus all records here are postive
select *
from flow_summary_h
where (conn_dir = 0 or conn_dir = 1)
    and dstip = -1062729189  -- ip of W Close 192.168.10.27
;


-- get connections to W Open
-- Apache service is running on port 80, 443, 
-- and SSH is running 22,
-- so all or most of TCP connections to these ports should be established
-- Thus all records here are negative
select *
from flow_summary_h
where (conn_dir = 0 or conn_dir = 1)
    and dstip = -1062729170  -- ip of W Open 192.168.10.46
;