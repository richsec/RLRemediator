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


-- flow record classified as rejected TCP connection
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
where (f.conn_dir = 0 or f.conn_dir = 1 or f.conn_dir = -6)
--	and f.pkt <= 10
--	and (f.bytes / f.pkt) <= 80
--	and EXISTS(SELECT 1 FROM flow_logs fl WHERE f.dstip=fl.dstip and f.srcip=fl.srcip and f.srcport=fl.srcport and f.dstport=fl.dstport and f.proto=fl.proto and f.conn_dir=1-fl.conn_dir)
--limit 100
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
--	and f.pkt <= 10
--	and (f.bytes / f.pkt) <= 80
--	and EXISTS(SELECT 1 FROM flow_logs fl WHERE f.dstip=fl.dstip and f.srcip=fl.srcip and f.srcport=fl.srcport and f.dstport=fl.dstport and f.proto=fl.proto and f.conn_dir=1-fl.conn_dir)
--	and f.srcip = 854153670
--	and ts >= 1471824000000
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
--	and f.pkt <= 10
--	and (f.bytes / f.pkt) <= 80
--	and f.srcip = 854153670
--	and ts >= 1471824000000
group by f.dstport, f.conn_dir
--limit 100
;


-- check attacked port in the case of workday
select
--	f.srcip,
	f.dstport,
	sum(flowcount) as flowcount
from flow_summary_h f
--join threat_feeds t
--on f.srcip = t.ip_address
where (f.conn_dir = 0 or f.conn_dir = 0)
	and f.customer_id = 2 -- workday id
--	and (f.bytes_vol / f.pkt_vol) <= 80
--	and f.srcip = 854153670		-- gateway ip of redlock office since 8/22/2016
	and f.ts >= 1471824000000		-- 8/22/2016 00:00:00 GMT
group by 
	f.dstport
--	, f.srcip
;

select *
from flow_summary_h f
where (f.conn_dir = 0 or f.conn_dir = 0)
	and f.customer_id = 2 -- workday id
	and f.ts >= 1471824000000		-- 8/22/2016 00:00:00 GMT
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
		and ts >= 1471392000000		-- 8/17/2016 00:00:00 GMT
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
--	and f.dstip = -1062729189  -- ip of W Close 192.168.10.27
	and f.dstip = -1062729170  -- ip of W Open 192.168.10.46
	and not f.srcip = 854153670	
--	and f.dstport = 2020
;


-- count recall
select
	count(distinct(CASE WHEN f.pkt <= 10 and (f.bytes / f.pkt) <= 80 THEN f.srcip END)) as recall,
	count(distinct(f.srcip)) as total
--	(recal / total) as ratio
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