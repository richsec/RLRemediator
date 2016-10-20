from utils import read_result_from_csv
from collections import defaultdict
from collections import deque
from utils import draw

# from paper SSH Compromise Detection using NetFlow/IPFIX
SSH_ATTACK_PKT_MAX = 51
SSH_ATTACK_PKT_MIN = 11

# heuristic guess
SSH_ATTACK_VAR_THRESHOLD = 0.2
SSH_ATTACK_WIN_VAR_THRESHOLD = 0.1
SSH_ATTACK_NUM_FLOW_PER_WIN_THRESHOLD = 5

# 3 mins, because TCP default timeout is 2 mins,
# thus if a flow alive more than that
# then it could be a successful SSH attack.
SSH_CONN_LIFE_TIME_THRESHOLD = 3 * 60 * 1000
WIN_SIZE = 10 * 60 * 1000
RECENT_BF_WIN_THRESHOLD = 1


class FlowLogEnrty:
    def __init__(
            self, ts, ts_end, srcip, srcport,
            dstip, conn_dir, bytes_vol, pkt_vol):
        self.ts = long(ts)
        self.ts_end = long(ts_end)
        self.srcip = int(srcip)
        self.srcport = int(srcport)
        self.dstip = int(dstip)
        self.conn_dir = int(conn_dir)
        self.bytes_vol = int(bytes_vol)
        self.pkt_vol = int(pkt_vol)

    def __str__(self):
        return '(ts=%d, ts_end=%d, srcip=%d, srcport=%d, dstip=%d'\
            ', dir=%d, byte=%d, pkt=%d)' % (
                self.ts, self.ts_end, self.srcip, self.srcport,
                self.dstip, self.conn_dir, self.bytes_vol, self.pkt_vol)


class FlowStat:
    def __init__(self, win_start, win_end):
        self.win_start = win_start
        self.win_end = win_end
        self.ratio_mean = 0.
        self.ratio_var = 0.
        self.ppf_mean = 0.
        self.ppf_var = 0.
        self.dpf_mean = 0.
        self.dpf_var = 0.
        self.num_flows = 0
        self.is_brute_force = False

    def __str__(self):
        return '(win_start=%d, win_end=%d'\
            ' ratio_mean=%f, ratio_var=%f, ppf_mean=%f, ppf_var=%f'\
            ', dpf_mean=%f, dpf_var=%f, num_flows=%d, is_brute_force=%r)'\
            % (self.win_start, self.win_end,
                self.ratio_mean, self.ratio_var, self.ppf_mean, self.ppf_var,
                self.dpf_mean, self.dpf_var, self.num_flows, self.
                is_brute_force)


class GlobalStatEntry:
    def __init__(self):
        self.dpf_mean = 0.
        self.ratio_mean = 0.
        self.ppf_mean = 0.


class FlowStatHistory:
    """used for checking whethe the traffic is brute froce
    """
    MAX_QUEUE_LENGTH = 5          # only consider the recent 5 windows
    MAX_TIME_LENGTH = 30 * 60 * 1000  # ms

    def __init__(self):
        # queue for statistic data of each time window
        self.stat_queues = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(lambda: None)))

        # statistic data for global stats across windows in the queue
        self.global_stats = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(lambda: None)))

    def add_flow_stats(self, flow_stats):
        for srcip in flow_stats.keys():
            tmp1 = flow_stats[srcip]
            for dstip in tmp1.keys():
                tmp2 = tmp1[dstip]
                for conn_dir in tmp2.keys():
                    stat = tmp2[conn_dir]
                    queue = self.stat_queues[srcip][dstip][conn_dir]
                    global_stat = self.global_stats[srcip][dstip][conn_dir]

                    if queue is None:
                        queue = deque()
                        self.stat_queues[srcip][dstip][conn_dir] = queue

                    if global_stat is None:
                        global_stat = GlobalStatEntry()
                        self.global_stats[srcip][dstip][conn_dir] = global_stat

                    ts = stat.win_start
                    queue.append(stat)
                    # if queue is too long, remove the last one
                    if len(queue) > self.MAX_QUEUE_LENGTH:
                        queue.popleft()

                    # remove win data which is too old
                    oldest_stat = queue[0]
                    while oldest_stat.win_start < ts - self.MAX_TIME_LENGTH:
                        queue.popleft()
                        oldest_stat = queue[0]

                    self._classify_brute_force(stat, queue, global_stat)

    def _classify_brute_force(self, stat, queue, global_stat):
        # decide whether a srcip to dstip is a brute force attack
        # By looking into the data inside the window,
        # we requires:
        # 1. mean_ppf is in the range of attack
        # 2. var_ppf, var_dpf, var_ratio are within threshold
        # (e.g. 20% of mean)
        # We think historical stats for previous windows are also useful
        # For SSH brute force, it should be in a stable traffic pattern
        stat.is_brute_force = False

        # for SSH attacker, the srcip is usually only used for attacking
        # thus the traffic pattern should be similar (at least in last hour)
        ppf_mean = stat.ppf_mean * stat.num_flows
        dpf_mean = stat.dpf_mean * stat.num_flows
        ratio_mean = stat.ratio_mean * stat.num_flows
        total_num_flows = stat.num_flows
        num_recent_bf_attack = 0
        for i in range(len(queue) - 2, -1, -1):
            s = queue[i]
            if not s.is_brute_force:
                # WE ASSUME: an brute force attack traffic does not mix
                # with non-brute force traffic
                # which is reasonable.
                break
            num_recent_bf_attack += 1

            total_num_flows += s.num_flows
            # weighted by the number of flows in each window
            ratio_mean += s.ratio_mean * s.num_flows
            ppf_mean += s.ppf_mean * s.num_flows
            dpf_mean += s.dpf_mean * s.num_flows
        ppf_mean /= total_num_flows
        dpf_mean /= total_num_flows
        ratio_mean /= total_num_flows

        global_stat.dpf_mean = dpf_mean
        global_stat.ppf_mean = ppf_mean
        global_stat.ratio_mean = ratio_mean

        # if a few recent window are bf attack, then the current window
        # is also likely to be. Cause if successful attack happens,
        # then the stat in current window may be different.
        if num_recent_bf_attack >= RECENT_BF_WIN_THRESHOLD:
            stat.is_brute_force = True
            return

        # if there is not recent bf windows then we check
        # the metrics of this single window first.
        if stat.num_flows < SSH_ATTACK_NUM_FLOW_PER_WIN_THRESHOLD:
            return

        if stat.ppf_mean > SSH_ATTACK_PKT_MAX\
                or stat.ppf_mean < SSH_ATTACK_PKT_MIN:
            return

        if stat.ppf_var / stat.ppf_mean > SSH_ATTACK_VAR_THRESHOLD\
                or stat.dpf_var / stat.dpf_mean > SSH_ATTACK_VAR_THRESHOLD\
                or stat.ratio_var / stat.ratio_mean > SSH_ATTACK_VAR_THRESHOLD:
            return

        # check difference for the mean of each window and the total mean
        for i in range(0, len(queue)):
            # without consider the first one, i.e. stat
            s = queue[i]
            if s.ppf_mean / ppf_mean > 1 + SSH_ATTACK_WIN_VAR_THRESHOLD\
                or s.dpf_mean / dpf_mean > 1 + SSH_ATTACK_WIN_VAR_THRESHOLD\
                or s.ratio_mean / ratio_mean > \
                    1 + SSH_ATTACK_WIN_VAR_THRESHOLD:
                return

        stat.is_brute_force = True
        return

    def is_brute_force_traffic(self, srcip, dstip, conn_dir):
        queue = self.stat_queues[srcip][dstip][conn_dir]
        if queue is None:
            return False
        return queue[len(queue) - 1].is_brute_force

    def get_global_stat(self, srcip, dstip, conn_dir):
        return self.global_stats[srcip][dstip][conn_dir]


class DataStream:
    """read data in stream style
    """
    def __init__(self, data):
        self.data = data
        self.next_index = 0
        self.length = len(data[data.keys()[0]])

    def get_next_flow(self):
        if self.next_index >= self.length:
            return None

        ts = self.data['ts'][self.next_index]
        ts_end = self.data['ts_end'][self.next_index]
        srcip = self.data['srcip'][self.next_index]
        dstip = self.data['dstip'][self.next_index]
        srcport = self.data['srcport'][self.next_index]
        conn_dir = self.data['conn_dir'][self.next_index]
        bytes_vol = self.data['bytes_vol'][self.next_index]
        pkt_vol = self.data['pkt_vol'][self.next_index]

        self.next_index += 1
        return FlowLogEnrty(
            ts, ts_end, srcip, srcport, dstip, conn_dir, bytes_vol, pkt_vol)


def fid(flow_entry):
    return fid_by_tuples(
        flow_entry.srcip, flow_entry.srcport, flow_entry.dstip)


def fid_by_tuples(srcip, srcport, dstip):
    return long(srcip) * 2**(32 + 16) + long(dstip) * 2**16 + long(srcport)


def calculate_flow_stats(grouped_data, win_start, win_end):
    # calculate means
    flow_stats = defaultdict(
        lambda: defaultdict(
            lambda: defaultdict(lambda: None)))
    for srcip in grouped_data.keys():
        tmp1 = grouped_data[srcip]
        for dstip in tmp1.keys():
            tmp2 = tmp1[dstip]
            for srcport in tmp2.keys():
                tmp3 = tmp2[srcport]
                for conn_dir in tmp3.keys():
                    flow = tmp3[conn_dir]
                    stat = flow_stats[flow.srcip][flow.dstip][flow.conn_dir]
                    if stat is None:
                        stat = FlowStat(win_start, win_end)
                        flow_stats[flow.srcip][flow.dstip][flow.conn_dir] \
                            = stat
                    stat.ratio_mean += flow.bytes_vol / float(flow.pkt_vol)
                    stat.dpf_mean += flow.bytes_vol - 40 * flow.pkt_vol
                    stat.ppf_mean += flow.pkt_vol
                    stat.num_flows += 1

    # calculate means
    for srcip in flow_stats.keys():
        tmp1 = flow_stats[srcip]
        for dstip in tmp1.keys():
            tmp2 = tmp1[dstip]
            for conn_dir in tmp2.keys():
                stat = tmp2[conn_dir]
                stat.dpf_mean = stat.dpf_mean / float(stat.num_flows)
                stat.ppf_mean = stat.ppf_mean / float(stat.num_flows)
                stat.ratio_mean = stat.ratio_mean / float(stat.num_flows)

    # calculate the var
    # if var is too large, it may not a SSH attack
    for srcip in grouped_data.keys():
        tmp1 = grouped_data[srcip]
        for dstip in tmp1.keys():
            tmp2 = tmp1[dstip]
            tmp_stats = flow_stats[srcip][dstip]
            for srcport in tmp2.keys():
                tmp3 = tmp2[srcport]
                for conn_dir in tmp3.keys():
                    flow = tmp3[conn_dir]
                    stat = tmp_stats[conn_dir]
                    stat.dpf_var += (
                        flow.bytes_vol - 40 * flow.pkt_vol - stat.dpf_mean)**2\
                        / stat.num_flows
                    stat.ppf_var += (flow.pkt_vol - stat.ppf_mean)**2 \
                        / stat.num_flows
                    ratio = flow.bytes_vol / float(flow.pkt_vol)
                    stat.ratio_var += (ratio - stat.ratio_mean)**2 \
                        / stat.num_flows

    # calculate standard var
    for srcip in flow_stats.keys():
        tmp1 = flow_stats[srcip]
        for dstip in tmp1.keys():
            tmp2 = tmp1[dstip]
            for conn_dir in tmp2.keys():
                stat = tmp2[conn_dir]
                stat.dpf_var = stat.dpf_var ** 0.5
                stat.ppf_var = stat.ppf_var ** 0.5
                stat.ratio_var = stat.ratio_var ** 0.5

    return flow_stats


def _is_anomalous_flow(flow, global_stat):
    # flow with anomalous behavior is also likely to be successful
    # but it is hard to know the pattern.
    # Thus cannot accurately separate it from noisy spikes.
    # A conservation rule:
    dpf = flow.bytes_vol - 40 * flow.pkt_vol
    ratio = flow.bytes_vol / float(flow.pkt_vol)
    return abs(0.5 - dpf / global_stat.dpf_mean % 1) < 0.45 and\
        abs(dpf - global_stat.dpf_mean) / global_stat.dpf_mean > 0.2 and\
        abs(ratio - global_stat.ratio_mean) / global_stat.ratio_mean > 0.2 and\
        abs(flow.pkt_vol - global_stat.ppf_mean) / global_stat.ppf_mean > 0.2


def detect_potential_compromise(
        grouped_data, history_stats, long_live_fids):
    """check each grouped flow in the current window to see whether it is
    likely to be a successful attack
    Note: this part is noisy for now.
    """
    succ_ssh_flow = list()

    for srcip in grouped_data.keys():
        tmp1 = grouped_data[srcip]
        for dstip in tmp1.keys():
            tmp2 = tmp1[dstip]
            is_brute_force = history_stats.is_brute_force_traffic(
                srcip, dstip, 1)
            if not is_brute_force:
                continue
            global_stat = history_stats.get_global_stat(srcip, dstip, 1)
            if global_stat is None:
                continue

            for srcport in tmp2.keys():
                # srcport is not sorted in order of ts
                # consider the traffic from attacker to victim server
                flow = tmp2[srcport][1]
                if flow is None:
                    continue

                # long live time flows are highly likely to be successful flow
                if fid(flow) in long_live_fids:
                    succ_ssh_flow.append(flow)
                    continue

                # 0.45 is a heuristic threshold
                if _is_anomalous_flow(flow, global_stat):
                    succ_ssh_flow.append(flow)
                    continue

    return succ_ssh_flow


def window_check(stream, win_start, win_end, atk_ips, history_stats):
    # return mean, variation, filtered stream data (denoised)
    # identify an attack by srcip and dstip
    # identify a flow by srcip srcport and dstip

    # pickup flows whose ts_delta = ts_end - ts > SSH_CONN_LIFE_TIME_THRESHOLD
    long_live_fids = dict()

    # a dictionary to store data grouped by srcip, srcport, dstip, conn_dir
    grouped_data = defaultdict(
        lambda: defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(lambda: None))))

    flow = stream.get_next_flow()
    while flow is not None:
        if flow.ts < win_start:
            flow = stream.get_next_flow()
            continue

        if flow.ts >= win_end:
            break

        if flow.srcip not in atk_ips:
            flow = stream.get_next_flow()
            continue

        # pick up long live flows
        ts_delta = flow.ts_end - flow.ts
        if ts_delta >= SSH_CONN_LIFE_TIME_THRESHOLD:
            long_live_fids[fid(flow)] = ts_delta

        # group flows in the time window by {srcip,srcport,dstip,conn_dir}
        preflow = \
            grouped_data[flow.srcip][flow.dstip][flow.srcport][flow.conn_dir]
        if preflow is not None:
            # combine current flow into the flow seen before
            preflow.ts = min(preflow.ts, flow.ts)
            preflow.ts_end = max(preflow.ts_end, flow.ts_end)
            preflow.bytes_vol += flow.bytes_vol
            preflow.pkt_vol += flow.pkt_vol
        else:
            grouped_data[flow.srcip][flow.dstip][flow.srcport][flow.conn_dir]\
                = flow

        flow = stream.get_next_flow()

    flow_stats = calculate_flow_stats(grouped_data, win_start, win_end)

    # add flow_stats into the history,
    # and classify whether the traffic is brute force
    history_stats.add_flow_stats(flow_stats)

    succ_ssh_flow = detect_potential_compromise(
        grouped_data, history_stats, long_live_fids)

    return succ_ssh_flow


if __name__ == "__main__":
    # data_file_path = './resources/one_day_workday.csv'
    # atk_ip_file_path = './resources/atk_ips.csv'
    data_file_path = './resources/redlock_traffic_during_sim.csv'
    atk_ip_file_path = './resources/atk_ips_sim.csv'

    data = read_result_from_csv(data_file_path)
    atk_srcips_str = read_result_from_csv(atk_ip_file_path)['srcip']
    atk_srcips = set()
    for srcip_str in atk_srcips_str:
        atk_srcips.add(int(srcip_str))
    # atk_srcips.add(-574476336)
    # atk_srcips.add(628016678)
    # atk_srcips.add(-572150667)

    stream = DataStream(data)
    history_stats = FlowStatHistory()

    # start = 1476082800000
    # end = 1476169185000
    start = 1475795102000
    end = 1475796903000

    win_start = start
    while win_start <= end:
        win_end = win_start + WIN_SIZE
        succ_ssh_flow = window_check(
            stream, win_start, win_end, atk_srcips, history_stats)
        # win_start = win_end
        win_start += WIN_SIZE / 2   # keep some overlap between windows
        if len(succ_ssh_flow) > 0:
            for flow in succ_ssh_flow:
                print flow
