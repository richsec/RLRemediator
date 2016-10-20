from utils import read_result_from_csv
from utils import draw


if __name__ == "__main__":
    resource_dir = './resources'
    result_file_name = 'ssh_attack_sim_denois_neg.csv'
    # result_file_name = 'ssh_attack_to_workday-7.csv'
    # result_file_name = 'ssh_attack_to_workday_from_server-9_denoise_neg.csv'
    # result_file_name = 'ssh_attack_to_workday-8_denoise_neg.csv'
    # result_file_name = 'legitimate_traffic_to_workday-3.csv'

    result_file_path = resource_dir + '/' + result_file_name
    output_fig_file_name = resource_dir + \
        '/fig/' + result_file_name.split('.')[0] + '.html'
    result_data = read_result_from_csv(result_file_path)
    ts = result_data['ts_unix']
    ratio = result_data['ratio']
    bpf = result_data['bpf']
    ppf = result_data['ppf']
    dpf = result_data['dpf']
    flow_index = range(0, len(ts))
    time_life = result_data['ts_delta']
    data = (flow_index, ratio, bpf, ppf, dpf, time_life)

    draw(data, output_fig_file_name)
