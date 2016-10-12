# please run "sudo pip install plotly" to install the package
import plotly as py
import plotly.graph_objs as go
import csv

from plotly import tools


def read_result_from_csv(result_file_path):
    # read csv result file
    result_data = dict()
    is_title_row = True
    title_list = list()

    with open(result_file_path, 'rb') as f:
        result_reader = csv.reader(f, delimiter=',', quotechar='"')
        for row in result_reader:
            # create list by titles
            if is_title_row:
                is_title_row = False
                for i in range(0, len(row)):
                    title = row[i]
                    result_data[title] = list()
                    title_list.append(title)
            else:
                for i in range(0, len(row)):
                    data = row[i]
                    title = title_list[i]
                    result_data[title].append(data)

    return result_data


if __name__ == "__main__":
    resource_dir = './resources'
    # result_file_name = 'ssh_attack_sim.csv'
    # result_file_name = 'ssh_attack_to_workday-7.csv'
    result_file_name = 'ssh_attack_to_workday_from_server-6.csv'
    # result_file_name = 'legitimate_traffic_to_workday-2.csv'

    result_file_path = resource_dir + '/' + result_file_name
    output_fig_file_name = resource_dir + \
        '/fig/' + result_file_name.split('.')[0]
    result_data = read_result_from_csv(result_file_path)
    ts = result_data['ts_unix']
    ratio = result_data['ratio']
    bpf = result_data['bpf']
    ppf = result_data['ppf']
    dpf = result_data['dpf']
    flow_index = range(0, len(ts))

    ratio_trace = go.Scatter(
        x=flow_index,
        y=ratio,
        name='ratio: bytes per packet',
    )

    bpf_trace = go.Scatter(
        x=flow_index,
        y=bpf,
        name='bpf: bytes per flow',
    )

    ppf_trace = go.Scatter(
        x=flow_index,
        y=ppf,
        name='ppf: packets per flow',
    )

    dpf_trace = go.Scatter(
        x=flow_index,
        y=dpf,
        name='dpf: databytes per flow',
    )

    layout = go.Layout(
        xaxis=dict(
            title='flow index (order by ts)',
        ),
        yaxis=dict(
            title='ratio',
        ),
    )

    fig = tools.make_subplots(rows=4, cols=1)

    fig.append_trace(ratio_trace, 1, 1)
    fig.append_trace(bpf_trace, 2, 1)
    fig.append_trace(ppf_trace, 3, 1)
    fig.append_trace(dpf_trace, 4, 1)

    fig['layout'].update(
        height=800, width=1200, title='Flows from SSH attacker')

    min_x = 0
    max_x = int(len(flow_index) * 1.1)
    x_label = 'flow index (ordered by ts)'
    y_labels = ['ratio (Bytes)', 'bpf (Bytes)', 'ppf', 'dpf (Bytes)']
    for i in range(1, 5):
        fig['layout']['xaxis' + str(i)].update(
            title=x_label,
            range=[min_x, max_x])
        fig['layout']['yaxis' + str(i)].update(
            title=y_labels[i - 1])

    plot_url = py.offline.plot(fig, filename=output_fig_file_name)
