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


def draw(data, out_file_path):
    flow_index = data[0]
    ratio = data[1]
    bpf = data[2]
    ppf = data[3]
    dpf = data[4]
    time_life = data[5]

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

    time_life_trace = go.Scatter(
        x=flow_index,
        y=time_life,
        name='time_life of a flow',
    )

    fig = tools.make_subplots(rows=5, cols=1)

    fig.append_trace(ratio_trace, 1, 1)
    fig.append_trace(bpf_trace, 2, 1)
    fig.append_trace(ppf_trace, 3, 1)
    fig.append_trace(dpf_trace, 4, 1)
    fig.append_trace(time_life_trace, 5, 1)

    fig['layout'].update(
        height=800, width=1200, title='SSH Attack Detection Metrics')

    min_x = 0
    max_x = int(len(flow_index) * 1.1)
    x_label = 'flow index (ordered by ts)'
    y_labels = [
        'ratio (Bytes)', 'bpf (Bytes)', 'ppf', 'dpf (Bytes)', 'time life (ms)']
    for i in range(1, 6):
        fig['layout']['xaxis' + str(i)].update(
            title=x_label,
            range=[min_x, max_x])
        fig['layout']['yaxis' + str(i)].update(
            title=y_labels[i - 1])

    plot_url = py.offline.plot(fig, filename=out_file_path)
    return plot_url
