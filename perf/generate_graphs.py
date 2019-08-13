#!/usr/bin/python3

#
# This script assumes that the set of CSV files produced by "generate_csv.sh" is provided as input
# and that locally there is the "results" folder.
#

# results for TCP:
INPUT_FILE_PUSHPULL_TCP_THROUGHPUT="results/pushpull_tcp_thr_results.csv"
INPUT_FILE_REQREP_TCP_LATENCY="results/reqrep_tcp_lat_results.csv"
TCP_LINK_GPBS=100

# results for INPROC:
INPUT_FILE_PUSHPULL_INPROC_THROUGHPUT="results/pushpull_inproc_thr_results.csv"
INPUT_FILE_PUBSUBPROXY_INPROC_THROUGHPUT="results/pubsubproxy_inproc_thr_results.csv"


# dependencies
#
# pip3 install matplotlib
#

import matplotlib.pyplot as plt
import numpy as np


# functions

def plot_throughput(csv_filename, title, is_tcp=False):
    message_size_bytes, message_count, pps, mbps = np.loadtxt(csv_filename, delimiter=',', unpack=True)

    fig, ax1 = plt.subplots()

    # PPS axis
    color = 'tab:red'
    ax1.set_xlabel('Message size [B]')
    ax1.set_ylabel('PPS [Mmsg/s]', color=color)
    ax1.semilogx(message_size_bytes, pps / 1e6, label='PPS [Mmsg/s]', marker='x', color=color)
    ax1.tick_params(axis='y', labelcolor=color)

    # GBPS axis
    color = 'tab:blue'
    ax2 = ax1.twinx()  # instantiate a second axes that shares the same x-axis
    ax2.set_ylabel('Throughput [Gb/s]', color=color)
    ax2.semilogx(message_size_bytes, mbps / 1e3, label='Throughput [Gb/s]', marker='o')
    if is_tcp:
        ax2.set_yticks(np.arange(0, TCP_LINK_GPBS + 1, TCP_LINK_GPBS/10)) 
    ax2.tick_params(axis='y', labelcolor=color)
    ax2.grid(True)
    
    plt.title(title)
    fig.tight_layout()  # otherwise the right y-label is slightly clippe
    plt.savefig(csv_filename.replace('.csv', '.png'))
    plt.show()

def plot_latency(csv_filename, title):
    message_size_bytes, message_count, lat = np.loadtxt(csv_filename, delimiter=',', unpack=True)
    plt.semilogx(message_size_bytes, lat, label='Latency [us]', marker='o')
    
    plt.xlabel('Message size [B]')
    plt.ylabel('Latency [us]')
    plt.grid(True)
    plt.title(title)
    plt.savefig(csv_filename.replace('.csv', '.png'))
    plt.show()


# main

plot_throughput(INPUT_FILE_PUSHPULL_TCP_THROUGHPUT, 'ZeroMQ PUSH/PULL socket throughput, TCP transport', is_tcp=True)
plot_throughput(INPUT_FILE_PUSHPULL_INPROC_THROUGHPUT, 'ZeroMQ PUSH/PULL socket throughput, INPROC transport')
plot_throughput(INPUT_FILE_PUBSUBPROXY_INPROC_THROUGHPUT, 'ZeroMQ PUB/SUB PROXY socket throughput, INPROC transport')
plot_latency(INPUT_FILE_REQREP_TCP_LATENCY, 'ZeroMQ REQ/REP socket latency, TCP transport')
