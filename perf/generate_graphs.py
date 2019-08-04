#!/usr/bin/python

#
# This script assumes that a CSV file produced by "generate_csv.sh" is provided as input
#

# configurable values:
INPUT_FILE_PUSHPULL_TCP_THROUGHPUT="pushpull_tcp_thr_results.csv"
INPUT_FILE_PUSHPULL_INPROC_THROUGHPUT="pushpull_inproc_thr_results.csv"
INPUT_FILE_PUBSUBPROXY_INPROC_THROUGHPUT="pubsubproxy_inproc_thr_results.csv"
INPUT_FILE_REQREP_TCP_LATENCY="reqrep_tcp_lat_results.csv"


# dependencies

import matplotlib.pyplot as plt
import numpy as np


# functions

def plot_throughput(csv_filename, title):
    message_size_bytes, message_count, pps, mbps = np.loadtxt(csv_filename, delimiter=',', unpack=True)
    plt.semilogx(message_size_bytes, pps / 1e6, label='PPS [Mmsg/s]', marker='x')
    plt.semilogx(message_size_bytes, mbps / 1e3, label='Throughput [Mb/s]', marker='o')
    
    plt.xlabel('Message size [B]')
    plt.title(title)
    plt.legend()
    plt.show()
    plt.savefig(csv_filename.replace('.csv', '.png'))

def plot_latency(csv_filename, title):
    message_size_bytes, message_count, lat = np.loadtxt(csv_filename, delimiter=',', unpack=True)
    plt.semilogx(message_size_bytes, lat, label='Latency [us]', marker='o')
    
    plt.xlabel('Message size [B]')
    plt.title(title)
    plt.legend()
    plt.show()
    plt.savefig(csv_filename.replace('.csv', '.png'))


# main

plot_throughput(INPUT_FILE_PUSHPULL_TCP_THROUGHPUT, 'ZeroMQ PUSH/PULL socket throughput, TCP transport')
plot_throughput(INPUT_FILE_PUSHPULL_INPROC_THROUGHPUT, 'ZeroMQ PUSH/PULL socket throughput, INPROC transport')
plot_throughput(INPUT_FILE_PUBSUBPROXY_INPROC_THROUGHPUT, 'ZeroMQ PUB/SUB PROXY socket throughput, INPROC transport')
plot_latency(INPUT_FILE_REQREP_TCP_LATENCY, 'ZeroMQ REQ/REP socket latency, TCP transport')
