### This file produces an nsg.csv file with which each flow log is appended with its corresponding label from label.csv
import sys
import csv
import argparse
import numpy as np
import re
from datetime import datetime
import math
import bisect
import pickle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', required=True)            # name of input folder
    args = parser.parse_args()

    flows = FlowLogs(args.f)

class FlowLogs():
    def __init__(self, srcfolder):
        self.read_lblfile(srcfolder + "/label.csv")
        self.read_logfile(srcfolder + "/nsg.csv")
        self.convert_to_list()
        self.write_pklfile(srcfolder + "/flows.pkl")

    def read_lblfile(self, lblfile):
        self.labels = Labels()
        # read labelfile entry by entry
        with open(lblfile, 'r') as lb:
            cr = csv.reader(lb, delimiter=',')
            for row in cr:
                self.labels.add_label(row)

    def read_logfile(self, logfile):
        self.logs = []
        # read logfile entry by entry
        with open(logfile, 'r') as lg:
            cr = csv.reader(lg, delimiter=',')
            for row in cr:
                new_flow = Flow(row)
                new_flow.label = self.labels.find_label(new_flow.srcip_str, new_flow.dstip_str, new_flow.time)
                self.logs.append(new_flow)

    def convert_to_list(self):
        self.logs_as_list = []
        for flow in self.logs:
            flow_as_list = [flow.time, flow.srcip, flow.dstip, flow.srcport, flow.dstport, flow.protocol, flow.direction, flow.decision, flow.state, flow.pktsent, flow.bytesent, flow.pktrecv, flow.byterecv, flow.label]
            self.logs_as_list.append(flow_as_list)

    def ip_str_to_int(self, ipaddr):
        return int(ipaddr.split())

    def write_pklfile(self, pklfile):
        with open(pklfile, 'wb') as pk:
            pickle.dump(self.logs_as_list, pk)


class Labels():
    def __init__(self):
        self.labels = {}

    def add_label(self, row):
        # read label fields from row
        srcip, dstip, time_str, label = row[:]
        # parse row into a key (corresponding to the srcip + dstip), time, and label value
        key = self.create_key(srcip, dstip)
        time = self.convert_to_unix(time_str)
        # check if key already exists in labelfile, if not create a list
        if key not in self.labels.keys():
            self.labels[key] = []
        # insert time and label into list based on ordering of the time value
        bisect.insort(self.labels[key], [time, label], key=lambda x: x[0])

    def create_key(self, srcip, dstip):
        return srcip + "," + dstip

    def convert_to_unix(self, time_str):
        year, month, day, hour, minute, second, tzh, tzm = re.search("\d+-\d+-\d+ \d+:\d+:\d+\+\d+:\d+", time_str).group(0).replace('-', ':').replace(' ', ':').replace('+', ':').split(':')
        year, month, day, hour, minute, second = int(year), int(month), int(day), int(hour), int(minute), int(second)
        dt = datetime(year, month, day, hour, minute, second)
        unixtime = dt.timestamp()

        return int(unixtime)

    def find_label(self, srcip, dstip, time):
        key = srcip + "," + dstip
        if key not in self.labels.keys():
            key = dstip + "," + srcip
        if key not in self.labels.keys():
            #print(f"Key {key} not found!")
            return 0
        idx = bisect.bisect(self.labels[key], time, key=lambda x: x[0]) - 1
        if idx < 0:
            idx = 0
        return int(self.labels[key][idx][1])


class Flow():
    def __init__(self, row):
        # Read row directly
        self.time_str = row[0]
        self.srcip_str, self.dstip_str, self.srcport, self.dstport, self.protocol = row[1:6]
        self.direction, self.decision, self.state = row[6:9]
        self.pktsent, self.bytesent, self.pktrecv, self.byterecv = row[9:]
        # Process integer fields
        self.srcip = int(self.srcip_str.split('.')[-1])
        self.dstip = int(self.dstip_str.split('.')[-1])
        self.srcport, self.dstport = int(self.srcport), int(self.dstport)
        if self.pktsent == '':
            self.pktsent = 1
        else:
            self.pktsent = int(self.pktsent)
        if self.bytesent == '':
            self.bytesent = 1
        else:
            self.bytesent = int(self.bytesent)
        if self.pktrecv == '':
            self.pktrecv = 1
        else:
            self.pktrecv = int(self.pktrecv)
        if self.byterecv == '':
            self.byterecv = 1
        else:
            self.byterecv = int(self.byterecv)
        self.label = 0
        # convert timestamp string to an integer value
        self.convert_to_unix()

    def __str__(self):
        # represent traffic direction
        match self.direction:
            case 'I':
                dir_repr = 'I' 
            case 'O':
                dir_repr = 'O'
            case _:
                pass
        # represent comm protocol used
        match self.protocol:
            case 'U':
                proto_repr = "UDP"
            case 'T':
                proto_repr = "TCP"
            case _:
                proto_repr = "???"
        # represent if traffic was accepted or denied
        match self.decision:
            case 'A':
                decision_repr = "✓"
            case 'D':
                decision_repr = "✕"
            case _:
                decision_repr = "?"
        # represent flow state
        match self.state:
            case 'B':
                state_repr = "began"
            case 'C':
                state_repr = "continued"
            case 'E':
                state_repr = "stopped by"
            case _:
                state_repr = "?"
        # represent label
        match self.label:
            case 0:
                label_repr = "benign"
            case 1:
                label_repr = "malicious"
            case _:
                label_repr = "benign"
            
        return f"Flow {decision_repr} {self.time_str} [{self.time}], {self.srcip_str}:{self.srcport} {dir_repr}→ {self.dstip_str}:{self.dstport} {state_repr} sending {self.pktsent} {label_repr} pkts ({self.bytesent}B), receiving {self.pktrecv} pkts ({self.byterecv}B) over {proto_repr}"

    def __repr__(self):
        return f"Flow({self.time_str},{self.srcip},{self.dstip},{self.srcport},{self.dstport},{self.protocol},{self.direction},{self.decision},{self.state},{self.pktsent},{self.bytesent},{self.pktrecv},{self.byterecv},{self.label})"

    # Converts the flow's timestamp string to a unixtime integer representation
    def convert_to_unix(self):
        year, month, day, hour, minute, second = re.search("\d+-\d+-\d+T\d+:\d+:[0-9.]+Z", self.time_str).group(0).replace('-', ':').replace('T',':').replace('Z','').split(':')
        year, month, day, hour, minute, second = int(year), int(month), int(day), int(hour), int(minute), int(round(float(second)) * 3 / 5)
        dt = datetime(year, month, day, hour, minute, second)
        unixtime = dt.timestamp()
        
        self.time = int(unixtime)


if __name__ == '__main__' : main()