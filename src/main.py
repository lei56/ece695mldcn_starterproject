### This file produces an nsg.csv file with which each flow log is appended with its corresponding label from label.csv
import argparse
import numpy as np
from datetime import datetime
import pickle
import torch
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv, GAE

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', required=True)            # name of input folder
    args = parser.parse_args()
    srcfolder = args.f

    # import logs from pickle file
    logs = read_pklfile(srcfolder + "/flows.pkl")
    # build feature graph
    net = graph(logs)
    graph.train()


def read_pklfile(pklfile):
    with open(pklfile, 'rb') as pk:
        return pickle.load(pk)


class graph():
    def __init__(self, logs):
        # fix formatting on fields
        for log in logs:
            # protocol
            match log[5]:
                case 'U':
                    log[5] = 1
                case 'T':
                    log[5] = 2
                case _:
                    log[5] = 0
            # direction
            match log[6]:
                case 'I':
                    log[6] = 0
                case 'O':
                    log[6] = 1
                case _:
                    log[6] = 0
            # decision
            match log[7]:
                case 'A':
                    log[7] = 1
                case 'D':
                    log[7] = 2
                case _:
                    log[7] = 0
            # state
            match log[8]:
                case 'B':
                    log[8] = 1
                case 'C':
                    log[8] = 2
                case 'E':
                    log[8] = 3
                case _:
                    log[8] = 0
            # label
            match log[13]:
                case '0':
                    log[13] = 0
                case '1':
                    log[13] = 1
                case _:
                    log[13] = 0

        # create edge list
        connectivity_list = list(set(logs[:,[1,2]]))
        self.edges = torch.tensor(connectivity_list, dtype=torch.long) 
        print(self.edges)

        # extract each unique timestamp value
        times = list(set([row[0] for row in logs]))
        # extract each unique edge pair
        edge_pairs = list(set(row[1:3] for row in logs))

        # create feature list for each timestamp
        edge_features = []
        # track ports which have been seen globally and locally
        seen_ports_global = {} # dictionary[port #] -> entry exists = seen
        seen_ports_local = {} # dictionary[ip addr] -> dictionary[port #] -> entry exists = seen

        # iterate through each timestamp
        for time in times:
            # track features collected for this timestamp
            features = []
            # mask out logs with matching timestamp
            t_mask = logs[:,0] == time
            t_values = logs[t_mask,1:]
            for pair in edge_pairs:
                # mask out logs corresponding to this edge pair
                p_mask = t_values[:,1:3] == pair
                p_values = t_values[p_mask,3:]
                # for pktsent, bytesent, pktrecv, byterecv values, extract min, max, mean, sum, std features
                for idx in range(6,10):
                    extracted_vals = p_values[:,idx]
                    min_val = min(extracted_vals)
                    max_val = max(extracted_vals)
                    sum_val = sum(extracted_vals)
                    if len(extracted_vals == 0):
                        avg_val = 0
                        std_val = 0
                    else:
                        avg_val = sum(extracted_vals) / len(extracted_vals)
                        std_val = np.std(extracted_vals)
                    # append features to feature set on this timestamp
                    features.extend([min_val, max_val, avg_val, sum_val, std_val])
                # track number of UDP and TCP flows
                udp_flows_mask = p_values[:,2] == 1
                udp_count = len(udp_flows_mask)
                tcp_flows_mask = p_values[:,2] == 2
                tcp_count = len(tcp_flows_mask)
                # track number of ports used
                unique_ports = list(set(row[0] for row in p_values).union(set(row[1]) for row in p_values))
                ports_count = len(unique_ports)
                # create dictionary entry for locally seen ports for this IP pair if does not already exist
                if pair not in seen_ports_local.keys():
                    seen_ports_local[pair] = {}
                # track number of unseen local and global ports used
                unseen_local_ports_count = 0
                unseen_global_ports_count = 0
                for port in unique_ports:
                    # determine if port has been seen locally
                    if port not in seen_ports_local[pair].keys():
                        unseen_local_ports_count += 1
                        seen_ports_local[pair][port] = 0
                    seen_ports_local[pair][port] += 1
                    # determine if port has been seen globally
                    if port not in seen_ports_global.keys():
                        unseen_global_ports_count += 1
                        seen_ports_global[port] = 0
                    seen_ports_global[port] += 1
                # append features to feaature set on this timestamp
                features.extend([udp_count, tcp_count, unseen_local_ports_count, unseen_global_ports_count, ports_count])
            # append features as this set for this timestamp
            edge_features.append(features)

    def train(self):
        num_features = 100
        encoder = Encoder(in_chan=num_features, hidden_chan=32, out_chan=16)
        decoder = Decoder(z_dim=16, hidden_dim=32, out_dim=num_features)

        autoencoder = Autoencoder(encoder, decoder)
        optimizer = torch.optim.Adam(autoencoder.parameters(), lr=1e-3)
        criterion = torch.nn.MSELoss()

        for epoch in range(100):
            optimizer.zero_grad()
            # in this case, I actually want to input 
            pred = autoencoder(edges, features)
            loss = criterion(pred, features)
            loss.backward()
            optimizer.step()
            print(f"Epoch {epoch}: loss = {loss.item():.4f}")

class Encoder(torch.nn.Module):
    def __init__(self, in_chan, hidden_chan, out_chan):
        super().__init__()
        self.conv1 = GCNConv(in_chan, hidden_chan)
        self.conv2 = GCNConv(hidden_chan, out_chan)

    # produces edge embeddings z
    def forward(self, edges, features):
        x = self.conv1(edges, features).relu()
        z = self.conv2(edges, features)
        return z

class Decoder(torch.nn.Module):
    def __init__(self, z_dim, hidden_dim, out_dim):
        super().__init__()
        self.mlp = torch.nn.Sequential(
            torch.nn.Linear(2 * z_dim, hidden_dim),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden_dim, out_dim)
        )
    
    def forward(self, z, edges):
        src, dst = edges
        z_edge = torch.cat([edges[src], edges[dst]], dim=1)
        return self.mlp(z_edge)
    
class Autoencoder(torch.nn.Module):
    def __init__(self, encoder, decoder):
        super().__init__()
        self.encoder = encoder
        self.decoder = decoder
    
    def forward(self, edges, features):
        z = self.encoder(edges, features)
        edge_pred = self.decoder(z, features)
        return edge_pred
    

if __name__ == '__main__' : main()