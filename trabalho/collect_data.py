import pyshark
import numpy as np
import datetime
import time

import warnings

warnings.filterwarnings("ignore")

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 

capture = pyshark.LiveCapture(interface='\\Device\\NPF_{DA3C63EE-7135-4FE7-8CE9-6C2409A2E5B3}', display_filter="ip.addr == 192.168.0.8")

total_data = []

frame_infos = ["frame.encap_type", "frame.len"]
ip_infos = ['ip.hdr_len', 'ip.len', 'ip.flags.rb', 'ip.flags.df', 'ip.flags.mf', 'ip.frag_offset', 'ip.ttl', 'ip.proto']
tcp_infos = ['tcp.srcport', 'tcp.dstport', 'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 'tcp.flags.cwr', 'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 'tcp.flags.push', 'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 'tcp.window_size', 'tcp.time_delta']

try:
    print(f"Iniciando coleta de dados às: {datetime.datetime.now()}")

    while True:
        data = []
        try:
            for packet in capture.sniff_continuously(packet_count=25):
                temp = []
                for info in frame_infos:
                    if packet.frame_info._all_fields[info] == "True":
                        temp.append(1)
                    elif packet.frame_info._all_fields[info] == "False":
                        temp.append(0)
                    else:
                        temp.append(int(float(packet.frame_info._all_fields[info])))
                if hasattr(packet, 'ip'):
                    for info in ip_infos:
                        if packet.ip._all_fields[info] == "True":
                            temp.append(1)
                        elif packet.ip._all_fields[info] == "False":
                            temp.append(0)
                        else:
                            temp.append(int(float(packet.ip._all_fields[info])))
                else:
                    temp.extend([0,0,0,0,0,0,0,0])
                if hasattr(packet, 'tcp'):
                    for info in tcp_infos:
                        if info == 'tcp.flags.ns' or info == 'tcp.flags.ecn':
                            try:
                                temp.append(int(float(packet.tcp._all_fields[info])))
                            except Exception:
                                temp.append(0)
                            continue
                        if packet.tcp._all_fields[info] == "True":
                            temp.append(1)
                        elif packet.tcp._all_fields[info] == "False":
                            temp.append(0)
                        else:
                            temp.append(int(float(packet.tcp._all_fields[info])))
                else:
                    temp.extend([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,])

                data.append(temp)

            # data = np.array([data])
            
            data = np.array(data)
            data = np.array(np.ravel(data))

            total_data.append(data)

        except Exception as e:
            print("Deu erro aqui ó")
            print(e)

except KeyboardInterrupt:
    print(f"Encerrando coleta de dados às {datetime.datetime.now()}")
    
    capture.close()

    total_data = np.array(total_data)
    
    name = f"collected_data-{time.time()}.npy"
    
    print(f"Salvando coleta como: {name}")
    np.save(f"data/{name}",total_data)