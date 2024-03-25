import pyshark
import numpy as np

# from tensorflow.keras.models import load_model
from xgboost import XGBClassifier

import warnings

warnings.filterwarnings("ignore")

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 

# model = load_model("models/LTSM.keras")

model = XGBClassifier()
model.load_model("models/XGBoost.json")

capture = pyshark.LiveCapture(interface='\\Device\\NPF_{DA3C63EE-7135-4FE7-8CE9-6C2409A2E5B3}', display_filter="ip.addr == 192.168.0.8")

while True:
    data = []
    try:
        for packet in capture.sniff_continuously(packet_count=25):
            temp = []
            temp.append(int(float(packet.frame_info._all_fields["frame.encap_type"])))#0
            temp.append(int(float(packet.frame_info._all_fields["frame.len"]))) #1
            # temp.append(int(float(packet.frame_info._all_fields["frame.protocols"]))) #2
            if hasattr(packet, 'ip'):
                temp.append(int(float(packet.ip._all_fields['ip.hdr_len'])))#3
                temp.append(int(float(packet.ip._all_fields['ip.len'])))#4
                temp.append(int(float(packet.ip._all_fields['ip.flags.rb'])))#5
                temp.append(int(float(packet.ip._all_fields['ip.flags.df'])))#6
                temp.append(int(float(packet.ip._all_fields['ip.flags.mf'])))#7
                temp.append(int(float(packet.ip._all_fields['ip.frag_offset'])))#8
                temp.append(int(float(packet.ip._all_fields['ip.ttl'])))#9
                temp.append(int(float(packet.ip._all_fields['ip.proto'])))#10
                # temp.append(int(float(packet.ip._all_fields['ip.src'])))#10
                # temp.append(int(float(packet.ip._all_fields['ip.dst'])))#11
            else:
                temp.extend([0,0,0,0,0,0,0,0])
            if hasattr(packet, 'tcp'):
                temp.append(int(float(packet.tcp._all_fields['tcp.srcport'])))#12
                temp.append(int(float(packet.tcp._all_fields['tcp.dstport'])))#13
                temp.append(int(float(packet.tcp._all_fields['tcp.len'])))#14
                temp.append(int(float(packet.tcp._all_fields['tcp.ack'])))#15
                temp.append(int(float(packet.tcp._all_fields['tcp.flags.res'])))#16

                try:
                    temp.append(int(float(packet.tcp._all_fields['tcp.flags.ns'])))#17
                except Exception:
                    temp.append(0)

                temp.append(int(float(packet.tcp._all_fields['tcp.flags.cwr'])))#18

                try:
                    temp.append(int(float(packet.tcp._all_fields['tcp.flags.ecn'])))#19
                except Exception:
                    temp.append(0)

                temp.append(int(float(packet.tcp._all_fields['tcp.flags.urg'])))#20
                temp.append(int(float(packet.tcp._all_fields['tcp.flags.ack'])))#21
                temp.append(int(float(packet.tcp._all_fields['tcp.flags.push'])))#22
                temp.append(int(float(packet.tcp._all_fields['tcp.flags.reset'])))#23
                temp.append(int(float(packet.tcp._all_fields['tcp.flags.syn'])))#24
                temp.append(int(float(packet.tcp._all_fields['tcp.flags.fin'])))#25
                temp.append(int(float(packet.tcp._all_fields['tcp.window_size'])))#26
                #temp.append(int(float(packet.tcp._all_fields['tcp.analysis.bytes_in_fligh)t'])
                #temp.append(int(float(packet.tcp._all_fields['tcp.analysis.push_bytes_sen)t'])
                temp.append(int(float(packet.tcp._all_fields['tcp.time_delta'])))#27
            else:
                temp.extend([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,])

            data.append(temp)

        # data = np.array([data])
        
        data = np.array(data)
        data = np.array([np.ravel(data)])

        # prediction = model.predict(data, verbose=False).flatten().round()

        prediction = model.predict(data)

        if prediction[0] == 0:
            print("DDoS, Desliga esse servidor plmds")
        else:
            print("Normal, segue o jogo")
        
        # print(prediction)

    except Exception as e:
        print("Deu erro aqui ó")
        print(e)