import pandas as pd 
from tkinter import *
from tkinter import filedialog
from pandastable import Table
import numpy as np
import binascii
import seaborn as sns
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP

def full_table():
    packets = rdpcap("test.pcap")

    ip_fields = [field.name for field in IP().fields_desc]
    tcp_fields = [field.name for field in TCP().fields_desc]
    # udp_fields = [field.name for field in UDP().fields_desc]

    dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex'] 

    df = pd.DataFrame(columns=dataframe_fields) # create dataframe
    for packet in packets[IP]:
        # Field array for each row of DataFrame
        field_values = []
        # Add all IP fields to dataframe
        for field in ip_fields:
            if field == 'options':
                # Retrieving number of options defined in IP Header
                field_values.append(len(packet[IP].fields[field]))
            else:
                field_values.append(packet[IP].fields[field])
        
        field_values.append(packet.time)
        
        layer_type = type(packet[IP].payload)
        for field in tcp_fields:
            try:
                if field == 'options':
                    field_values.append(len(packet[layer_type].fields[field]))
                else:
                    field_values.append(packet[layer_type].fields[field])
            except:
                field_values.append(None)
        
        # Append payload
        field_values.append(len(packet[layer_type].payload))
        field_values.append(packet[layer_type].payload.original)
        field_values.append(binascii.hexlify(packet[layer_type].payload.original))
        # Add row to DF
        df_append = pd.DataFrame([field_values], columns=dataframe_fields)
        df = pd.concat([df, df_append], axis=0)

    # Reset Index
    df = df.reset_index()
    # Drop old index column
    df = df.drop(columns="index")
    table = Table(frame, dataframe=df.head(), showtoolbar=True, showstatusbar=True, width=1500, height=800)
    table.show()


root = Tk()
root.geometry("1500x800")
frame = Frame(root)

def get_file():
    root.filename = filedialog.askopenfilename(initialdir="/home/x90/Documents/college/Year2/Programming And Algorithims/analyzed", title="Select a file")
    packets = rdpcap(root.filename)
    packets_length = Label(root, text="Total length of packet is "+ str(len(packets)))
    packets_length.grid(row=2, column=1)

file = Button(frame, text="Open file", command=get_file)
file.grid(row=5, column=0)
myButton = Button(frame, text="Analyze", command=full_table)

myButton.grid(row=0,column=0)



frame.grid(row=0, column=0)




root.mainloop()
