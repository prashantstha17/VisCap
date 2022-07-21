import pandas as pd 
from tkinter import *
from tkinter import filedialog
from pandastable import Table
import binascii
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers import http

menu = Tk()
menu.title("Menu")
menu.geometry("1000x600")


def read_file():
    global filename
    menu.filename = filedialog.askopenfilename(initialdir="/home/x90/Documents/college/Year2/Programming And Algorithims/analyzed", title="Select a file")
    print(menu.filename)


def analyzer():
    table_view = Toplevel()
    table_view.title("Analyzed Pcap")
    table_view.geometry("800x500")
    packets = rdpcap(menu.filename)
    

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



    def show_IPs():
        ip_show = Toplevel()
        ip_show.title("Table Frame")
        ip_show.geometry("1000x600")
        cols = choosed_cols.get()
        cols = cols.split()
        table = Table(ip_show, dataframe=df[cols], showtoolbar=True, showstatusbar=True, width=1500, height=800)
        table.show()


    choosed_cols = Entry(table_view)
    choosed_cols.grid(row=9, column=0)

    choosed_cols_button = Button(table_view, text="Choose columns", command=show_IPs)
    choosed_cols_button.grid(row=11, column=0)

    def show_columns():
        show_cols = Toplevel()
        show_cols.title("Columns Names")
        cols = []
        for i in range(len(df.columns)):
            cols.append(df.columns[i])
        cols = str(cols)
        cols_label = Label(show_cols, text=cols)
        cols_label.pack()
        
    show_cols_button = Button(table_view, text="Click here to show columns", command=show_columns)
    show_cols_button.grid(row=12, column=0)



    choosed = StringVar()
    choosed.set("Address Sending Payloads")
    def choosed_graph():
        return choosed.get()

    choose_graph = OptionMenu(table_view, choosed, 'Address Sending Payloads', 'Destination Adresses (Bytes Received)', 'Source Ports (Bytes Sent)', 'Destination Ports (Bytes Received)', 'History of bytes by most frequent address', 'Suspicious Destination' )
    choose_graph.grid(row=3, column=0)






    def visualizer():
        vis = Toplevel()
        vis.title("Visualizer")
        vis.geometry("1000x600")
        # sns.set(style="darkgrid")

        graph_type = choosed_graph()
        if graph_type == 'Address Sending Payloads':
            source_addresses = df.groupby("src")['payload'].sum()
            source_addresses.plot(kind='barh',title="Addresses Sending Payloads",figsize=(10,10))
            plt.show()

        elif graph_type == 'Destination Adresses (Bytes Received)':
            destination_addresses = df.groupby("dst")['payload'].sum()
            destination_addresses.plot(kind='barh',title="Destination Adresses (Bytes Received)",figsize=(10,10))
            plt.show()

        elif graph_type == 'Source Ports (Bytes Sent)':
            source_ports = df.groupby("sport")['payload'].sum()
            source_ports.plot(kind='barh',title="Source Ports (Bytes Sent)",figsize=(10,10))
            plt.show()

        elif graph_type == 'Destination Ports (Bytes Received)':
            destination_ports = df.groupby("dport")['payload'].sum()
            destination_ports.plot(kind='barh',title="Destination Ports (Bytes Received)",figsize=(10,10))
            plt.show()

        # elif graph_type == 'History of bytes by most frequent address':
        #     frequent_address = df['src'].describe()['top']
        #     frequent_address_df = df[df['src'] == frequent_address]
        #     x = frequent_address_df['payload'].tolist()
        #     sns.barplot(x="time", y="payload", data=frequent_address_df[['payload','time']],label="Total", color="b").set_title("History of bytes sent by most frequent address")
        #     plt.show()


        elif graph_type == 'Suspicious Destination':
            frequent_address = df['src'].describe()['top']
            frequent_address_df = df[df['src']==frequent_address]

            # Only display Src Address, Dst Address, and group by Payload 
            frequent_address_groupby = frequent_address_df[['src','dst','payload']].groupby("dst")['payload'].sum()

            # Plot the Frequent address is speaking to (By Payload)
            frequent_address_groupby.plot(kind='barh',title="Most Frequent Address is Speaking To (Bytes)",figsize=(10,8))

            # Which address has excahnged the most amount of bytes with most frequent address
            # suspicious_ip = frequent_address_groupby.sort_values(ascending=False).index[0]
            # print(suspicious_ip, "May be a suspicious address")

            # Create dataframe with only conversation from most frequent address and suspicious address
            # suspicious_df = frequent_address_df[frequent_address_df['dst']==suspicious_ip]
            plt.show()


    visualize = Button(table_view, text="Visualize Graph", command=visualizer)
    visualize.grid(row=2, column=0)

    
    def get_url(packet):
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
            return url

    def get_login_info(packet):
        if packet.haslayer(http.HTTPRequest):
            if packet.haslayer(Raw):
                load = packet[Raw].load
                #load = str(load)
                keybword = ["usr", "uname", "username", "pwd", "pass", "password"]
                for eachword in keybword:
                    if eachword.encode() in load:
                        return load

    def passwordFinder():
        packets = rdpcap(menu.filename)

        logins = {"URL": [], "Login Info": []}
        for i in range(len(packets)):
            if packets[i].haslayer(http.HTTPRequest):
                url = get_url(packets[i]).decode('utf-8')
                login_info = get_login_info(packets[i])
                if login_info:
                    logins['URL'].append(str(url))
                    logins['Login Info'].append(login_info)

        login_dataframe = pd.DataFrame(logins)
        table_show = Toplevel()
        table_show.title("Table Frame")
        table_show.geometry("1000x600")
        table = Table(table_show, dataframe=login_dataframe, showtoolbar=True, showstatusbar=True, width=1500, height=800)
        table.show()

        

    http_password = Button(table_view, text="Find HTTP Password", command=passwordFinder)
    http_password.grid(row=5, column=0)


    def summarize():
        packets = rdpcap(menu.filename)
        summary = Toplevel()
        summary.title("Summary")
        summary.geometry("1000x600")

        frequent_address = df['src'].describe()['top']

        filename = menu.filename
        filename = filename.split("/")
        filename = filename[-1]
        x = f"""
This file ({filename}) has {len(packets)} packets.

Unique Source Addresses
{df['src'].unique()}

Unique Destination Addresses
{df['dst'].unique()}

Top Source Address
{df['src'].describe()}

Top Destination Address
{df['dst'].describe()}

# Who is Top Address Speaking to?"
{df[df['src'] == frequent_address]['dst'].unique()}

# Who is the top address speaking to (Destination Ports)
{df[df['src'] == frequent_address]['dport'].unique()}

# Who is the top address speaking to (Source Ports)
{df[df['src'] == frequent_address]['sport'].unique()}
"""

        summary_text = Label(summary, text=x)
        summary_text.pack()
    summarizer = Button(table_view, text="Summarize Everything", command=summarize)
    summarizer.grid(row=7, column=0)




get_file = Button(menu, text="Open file", command=read_file)
get_file.pack()
analyze_file = Button(menu, text="Analyze", command=analyzer)
analyze_file.pack()


menu.mainloop()