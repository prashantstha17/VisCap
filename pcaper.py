
from tkinter import *
from tkinter import filedialog, messagebox
from customtkinter import *
import pandas as pd
from pandastable import Table
import binascii
from scapy.all import *
# from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers import http



set_appearance_mode("dark")  # Modes: system (default), light, dark
set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

base = CTk()  # create CTk window like you do with the Tk window
base.geometry("780x750")
base.title("PCAP analyzer")
base.resizable(False, False)

frame1 = LabelFrame(base, 
                    highlightbackground="grey", 
                    width=550, 
                    height=50, 
                    highlightthickness=3, 
                    text="Selection Section", 
                    background="#302c2c", 
                    foreground="white",
                    labelanchor=N,
                    font=("Times", "16", "bold italic"))
frame1.grid(row=0, column=0, padx=100, pady=50, ipadx=20, ipady=20)

file_label = CTkLabel(frame1, text="Enter a path to pcap file:")
file_label.grid(row=0, column=0, padx=10, pady=10)

file_entry = CTkEntry(frame1, width=200)
file_entry.grid(row=0, column=1, padx=10, pady=10)

def filebrowse():
    filebrowser = filedialog.askopenfilename(initialdir="/home/x90/Documents/college/Year2/Programming And Algorithims/", title="Select a file", filetypes=(("pcap files", "*.pcap"), ("all files", "*.*")))
    file_entry.delete(0, END)
    file_entry.insert(0, str(filebrowser))
    return

file_search_button = CTkButton(frame1, text="Browse", command=filebrowse)
file_search_button.grid(row=0, column=2)

analyze_progres = CTkProgressBar(frame1, width=100)
analyze_progres.grid(row=1, column=2)
analyze_progres.set(0)
analyze_progres.configure(fg_color="white",
                      progress_color="green")

def analyzer():
    # table_view = Toplevel()
    # table_view.title("Analyzed Pcap")
    # table_view.geometry("800x500")
    analyze_progres.set(0)
    if file_entry.get() == "":
        messagebox.showerror("Error", "Please enter a path to a pcap file")

    else:
        try:
            file_name = file_entry.get()
            file_name_split = file_name.split("/")
            file_name_split = file_name_split[-1].split(".")
            file_extension = file_name_split[-1]

            if file_extension == "pcap" or file_extension == "pcapng":
                global df
                
                packets = rdpcap(file_entry.get())
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
                
                analyze_progres.set(1000)
                
                create_table_button.configure(state=NORMAL)
                password_button.configure(state=NORMAL)
                summarizer_button.configure(state=NORMAL)
                graph_view_button.configure(state=NORMAL)
                choosed_cols_button.configure(state=NORMAL)
                view_cols.configure(state=NORMAL)
                
 
            else:
                messagebox.showerror("Error", "File must be a pcap or pcapng file")
                
        except:
            pass


file_analyze = CTkButton(frame1, text="Analyze", command=analyzer)
file_analyze.grid(row=1, column=1)



frame2 = LabelFrame(base, 
                    highlightbackground="grey", 
                    width=730, 
                    height=50, 
                    highlightthickness=3, 
                    text="Analyze Section", 
                    background="#302c2c", 
                    foreground="white",
                    labelanchor=N,
                    font=("Times", "16", "bold italic"))
frame2.grid(row=1, column=0, padx=20, pady=15, ipadx=20, ipady=20)

def viewTable():
    table_show = Toplevel()
    table_show.title("Table Frame")
    table_show.geometry("1000x600")
    table = Table(table_show, dataframe=df, showtoolbar=True, showstatusbar=True, width=1500, height=800)
    table.show()

create_table_button = CTkButton(frame2, text="Pcap Table View", command=viewTable, state=DISABLED)
create_table_button.grid(row=0, column=1, padx=30, pady=20)

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

def passwordView():
    packets = rdpcap(file_entry.get())

    logins = {"URL": [], "Login Info": []}
    for i in range(len(packets)):
        if packets[i].haslayer(http.HTTPRequest):
            url = get_url(packets[i]).decode('utf-8')
            login_info = get_login_info(packets[i])
            if login_info:
                logins['URL'].append(str(url))
                logins['Login Info'].append(login_info)

    if len(logins['URL']) == 0:
        messagebox.showerror("Error", "No login information found")
    else:
        login_dataframe = pd.DataFrame(logins)
        table_show = Toplevel()
        table_show.title("Table Frame")
        table_show.geometry("1000x600")
        table = Table(table_show, dataframe=login_dataframe, showtoolbar=True, showstatusbar=True, width=1500, height=800)
        table.show()
    
    


password_button = CTkButton(frame2, text="HTTP Passwords", command=passwordView, state=DISABLED)
password_button.grid(row=0, column=2, padx=80, pady=20)

def summarize():
    summary = Toplevel()
    summary.title("Summary")
    summary.geometry("1000x600")

    frequent_address = df['src'].describe()['top']

    filename = file_entry.get()
    packets = rdpcap(filename)
    filename = filename.split("/")
    filename = filename[-1]
    
    text = f"""
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
    summary.grid_rowconfigure(0, weight=1)
    summary.grid_columnconfigure(0, weight=1)

    # create scrollable textbox
    tk_textbox = Text(summary, highlightthickness=0)
    tk_textbox.grid(row=0, column=0, sticky="nsew")

    tk_textbox.insert(END, text)
    # create CTk scrollbar
    ctk_textbox_scrollbar = CTkScrollbar(summary, command=tk_textbox.yview)
    ctk_textbox_scrollbar.grid(row=0, column=1, sticky="ns")

    # connect textbox scroll event to CTk scrollbar
    tk_textbox.configure(yscrollcommand=ctk_textbox_scrollbar.set)



summarizer_button = CTkButton(frame2, text="Summarizer", command=summarize, state=DISABLED)
summarizer_button.grid(row=0, column=4, padx=10, pady=20)

def show_columns():
    show_cols = CTkToplevel()
    show_cols.title("Columns Names")
    cols = []
    for i in range(len(df.columns)):
        cols.append(df.columns[i])
    cols = str(cols)
    cols_label = Label(show_cols, text=cols)
    cols_label.pack()
    
view_cols = CTkButton(frame2, text="View Columns", command=show_columns, state=DISABLED)
view_cols.grid(row=3, column=2,pady=20)

def preferred_table():
    try:
        cols = choosed_cols.get()
        cols = cols.split()
        if choosed_cols.get() == "":
            messagebox.showerror("Error", "Try entering the columns name separated by space")
        else:
            ip_show = CTkToplevel()
            ip_show.title("Preferred Table")
            ip_show.geometry("1000x600")
            
            table = Table(ip_show, dataframe=df[cols], showtoolbar=True, showstatusbar=True, width=1500, height=800)
            table.show()
    except:
        messagebox.showerror("Error", "Only No Column with that name Exists! Try seeing the column names")


choosed_cols = CTkEntry(frame2, width=200)
choosed_cols.grid(row=1, column=2, padx=10, pady=10)

choosed_cols_button = CTkButton(frame2, text="Choose columns", command=preferred_table, state=DISABLED)
choosed_cols_button.grid(row=2, column=2)

        


frame3 = LabelFrame(base, 
                    highlightbackground="grey", 
                    width=730, 
                    height=50, 
                    highlightthickness=3, 
                    text="Graph Section", 
                    background="#302c2c", 
                    foreground="white",
                    labelanchor=N,
                    font=("Times", "16", "bold italic"))
frame3.grid(row=2, column=0, padx=20, pady=15, ipadx=20, ipady=20)

def choosed_graph(choice):
    global graph_type
    graph_type = choice
    return graph_type

def visualize():

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


    elif graph_type == 'Suspicious Destination':
        frequent_address = df['src'].describe()['top']
        frequent_address_df = df[df['src']==frequent_address]
        # Only display Src Address, Dst Address, and group by Payload 
        frequent_address_groupby = frequent_address_df[['src','dst','payload']].groupby("dst")['payload'].sum()

        # Plot the Frequent address is speaking to (By Payload)
        frequent_address_groupby.plot(kind='barh',title="Most Frequent Address is Speaking To (Bytes)",figsize=(10,8))

        # Which address has excahnged the most amount of bytes with most frequent address
        plt.show()


graph_drop_down = CTkOptionMenu(master=frame3, command=choosed_graph, values=['Address Sending Payloads', 'Destination Adresses (Bytes Received)', 'Source Ports (Bytes Sent)', 'Destination Ports (Bytes Received)', 'Suspicious Destination'])
graph_drop_down.set("Address Sending Payloads")
graph_drop_down.grid(row=0, column=0, padx=10, pady=20)


graph_view_button = CTkButton(frame3, text="Visaulize Graph", command=visualize, state=DISABLED)
graph_view_button.grid(row=0, column=1, padx=10, pady=20)



base.mainloop()