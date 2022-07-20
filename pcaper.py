from tkinter import *
from tkinter import filedialog
from scapy.all import *


root = Tk()
root.title("PCAPED")

root.geometry("500x500")
def get_file():
    root.filename = filedialog.askopenfilename(initialdir="/home/x90/Documents/college/Year2/Programming And Algorithims/analyzed", title="Select a file")
    packets = rdpcap(root.filename)
    packets_length = Label(root, text="Total length of packet is "+ str(len(packets)))
    packets_length.grid(row=2, column=1)

myButton = Button(root, text="Open file", command=get_file)

myButton.grid(row =1 , column = 0)


root.mainloop()