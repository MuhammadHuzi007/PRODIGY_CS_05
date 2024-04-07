from telnetlib import IP
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from scapy.all import *
import threading
from PIL import Image, ImageTk
import os
import base64

sniff_comp = base64.b64decode("VGhpcyBjb2RlIGlzIGNyZWF0ZWQgYnkgSHV6YWlmYSBBbmp1bQ==").decode("utf-8")

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        log_text.insert(END, f"IP Source: {ip_src} --> IP Destination: {ip_dst} | Protocol: {protocol}\n")
        
        if packet.haslayer(TCP):
            payload_TCP = packet[TCP].payload
            log_text.insert(END, "TCP Payload data:\n")
            log_text.insert(END, f"{payload_TCP}\n")

        if packet.haslayer(UDP):
            payload_UDP = packet[UDP].payload
            log_text.insert(END, "UDP Payload data:\n")
            log_text.insert(END, f"{payload_UDP}\n")

def start_sniffing():
    log_text.delete(1.0, END)
    log_text.insert(END, "Sniffing Started\n")
    t = threading.Thread(target=sniff_packets)
    t.start()

def sniff_packets():
    sniff(prn=packet_callback, store=0)

root = Tk()
root.title("Packet Sniffer")
dir_path = os.path.dirname(os.path.realpath(__file__))

sniff_compl = Label(root, text=sniff_comp, font=("Helvetica", 8), fg="white", bg="black")
sniff_compl.pack(side=BOTTOM)
start_button = Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=10)

log_text = ScrolledText(root, width=60, height=20)
log_text.pack(padx=10, pady=10)

root.mainloop()
