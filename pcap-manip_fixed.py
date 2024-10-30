#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
from scapy.all import *


def change_pkts(ip_old, ip_new, mac_old, mac_new, port_old: int, port_new: int ,input_pcap, output_pcap):
    pkts = rdpcap(input_pcap)
    for p in pkts:
    	if p.haslayer(IP):
    		del p[IP].chksum
    		if p.haslayer(TCP):
    			del p[TCP].chksum
    		if p.haslayer(UDP):
    			del p[UDP].chksum

    for p in pkts:
    	if mac_old is not None:
	    	if p.src == mac_old:
	    		p.src = mac_new
	    	if p.dst == mac_old:
	    		p.dst = mac_new
    	if ip_old is not None:
	    	if p.haslayer(IP):
	    		if p[IP].src == ip_old:
	    			p[IP].src = ip_new
	    		if p[IP].dst == ip_old:
	    			p[IP].dst = ip_new
    	if port_old is not None:
	    	if p.haslayer(TCP):
	    		if p[TCP].sport == port_old:   			
	    			p[TCP].sport = port_new
	    		if p[TCP].dport == port_old:
	    			p[TCP].dport = port_new

    wrpcap(output_pcap, pkts)
    			



if __name__ == '__main__':
	parser = argparse.ArgumentParser(
        description="Modify a pcap"
        )
	parser.add_argument('--ip-origin', dest="arg_ip_origin", nargs='?', help='IP to match')
	parser.add_argument('--ip-new', dest="arg_ip_new", nargs='?', help='New IP')
	parser.add_argument('--mac-origin', dest="arg_mac_origin", nargs='?', help='MAC to match')
	parser.add_argument('--mac-new', dest="arg_mac_new", nargs='?', help='New MAC')
	parser.add_argument('--port-origin', dest="arg_port_origin", type=int, nargs='?', help='Port to match')
	parser.add_argument('--port-new', dest="arg_port_new", type=int, nargs='?', help='New port')
	parser.add_argument('--input', dest="arg_input", nargs='?', help='Input file')
	parser.add_argument('--output', dest="arg_output", nargs='?', help='Output file')
	args = parser.parse_args()

	change_pkts(args.arg_ip_origin, args.arg_ip_new, args.arg_mac_origin, args.arg_mac_new, args.arg_port_origin, args.arg_port_new, args.arg_input, args.arg_output)


