# Packte_Sniffer
# Packet Sniffer in C (libpcap)

## Overview 
This project implements a basic packet sniffer in C using the Libpcap library. Captures network traffic and parses IPv4 header. 

## Fearures 
-Live packet capture 
-IPV4 header parsing 
-Display source and Destination IP addresses
-Display packets ID, TOS, TTL

## How to compile:
gcc pkt_sniff.c -o PacketSniffer -lpcap

## How to run:
./PacketSniffer

## Sample output:
ID: 1460 | SRC: 0.28.0.0 | DST: 0.0.0.0 | TOS: 0x3 | TTL: 42

## How to Improve:
-protocol filtering 
-TCP/UDP port parsing

