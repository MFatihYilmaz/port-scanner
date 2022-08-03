#!/bin/python3
import re
from scapy.all import *
import socket

def tcp_con_scan(dst_ip,dport):
    s_port=RandShort()._fix()
    paket=IP(dst=dst_ip)/TCP(sport=s_port,dport=dport,flags='S')
    rspns=sr1(paket,verbose=0,timeout=0.5)
    
    if(rspns!=None):
        if(rspns.haslayer(TCP)):
            if(rspns[TCP].flags=='SA'):
                rst=IP(dst=dst_ip)/TCP(sport=s_port,dport=dport,flags='RA')
                rst_rsp=sr1(rst,timeout=0.5,verbose=0)
                print(f"{dport} is open",end="")
                getbanner(dst_ip,dport)
            elif(rspns[TCP].flags=='R'):
                print(f"{dport} is close")
    else:
        print(f"{dport} filtered")


def syn_scan(dst_ip,dport):
    s_port=RandShort()._fix()
    paket=IP(dst=dst_ip)/TCP(sport=s_port,dport=dport,flags='S')
    rspns=sr1(paket,verbose=0,timeout=0.5)
    
    if(rspns!=None):
        if(rspns.haslayer(TCP)):
            if(rspns[TCP].flags=='SA'):
                rst=IP(dst=dst_ip)/TCP(sport=s_port,dport=dport,flags='R')
                rst_rsp=sr1(rst,timeout=0.5,verbose=0)
               
                print(f"{dport} is open",end="")
                getbanner(dst_ip,dport)
            elif(rspns[TCP].flags=='R'):
                print(f"{dport} is close")
    else:
        print(f"{dport} filtered")

def getbanner(ip,port):

    try:
        s =socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(1)
        result=s.connect_ex((ip,port))
        if(result==0):
            ans=s.recv(1024)
            print(f"--->{ans.decode('utf-8')}")
        s.close()
    except Exception:
        print("Banner Bilgisi yok")
        pass
        s.close()

print("Welcome to Per'fth'ect Scanner")
print("\n ***************************************")
patt=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
while True:
    ip=input("Please type IP address to scan:")
    newa=re.findall(patt,ip)
    if(len(newa)==0):
        continue
    else:
        control=newa[0].split(".")
    
    ctrl=0
    for i in control:
        if(int(i)>254 or int(i)<0):
            print("Invalid IP address")
            ctrl=1
    if(ctrl==0):
        break  
      
while True:
    port=input("Please type port or port range ex:'10-20 range or a port 50-':")
    patt=r"([0-9]+)-([0-9]+)"
    ports=re.findall(patt,port)
    print(ports)
    if(len(ports)!=0):
    
        if((int(ports[0][0]))>65535 or (int(ports[0][1])>65535)):
            print("Invalid port")
        else:
            break
    else:
        num=port
        break
question=input("Which scan do u use?\n1-TCP Connect Scan\n2-SYN Scanm\n")

if (len(ports)!=0 and question=="2"):
    for i in range(int(ports[0][0]),int(ports[0][1])+1):
        tcp_con_scan(ip,i)
elif(question=="1" and len(ports)!=0):
    for i in range(int(ports[0][0]),int(ports[0][1])+1):
        syn_scan(ip,i)
elif(question=="1"):
    tcp_con_scan(ip,num)
else:
    syn_scan(ip,num)