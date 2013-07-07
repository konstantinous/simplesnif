#!/usr/bin/env python

import socket
import struct
import binascii


tcp_flags={1:'U',2:'A',3:'P',4:'R',5:'S',6:'F',}
mysock=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0001))
while True:
    ans=mysock.recvfrom(2048)
    ethernet=ans[0][0:14]
    eth_addr=struct.unpack("!6s6s2s",ethernet)
    eth_mac_to=binascii.hexlify(eth_addr[0])
    eth_mac_from=binascii.hexlify(eth_addr[1])
    eth_proto=binascii.hexlify(eth_addr[2])
    
    print("Destination mac - {0}\nSource mac - {1} \nProto type - {2}").format(eth_mac_to,eth_mac_from,eth_proto)
    
    internet=ans[0][14:34]
    inet_header=struct.unpack("!bbhhhbbh4s4s",internet)
    ip_ver=inet_header[0]>>4
    #ip_h_legth=inet_header[0]
    ip_tos=inet_header[1]
    ip_ttl=inet_header[5]
    ip_proto=inet_header[6]
    ip_source=socket.inet_ntoa(inet_header[8])
    ip_dest=socket.inet_ntoa(inet_header[9])
    print ("ip version={0}\nip ttl={1}\nip_proto={2}\nip source addr={3}\nip dest addr={4}\n").format(ip_ver,ip_ttl,ip_proto,ip_source,ip_dest)
    
    
    tcp=ans[0][34:54]
    tcp_header=struct.unpack("!HHLLBBHHH",tcp)
    sourse_port=tcp_header[0]
    dest_port=tcp_header[1]
    seq_num=tcp_header[2]
    ack_num=tcp_header[3]
    header_length=tcp_header[4] >> 4
    flag=tcp_header[5]
    flag=bin(flag)
    flags=''
    len(flag)
    for num in range(len(flag)):
    	if flag[num]=='1':
	    flags+=tcp_flags.get(num)
    window_size=tcp_header[6]
    checksum=tcp_header[7]
    pointer=tcp_header[8]
    
    print ("tcp_header\n")
    
    print "source port={0}\ndest port={1}\nseq_num={2}\nack num={3}\nflags={4}\nheader_length={5}\nwindow size={6}\nchecksum={7}\npointer={8}\n".format(sourse_port,dest_port,seq_num,ack_num,flags,header_length,window_size,checksum,pointer)
    
    data=ans[0][54:]
    print str(data)
