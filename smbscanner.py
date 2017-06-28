#!/usr/bin/env python

import smbc
import sys
import os
import argparse
import io
import json
import time
import netaddr
from socket import *
#from multiprocessing import Pool, Value, Lock, Manager

def smbscan(server, results_file):
    smb_obj = []
    ctx = smbc.Context()
    ts = time.time()
    print "attempting to scan " + server + '\n'    
# attempt to pull shares
    try:
        entries = ctx.opendir('smb://' + server).getdents()
        for entry in entries:
            if entry is not None:
                connector = socket(AF_INET, SOCK_STREAM)
                connector.settimeout(1)
                try:
                    connector.connect(('%s' % server, 445))
                    connector.send('Friendly Portscanner\r\n')
                    smbbg = connector.recv(2048)
                    connector.close()
                    if results_file is not None:
                        with open(results_file, 'a+') as outfile:
                            smb_data = 'host: ' + '%s' % server + '\n' + 'is_smb: true\nopen_share:' + '%s' % entry + '\n' + 'banner: ' + '%s' % smbbg + 'is_dupulsar: true\nbg_port: 445\ntimestamp: ' + '%s' % ts + '\n\n'
                            outfile.write(smb_data)
                    else:
                        print ("[+] " + '%s' % server + ": " + '%s' % entry + ", Banner Grab: " + '%s' % smbbg + ' Possible DPulsar Target = True')
                except:
                    if results_file is not None:
                        with open(results_file, 'a+') as outfile:
                            smb_data = 'host: ' + '%s' % server + '\n' + 'is_smb: true\nopen_share:' + '%s' % entry + '\n' + 'banner: closed\nis_dpulsar: false\nbg_port: 445\ntimestamp: ' + '%s' % ts + '\n\n'
                            outfile.write(smb_data)
                    else:
                        print ("[+] " + '%s' % server + ": " + '%s' % entry + ", Port 445: closed, Possible DPulsar Target = False")
            else:
                continue
    except:
          pass
#    return [server,entry,ts]
if __name__ == "__main__":    
    smbparser = argparse.ArgumentParser(description="SMB Scanner")
    smbparser.add_argument("-netrange", type=str, required=False, help="CIDR Block")
    smbparser.add_argument("-ip", type=str, required=False, help="IP address to scan")
    smbparser.add_argument("-results_file", type=str, required=False, help="Results File")
    smbparser.add_argument("-packet_rate", default=1, type=int, required=False, help="Packet rate")
    smbargs = smbparser.parse_args()
    
    if smbargs.ip is not None: 
        results = smbscan(smbargs.ip, smbargs.results_file)

    elif smbargs.netrange is not None:
        for ip in netaddr.IPNetwork(smbargs.netrange).iter_hosts():
            results = smbscan(str(ip), smbargs.results_file)
    else: 
        print "Please define either IP or Netrange." 
        exit
