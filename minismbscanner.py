#!/usr/bin/env python

import smbc
import sys
import os
import argparse
import netaddr
from socket import *
from multiprocessing import Pool, Value, Lock, Manager

def smbscan(server):
    smb_obj = []
    ctx = smbc.Context()

# attempt to pull shares
    try:
        entries = ctx.opendir('smb://' + server).getdents()
        for entry in entries:
            print server
            print entry
    except:
          pass

# semaphores
#    while lock == 1:
#        contine
#    lock.value = 1
#    lock.value = 0
#    return True

smbparser = argparse.ArgumentParser(description="SMB Scaner")
smbparser.add_argument("-ip", type=str, required=True, help="IP address to scan")
smbparser.add_argument("-results_file", type=str, required=False, help="Results File")
smbparser.add_argument("-packet_rate", default=1, type=int, required=False, help="Packet rate")
smbargs = smbparser.parse_args()

if smbargs.ip is not None:

#    lock = Value(0,lock=True)
#    pool = Pool(smbargs.packet_rate)
#    results = pool.map_async(smbscan, smbargs.ip)
    results = smbscan(smbargs.ip)
    print str(results)
else:
    exit
