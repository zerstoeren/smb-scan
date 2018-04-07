#!/usr/bin/env python

import smbc
import sys
import argparse
import time
import netaddr
import threading
from smb.SMBConnection import SMBConnection
from socket import * # noqa


def smbscan(server, port, smbversion, results_file):
    sys.stdout.write("attempting to find open shares on " + server + '\n')
    #  smb_obj is needed for when we add new stuff.
    #  currently is a place holder.
    #  smb_obj = []
    ctx = smbc.Context()
# attempt to pull shares
    try:
        ts = time.strftime("%Y-%m-%d %H:%M")
        entry = ctx.opendir('smb://' + server).getdents()
        if entry is not None:
            connector = socket(AF_INET, SOCK_STREAM)  # noqa
            connector.settimeout(1)
            try:
                connector.connect(('%s' % server, 445))
                connector.send('Friendly Portscanner\r\n')
                smbbg = connector.recv(2048)
                connector.close()
                if results_file is not None:
                    with open(results_file, 'a+') as outfile:
                        smb_data = ('host: ' + '%s' % server + '\n' +
                                    'is_smb: true\nsmb_ver: ' +
                                    smbversion + '\nopen_share:' +
                                    '%s' % entry + '\n' + 'banner: ' +
                                    '%s' % smbbg +
                                    'is_dupulsar: true\nsmb_port: ' +
                                    '%s' % port + '\nbg_port: 445\ntimestamp: ' +  # noqa
                                    '%s' % ts + '\n\n')
                        outfile.write(smb_data)
                else:
                    sys.stdout.write("[+] " + '%s' % server + ": " + '%s' % entry +  # noqa
                                     ", Banner Grab: " + '%s' % smbbg +
                                     ' Possible DPulsar Target: True' +
                                     ', is_smb: True, smb_ver: ' + smbversion + '\n')  # noqa
            except:
                if results_file is not None:
                    with open(results_file, 'a+') as outfile:
                        smb_data = ('host: ' + '%s' % server + '\n' +
                                    'is_smb: true\nsmb_ver: ' + smbversion +
                                    '\nopen_share: ' +  '%s' % entry + '\n' +  # noqa
                                    'banner: closed\nis_dpulsar: false\nsmb_port: ' +  # noqa
                                    '%s' % port + '\nbg_port: 445\ntimestamp: ' +  # noqa
                                    '%s' % ts + '\n\n')
                        outfile.write(smb_data)
                else:
                    sys.stdout.write("[+] " + '%s' % server + ": " + '%s' % entry +  # noqa
                                     ", Port 445: closed, Possible DPulsar Target = False, " +  # noqa
                                     'is_smb: True, smb_ver: ' + smbversion + '\n')  # noqa
            finally:
                pass
        else:
            pass
    except:
        if results_file is not None:
            with open(results_file, 'a+') as outfile:
                smb_data = ('host: ' + '%s' % server + '\n' +
                            'is_smb: true\nsmb_ver: ' + smbversion +
                            '\nopen_share: no open shares were found. awesome!\n' +  # noqa
                            'banner: closed\nis_dpulsar: false\nsmb_port: ' +  # noqa
                            '%s' % port + '\nbg_port: 445\n' +  # noqa
                            'timestamp: ' + '%s' % ts + '\n\n')
                outfile.write(smb_data)
                pass
        else:
            sys.stdout.write("[+] " + '%s' % server + ": no open shares were found. awesome!, " +  # noqa
                             'Port 445: closed, Possible Dpulsar Target = False, ' +  # noqa
                             'is_smb: True, smb_ver: ' + smbversion + '\n')
            pass
    finally:
        pass


def smb_verify(server):
    sys.stdout.write("Validating SMB and Version for " + server + '\n')
    try:
        smbcon = SMBConnection('', '', server, '', use_ntlm_v2 = False)  # noqa
        assert smbcon.connect(server, 139)
        is_smbv2 = smbcon.isUsingSMB2
        smb_verify = smbcon.echo('EHLO', timeout=1)
        smbcon.close()
        if smb_verify == 'EHLO' and is_smbv2 is True:
            port = 139
            smbversion = 'smbv2'
            sys.stdout.write("[+] " + server + ": Device is " + smbversion + '\n')  # noqa
            smbscan(server, port, smbversion, smbargs.results_file)
        elif smb_verify == 'EHLO' and is_smbv2 is False:
            port = 139
            smbversion = 'smbv1: potential Wannacry target'
            sys.stdout.write('[+] ' + server + ': Device is ' + smbversion + '\n')  # noqa
            smbscan(server, port, smbversion, smbargs.results_file)
        else:
            pass
    except Exception, TypeError:
        if "Server does not support any of the pysmb dialects." in '%s' % TypeError: # noqa 
            print "it works"
            smbversion = 'smbv3'
            port = 139
            sys.stdout.write("[+] " + server + ": Device is " + smbversion + '\n') # noqa
            smbscan(server, port, smbversion, smbargs.results_file)
        else:
            pass
    except Exception, errorcode:
        if len(errorcode) > 1 and errorcode[1] == "Connection refused":
            sys.stdout.write("[-] " + server + ": port 139 is not SMB, trying port 445.\n")  # noqa
            try:
                smbcon = SMBConnection('', '', server, '', use_ntlm_v2 = False)  # noqa
                assert smbcon.connect(server, 445)
                is_smbv2 = smbcon.isUsingSMBv2
                smb_verify = smbcon.echo('EHLO', timeout=1)
                smbcon.close()
                if smb_verify == 'EHLO' and is_smbv2 is True:
                    port = 445
                    smbversion = 'smbv2'
                    sys.stdout.write("[+] " + server + ": Device is " + smbversion + '\n')  # noqa
                    smbscan(server, smbversion, smbargs.results_file)
                elif smb_verify == 'EHLO' and is_smbv2 is False:
                    port = 445
                    smbversion = 'smbv1: potential Wannacry target'
                    sys.stdout.write('[+] ' + server + ': Device is ' + smbversion + '\n')  # noqa
                    smbscan(server, port, smbversion, smbargs.results_file)
                else:
                    pass
            except Exception, TypeError:
                if "Server does not support any of the pysmb dialects." in '%s' % TypeError: # noqa
                    smbversion = 'smbv3'
                    port = 445
                    sys.stdout.write('[+] ' + server + ": Device is " + smbversion + '\n') # noqa
                    smbscan(server, port, smbversion, smbargs.results_file)
                else:
                    pass
            except Exception, errorcode:
                if errorcode[1] == "Connection refused":
                    sys.stdout.write('[-] ' + server + ': is_smb: False.\n')  # noqa
                    pass
            finally:
                pass
    finally:
        pass

if __name__ == "__main__":
    smbparser = argparse.ArgumentParser(description="SMB Scanner")
    smbparser.add_argument("-netrange", type=str, required=False, help="CIDR Block")  # noqa
    smbparser.add_argument("-ip", type=str, required=False, help="IP address to scan")  # noqa
    smbparser.add_argument("-results_file", type=str, required=False, help="Results File")  # noqa
    smbparser.add_argument("-target_file", type=str, required=False, help="Targets File")  # noqa
    smbparser.add_argument("-packet_rate", default=1, type=int, required=False, help="Packet rate")  # noqa
    smbargs = smbparser.parse_args()


    if smbargs.ip is not None:
        smb_verify(smbargs.ip)

    elif smbargs.netrange is not None:
        for ip in netaddr.IPNetwork(smbargs.netrange).iter_hosts():
            threads = [smbargs.packet_rate]
            smbthread = threading.Thread(target=smb_verify, args=(str(ip),))
            threads.append(smbthread)
            smbthread.start()

    elif smbargs.target_file is not None:
        with open(smbargs.target_file, mode='r', buffering=1) as targets_file:
            targets = targets_file.readlines()
            for target in targets:
                for ip in netaddr.IPNetwork(target).iter_hosts():

                    threads = [smbargs.packet_rate]
                    smbthread = threading.Thread(target=smb_verify, args=(str(ip),))
                    threads.append(smbthread)
                    smbthread.start()

    else:
        print "Please define either IP or Netrange."
        exit
