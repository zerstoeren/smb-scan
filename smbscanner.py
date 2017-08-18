#!/usr/bin/env python

import smbc
import argparse
import time
import netaddr
import threading
from smb.SMBConnection import SMBConnection
from socket import * # noqa


def smbscan(server, smbversion, results_file):
    print "attempting to find open shares on " + server + '\n'
    #  smb_obj is needed for when we add new stuff.
    #  currently is a place holder.
    #  smb_obj = []
    ctx = smbc.Context()
# attempt to pull shares
    try:
        ts = time.strftime("%Y-%m-%d %H:%M")
        entry = ctx.opendir('smb://' + server).getdents()
#        for entry in entries:
        if entry is not None:
            connector = socket(AF_INET, SOCK_STREAM)  # noqa
            connector.settimeout(1)
            try:
                connector.connect(('%s' % server, 445))
                connector.send('Friendly Portscanner\r\n')
                smbbg = connector.recv(2048)
                connector.close()
                if results_file is not None:
                    with print_lock:
                        with open(results_file, 'a+') as outfile:
                            smb_data = ('host: ' + '%s' % server + '\n' +
                                        'is_smb: ' + smbversion +
                                        '\nopen_share:' +
                                        '%s' % entry + '\n' + 'banner: ' +
                                        '%s' % smbbg +
                                        'is_dupulsar: true\nbg_port: 445\ntimestamp: ' +  # noqa
                                        '%s' % ts + '\n\n')
                            outfile.write(smb_data)
                else:
                    with print_lock:
                        print ("[+] " + '%s' % server + ": " + '%s' % entry +
                               ", Banner Grab: " + '%s' % smbbg +
                               ' Possible DPulsar Target: True' +
                               ', is_smb: ' + smbversion + '\n')
            except:
                if results_file is not None:
                    with print_lock:
                        with open(results_file, 'a+') as outfile:
                            smb_data = ('host: ' + '%s' % server + '\n' +
                                       'is_smb: ' + smbversion + '\nopen_share:' +  # noqa
                                       '%s' % entry + '\n' +
                                       'banner: closed\nis_dpulsar: false\nbg_port: 445\ntimestamp: '  # noqa
                                       + '%s' % ts + '\n\n')
                            outfile.write(smb_data)
                else:
                    with print_lock:
                        print ("[+] " + '%s' % server + ": " + '%s' % entry +
                               ", Port 445: closed, Possible DPulsar Target = False, " +  # noqa
                               'is_smb: ' + smbversion + '\n')  # noqa
            finally:
                pass
        else:
            pass
    except:
        if results_file is not None:
            with print_lock:
                with open(results_file, 'a+') as outfile:
                    smb_data = ('host: ' + '%s' % server + '\n' +
                                'is_smb: ' + smbversion +
                                '\nopen_share: no open shares were found. awesome!\n' +  # noqa
                                'banner: closed\nis_dpulsar: false\nbg_port: 445\n' +  # noqa
                                'timestamp: ' + '%s' % ts + '\n\n')
                    outfile.write(smb_data)
                    pass
        else:
            with print_lock:
                print ("[+] " + '%s' % server + ": no open shares were found. awesome!, " +  # noqa
                       'Port 445: closed, Possible Dpulsar Target = False, ' +
                       'is_smb: ' + smbversion + '\n')
                pass
    finally:
        pass


def smb_verify(server):
    print "Validating SMB and Version for " + server + '\n'
    try:
        smbcon = SMBConnection('', '', server, '', use_ntlm_v2 = False)  # noqa
        assert smbcon.connect(server, 139)
        is_smbv2 = smbcon.isUsingSMB2
        smb_verify = smbcon.echo('EHLO', timeout=1)
        smbcon.close()
        if smb_verify == 'EHLO' and is_smbv2 is True:
            smbversion = 'smbv2'
            print "[+] " + server + ": Device is " + smbversion + '\n'
            smbscan(server, smbversion, smbargs.results_file)
        elif smb_verify == 'EHLO' and is_smbv2 is False:
            smbversion = 'smbv1: potential Wannacry target'
            print '[+] ' + server + ': Device is ' + smbversion + '\n'
            smbscan(server, smbversion, smbargs.results_file)
        else:
            pass
    except Exception, errorcode:
        if errorcode[1] == "Connection refused":
            print "[-] " + server + ": port 139 is not SMB, trying port 445."
            try:
                smbcon = SMBConnection('', '', server, '', use_ntlm_v2 = False)  # noqa
                assert smbcon.connect(server, 445)
                is_smbv2 = smbcon.isUsingSMBv2
                smb_verify = smbcon.echo('EHLO', timeout=1)
                smbcon.close()
                if smb_verify == 'EHLO' and is_smbv2 is True:
                    smbversion = 'smbv2'
                    print "[+] " + server + ": Device is " + smbversion + '\n'
                    smbscan(server, smbversion, smbargs.results_file)
                elif smb_verify == 'EHLO' and is_smbv2 is False:
                    smbversion = 'smbv1: potential Wannacry target'
                    print '[+] ' + server + ': Device is ' + smbversion + '\n'
                    smbscan(server, smbversion, smbargs.results_file)
                else:
                    pass
            except Exception, errorcode:
                if errorcode[1] == "Connection refused":
                    print '[-] ' + server + ': Does not appear to be an SMB device.\n'  # noqa
                    pass
            finally:
                pass
        else:
            pass

    finally:
        pass


def thread_check(server, results_file):
    global semaphore

    try:
        #        smb_scan(server, results_file)
        smb_verify(server)
    except Exception as e:
        with print_lock:
            logger.error('Scan error at ' + server + e, exc_info=True)  # noqa
    finally:
        semaphore.release()


if __name__ == "__main__":
    smbparser = argparse.ArgumentParser(description="SMB Scanner")
    smbparser.add_argument("-netrange", type=str, required=False, help="CIDR Block")  # noqa
    smbparser.add_argument("-ip", type=str, required=False, help="IP address to scan")  # noqa
    smbparser.add_argument("-results_file", type=str, required=False, help="Results File")  # noqa
    smbparser.add_argument("-packet_rate", default=1, type=int, required=False, help="Packet rate")  # noqa
    smbargs = smbparser.parse_args()

    semaphore = threading.BoundedSemaphore(value=smbargs.packet_rate)
    print_lock = threading.Lock()

    if smbargs.ip is not None:
        #        smb_scan(smbargs.ip, smbargs.results_file)
        smb_verify(smbargs.ip)
    elif smbargs.netrange is not None:
        for ip in netaddr.IPNetwork(smbargs.netrange).iter_hosts():
            #            smb_scan(str(ip), smbargs.results_file)
            smb_verify(str(ip))
    elif smbargs.packet_rate is not None:
        for ip in netaddr.IPNetwork(smbargs.netrange).iter_hosts():
            semaphore.acquire()
            smbthread = threading.Thread(target=thread_check, args=(str(ip), smbargs.results_file))  # noqa
            smbthread.start()
            smbthread.join()

    else:
        print "Please define either IP or Netrange."
        exit
