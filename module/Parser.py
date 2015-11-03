#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

import os
import re
import logging
import traceback

__version__ = '1.0.0.1'
AUTHNAME = 'https://github.com/bGN4'
AUTHEMAIL = 'https://github.com/bGN4'

def Parse_hosts(hosts, Log=logging):
    try:
        Log.debug( hosts )
        assert( hosts is not None )
        all_host_set = set( hosts.replace(' ', '').split(',') )
        pre_host_set = set( host for host in all_host_set if re.search('[^\d./]', host) )
        sig_host_set = set( host for host in pre_host_set if re.search('[^\d.-]', host) )
        solve_list   = list( all_host_set - pre_host_set )
        for host in pre_host_set - sig_host_set:
            if host.count('-') == 1:
                ip_group = sorted([i.split('.') for i in host.split('-')], lambda x,y: len(y)-len(x))
                if len(ip_group[0]) == 4:
                    solve_list.append( tuple('.'.join(ip) for ip in [ip_group[0],[ip_group[0][i] for i in range(len(ip_group[0])-len(ip_group[1]))]+ip_group[1]]) )
                    continue
            Log.warn('[FAIL] Unable to recognize host:'+host)
        import iptools
        return sorted( set( ip for ranges in iptools.IpRangeList(*solve_list).ips for ip in ranges ) | sig_host_set )
    except Exception as e:
        Log.error('[FAIL] Resolve host list "%s" failed\n%s'%(hosts, traceback.format_exc()))
        return None

def Write2file(iplist, path, Log=logging):
    if not isinstance(iplist, list):
        Log.error( '[FAIL] Write IP list to {} failed, not a list:\n{}'.format(path, iplist) )
        return False
    with open(path, 'w') as fp:
        fp.write( '\n'.join(iplist) )
        Log.info( '[ OK ] Write IP list to %s'%(path) )
        return True

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    Write2file(Parse_hosts('127.0.0.1,192.168.1.1/30,10.20.1.1-10.20.1.9'), 'iplist.txt')
