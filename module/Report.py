#!/usr/local/bin/python2.7
# -*- coding: utf-8 -*-

#
# parse xml report
# author: https://github.com/bGN4
#

import os
import time
import logging
import traceback
from libnmap.parser import NmapParser

class OpenvasXml:
    _root_node   = {}
    _report_node = {}
    _task_node   = {}
    _hosts_nodes = []
    _results_nodes = []
    results_num = 0
    hosts_hum  = 0
    scan_start = None
    scan_end   = None
    load_time  = 0
    def __init__(self, path):
        import xmltodict
        root  = {}
        stime = time.time()
        with open(path) as fp:
            root = xmltodict.parse( fp.read() )
        etime = time.time()
        self.load_time = int(1000*(etime-stime))
        try:
            self._root_node = root['report']
        except KeyError:
            self._root_node = root['get_reports_response']['report']
        self._report_node = self._root_node['report']
        self._task_node   = self._report_node['task']
        self._hosts_nodes = self._report_node['host']
        self._results_nodes = self._report_node['results']['result']
        self.scan_start  = self._report_node.get('scan_start')
        self.scan_end    = self._report_node.get('scan_end')
        self.results_num = len(self._results_nodes)
        self.hosts_num   = len(self._hosts_nodes)
    def get_hosts_list(self):
        return self._hosts_nodes if isinstance(self._hosts_nodes, list) else []
    def get_results_list(self):
        return self._results_nodes if isinstance(self._results_nodes, list) else []

def weak_pass_node(rid      = 0,
                   subnet   = '',
                   ip       = '',
                   service  = '',
                   port     = '',
                   protocol = '',
                   oid      = '',
                   descript = ''):
    descript = descript.rstrip().replace('\n', '\n'+' '*16)
    Template = '''
            <result id="%(rid)d">
                <detection/>
                <subnet>%(subnet)s</subnet>
                <host>%(ip)s</host>
                <port>%(service)s (%(port)s/%(protocol)s)</port>
                <nvt oid="%(oid)s">
                    <name>%(service)s weak password</name>
                    <family>Accounts</family>
                    <cvss_base>9.0</cvss_base>
                    <risk_factor>Critical</risk_factor>
                    <cve>NOCVE</cve>
                    <bid>NOBID</bid>
                    <tags>Change the password as soon as possible.</tags>
                    <cert></cert>
                    <xref>NOXREF</xref>
                </nvt>
                <threat>High</threat>
                <description>%(descript)s
                </description>
                <original_threat>High</original_threat>
                <notes></notes>
                <overrides></overrides>
            </result>\n'''
    return Template.lstrip('\n')%locals()

def parse_weak_pass_file(path, stat):
    result_lst = []
    try:
        report = NmapParser.parse_fromfile( path )
        for host in report.hosts:
            for svc in host.services:
                for script in svc.scripts_results:
                    output = script.get('output')
                    if output and ('Valid credentials' in output or 'Login Success' in output):
                        stat.host_weak = stat.host_weak + 1
                        stat.weak_list.append( '\n{}:{}{}'.format(host.address, svc.port, output) )
                        result_lst.append( weak_pass_node(stat.host_weak, host.address, host.address, svc.service, svc.port, svc.protocol, script.get('id'), script.get('output')) )
    except Exception as e:
        logging.error( 'Error in parse_weak_pass_file\n' + traceback.format_exc() )
    return result_lst

def parse_port_from_nmap_lcx(path):
    with open(path) as fp:
        return [h for x in fp.read().split('<!-- Split By Infinite bGN4 -->') for h in NmapParser.parse_fromstring(x.strip()).hosts]

def write_weak_pass_node(path, results):
    with open(path, 'a') as fp:
        for result in results:
            fp.write( result )

def write_openvas_file(path, report_id='', num=''):
    ipath = path + '.sp'
    os.renames(path, ipath)
    with open(ipath, 'r') as fpi, open(path, 'w') as fpo:
        fpo.write( ' '*0 + '<report id="%s" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" type="scan" content_type="text/xml">\n'%(report_id) )
        fpo.write( ' '*4 + '<report id="%s">\n'%(report_id) )
        fpo.write( ' '*8 + '<results max="%s" start="1">\n'%(num) )
        while True:
            data = fpi.read(65536)
            if not data: break
            fpo.write( data )
        fpo.write( ' '*8 + '</results>\n' )
        fpo.write( ' '*4 + '</report>\n' )
        fpo.write( ' '*0 + '</report>\n' )
    os.remove( ipath )

if __name__ == '__main__':
    write_openvas_file('C:/Users/Administrator/Desktop/Z0.xml', parse_weak_pass_file('C:/Users/Administrator/Desktop/Z.xml'))
    parse_port_from_nmap_lcx('D:/IDE/MyProjects/SVN/hubu/Ver2.0/module/tasks/Task-nmap-brute-20150901143431/20150901143431/110_nmap.xml')
