#!/usr/bin python2.7
# -*- coding: utf-8 -*-

import os
import ssl
import time
import socket
import base64
import logging
import functools
from xml.etree import ElementTree

__version__ = '3.0.0.0'
#PROGRAM = sys.argv[0]
AUTHNAME = 'https://github.com/bGN4'
AUTHEMAIL = 'https://github.com/bGN4'

class OMPError(Exception):
    """Base class for OMP errors."""
    def __str__(self):
        return repr(self)

class _ErrorResponse(OMPError):
    def __init__(self, cmd, *args):
        if cmd.endswith('_response'):
            cmd = cmd[:-9]
        super(_ErrorResponse, self).__init__(cmd, *args)
        
    def __str__(self):
        return '%s %s' % self.args[1:3]

class ClientError(_ErrorResponse):
    """command issued could not be executed due to error made by the client"""
    
class ServerError(_ErrorResponse):
    """error occurred in the manager during the processing of this command"""
    
class ResultError(OMPError):
    """Get invalid answer from Server"""
    def __str__(self):
        return 'Result Error: answer from command %s is invalid' % self.args

class AuthFailedError(OMPError):
    """Authentication failed."""

def XMLNode(tag, *kids, **attrs):
    n = ElementTree.Element(tag, attrs)
    for k in kids:
        if isinstance(k, basestring):
            assert n.text is None
            n.text = k
        else:
            n.append(k)
    return n

class OMP:

    _socket   = None
    _omp_path = ''
    _host     = ''
    _port     = 0
    _verbose  = False
    _username = ''
    _password = ''
    _format   = None
    _config_file  = ''
    _pretty_print = False
    _cmd_sequence = []
    _cmd_string   = ''
    _xml = ''

    _action_task_list    = ( 'delete', 'pause', 'resume_or_start_task', 'resume_paused_task', 'resume_stopped_task', 'start', 'stop' )
    _new_del_object_list = ( 'agent', 'config', 'alert', 'filter', 'lsc_credential', 'note', 'override', 'port_list', 'port_range', 'report', 'report_format', 'schedule', 'slave', 'target', 'task' )
    _get_objects_list    = ( 'agents', 'configs', 'alerts', 'filters', 'lsc_credentials', 'notes', 'overrides', 'port_lists', 'reports', 'report_formats', 'schedules', 'slaves', 'targets', 'tasks', 'settings', 'dependencies', 'info', 'nvts', 'nvt_families', 'nvt_feed_checksum', 'preferences', 'results', 'system_reports', 'target_locators', 'version' )
    _modify_object_list  = ( 'config', 'filter', 'lsc_credential', 'note', 'override', 'report', 'report_format', 'schedule', 'target', 'task', 'setting' )

    _nvt_plugins_blacklist      = {'Buffer overflow'        : { '1.3.6.1.4.1.25623.1.0.900651'  : {'name' : 'Mini-stream CastRipper Stack Overflow Vulnerability'}},
                                   'Default Accounts'       : { '1.3.6.1.4.1.25623.1.0.103239'  : {'name' : 'SSH Brute Force Logins with default Credentials'}},
                                   'Denial of Service'      : { '1.3.6.1.4.1.25623.1.0.800327'  : {'name' : 'BreakPoint Software Hex Workshop Denial of Service vulnerability'},
                                                                '1.3.6.1.4.1.25623.1.0.100305'  : {'name' : "Dopewars Server 'REQUESTJET' Message Remote Denial of Service Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.800216'  : {'name' : 'PGP Desktop Denial of Service Vulnerability'}},
                                   'Gain a shell remotely'  : { '1.3.6.1.4.1.25623.1.0.103922'  : {'name' : 'Loadbalancer.org Enterprise VA 7.5.2 Static SSH Key'}},
                                   'General'                : { '1.3.6.1.4.1.25623.1.0.14629'   : {'name' : 'IlohaMail Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.800907'  : {'name' : 'NullLogic Groupware Multiple Vulnerabilities (Linux)'},
                                                                '1.3.6.1.4.1.25623.1.0.800904'  : {'name' : 'NullLogic Groupware Version Detection (Linux)'},
                                                                '1.3.6.1.4.1.25623.1.0.11962'   : {'name' : 'Xoops myheader.php URL Cross Site Scripting Vulnerability'}},
                                   'Privilege escalation'   : { '1.3.6.1.4.1.25623.1.0.800560'  : {'name' : 'Adobe Flash Media Server Privilege Escalation Vulnerability'}},
                                   'Product detection'      : { '1.3.6.1.4.1.25623.1.0.900355'  : {'name' : 'Bitweaver Version Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.900614'  : {'name' : 'Detecting the cubecart version'},
                                                                '1.3.6.1.4.1.25623.1.0.105162'  : {'name' : 'F5 Networks BIG-IP Webinterface Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.800612'  : {'name' : 'Foswiki Version Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.103594'  : {'name' : 'Grandstream GXP Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.800295'  : {'name' : 'Limny Version Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.103740'  : {'name' : 'Plesk  Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.103532'  : {'name' : 'Scrutinizer Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.800399'  : {'name' : 'TWiki Version Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.803979'  : {'name' : 'TYPO3 Detection'},
                                                                '1.3.6.1.4.1.25623.1.0.901001'  : {'name' : 'TikiWiki Version Detection'}},
                                   'Service detection'      : { '1.3.6.1.4.1.25623.1.0.100846'  : {'name' : "Barracuda Spam & Virus Firewall Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.800901'  : {'name' : "Clicknet CMS Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.801381'  : {'name' : "CruxSoftware Products Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.902533'  : {'name' : "Cybozu Products Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.901044'  : {'name' : "eFront Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.100911'  : {'name' : "FreeNAS Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.900256'  : {'name' : "FrontAccounting Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.900583'  : {'name' : "Fuzzylime(cms) Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.900746'  : {'name' : "geccBBlite Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.902309'  : {'name' : "Haudenschilt Family Connections CMS (FCMS) Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.20834'   : {'name' : "Inter-Asterisk eXchange Protocol Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.900744'  : {'name' : "JAG (Just Another Guestbook) Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.900352'  : {'name' : "LimeSurvey Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.100208'  : {'name' : "Name Server Daemon Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.902023'  : {'name' : "Netpet CMS Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.800779'  : {'name' : "OpenMairie Products Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.800735'  : {'name' : "phpCOIN Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.100106'  : {'name' : "phpMyFAQ Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.800557'  : {'name' : "Simple Machines Forum Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.801390'  : {'name' : "SimpNews Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.801242'  : {'name' : "sNews Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.800622'  : {'name' : "Vanilla Version Detection"},
                                                                '1.3.6.1.4.1.25623.1.0.801091'  : {'name' : "YABSoft Advanced Image Hosting Script (AIHS) Version Detection"}},
                                   'Web Servers'            : { '1.3.6.1.4.1.25623.1.0.802418'  : {'name' : "IBM WebSphere Application Server Hash Collisions DOS Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.100245'  : {'name' : "RaidenHTTPD Cross Site Scripting and Local File Include Vulnerabilities"}},
                                   'Web application abuses' : { '1.3.6.1.4.1.25623.1.0.100089'  : {'name' : "Acute Control Panel SQL Injection Vulnerability and Remote File Include Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.801414'  : {'name' : "AdPeeps 'index.php' Multiple Vulnerabilities."},
                                                                '1.3.6.1.4.1.25623.1.0.105082'  : {'name' : "ALCASAR Remote Code Execution Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.100070'  : {'name' : "AWStats 'awstats.pl' Multiple Path Disclosure Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.100177'  : {'name' : "Axigen Mail Server HTML Injection Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.805365'  : {'name' : "Balero CMS Multiple Vulnerabilities"},
                                                                '1.3.6.1.4.1.25623.1.0.100393'  : {'name' : "Barracuda IM Firewall 'smtp_test.cgi' Cross-Site Scripting Vulnerabilities"},
                                                                '1.3.6.1.4.1.25623.1.0.100847'  : {'name' : "Barracuda Networks Multiple Products 'view_help.cgi' Directory Traversal Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.805564'  : {'name' : "BigAce CMS Cross-Site Scripting Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.801151'  : {'name' : "Bigforum 'profil.php' SQL Injection Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.803791'  : {'name' : "BlogEngine.NET 'sioc.axd' Information Disclosure Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.803792'  : {'name' : "Burden 'burden_user_rememberme' Authentication Bypass Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.902611'  : {'name' : "Chyrp Multiple Directory Traversal Vulnerabilities"},
                                                                '1.3.6.1.4.1.25623.1.0.800789'  : {'name' : "CMSQlite 'index.php' SQL Injection and Directory Traversal Vulnerabilities"},
                                                                '1.3.6.1.4.1.25623.1.0.802122'  : {'name' : "Copyscape SQL Injection Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.100060'  : {'name' : "Cryptographp 'index.php' Local File Include Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.801952'  : {'name' : "DmxReady Secure Document Library SQL Injection Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.100022'  : {'name' : "Dragan Mitic Apoll 'admin/index.php' SQL Injection Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.800909'  : {'name' : "Drupal Information Disclosure Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.105935'  : {'name' : "Drupal Session Hijacking Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.800908'  : {'name' : "Drupal XSS and Code Injection Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.800616'  : {'name' : "FlashChat Role Filter Security Bypass Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.902056'  : {'name' : "FreePHPBlogSoftware 'default_theme.php' Remote File Inclusion Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.804509'  : {'name' : "Ganesha Digital Library Multiple Vulnerabilities"},
                                                                '1.3.6.1.4.1.25623.1.0.804489'  : {'name' : "GNU Bash Environment Variable Handling Shell Remote Command Execution Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.801445'  : {'name' : "Irokez CMS 'id' Parameter SQL Injection Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.103487'  : {'name' : "Kerio WinRoute Firewall Web Server Remote Source Code Disclosure Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.101008'  : {'name' : "Multiple Cross Site Scripting and SQL Injection vulnerabilities in XRMS"},
                                                                '1.3.6.1.4.1.25623.1.0.801454'  : {'name' : "NetArt Media Car Portal Multiple Cross-site Scripting Vulnerabilities"},
                                                                '1.3.6.1.4.1.25623.1.0.801518'  : {'name' : "NetArtMedia WebSiteAdmin Directory Traversal Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.800734'  : {'name' : "OpenCart SQL Injection Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.103760'  : {'name' : "OpenNetAdmin 'ona.log' File Remote PHP Code Execution Vulnerability"},
                                                                '1.3.6.1.4.1.25623.1.0.110187'  : {'name' : "PHP version smaller than 5.2.9"}}}

    _task_cache_dictionary      = {'__example_task_name__'  : {'task_id'        : '',
                                                               'target_id'      : '',
                                                               'report_id'      : '',
                                                               'port_list_id'   : '',
                                                               'status'         : '',
                                                               'progress'       : ''}}

    _targets_dictionary         = {'Localhost'                                  : 'b493b7a8-7489-11df-a3ec-002264764cea'}

    _port_lists_dictionary      = {'All IANA assigned TCP 2012-02-10'           : '33d0cd82-57c6-11e1-8ed1-406186ea4fc5',
                                   'All IANA assigned TCP and UDP 2012-02-10'   : '4a4717fe-57d2-11e1-9a26-406186ea4fc5',
                                   'All privileged TCP'                         : '492b72f4-56fe-11e1-98a7-406186ea4fc5',
                                   'All privileged TCP and UDP'                 : '5f2029f6-56fe-11e1-bb94-406186ea4fc5',
                                   'All TCP'                                    : 'fd591a34-56fd-11e1-9f27-406186ea4fc5',
                                   'All TCP and Nmap 5.51 top 100 UDP'          : '730ef368-57e2-11e1-a90f-406186ea4fc5',
                                   'All TCP and Nmap 5.51 top 1000 UDP'         : '9ddce1ae-57e7-11e1-b13c-406186ea4fc5',
                                   'Nmap 5.51 top 2000 TCP and top 100 UDP'     : 'ab33f6b0-57f8-11e1-96f5-406186ea4fc5',
                                   'OpenVAS Default'                            : 'c7e03b6c-3bbe-11e1-a057-406186ea4fc5'}

    _scan_configs_dictionary    = {'empty'                                      : '085569ce-73ed-11df-83c3-002264764cea',
                                   'Discovery'                                  : '8715c877-47a0-438d-98a3-27c7a6ab2196',
                                   'Host Discovery'                             : '2d3f051c-55ba-11e3-bf43-406186ea4fc5',
                                   'System Discovery'                           : 'bbca7412-a950-11e3-9109-406186ea4fc5',
                                   'Full and fast'                              : 'daba56c8-73ec-11df-a475-002264764cea',
                                   'Full and fast ultimate'                     : '698f691e-7489-11df-9d8c-002264764cea',
                                   'Full and very deep'                         : '708f25c4-7489-11df-8094-002264764cea',
                                   'Full and very deep ultimate'                : '74db13d6-7489-11df-91b9-002264764cea'}

    _report_formats_dictionary  = {'ARF'                                        : '910200ca-dc05-11e1-954f-406186ea4fc5',
                                   'CPE'                                        : '5ceff8ba-1f62-11e1-ab9f-406186ea4fc5',
                                   'HTML'                                       : '6c248850-1f62-11e1-b082-406186ea4fc5',
                                   'ITG'                                        : '77bd6c4a-1f62-11e1-abf0-406186ea4fc5',
                                   'LaTeX'                                      : 'a684c02c-b531-11e1-bdc2-406186ea4fc5',
                                   'NBE'                                        : '9ca6fe72-1f62-11e1-9e7c-406186ea4fc5',
                                   'PDF'                                        : 'c402cc3e-b531-11e1-9163-406186ea4fc5',
                                   'TXT'                                        : 'a3810a62-1f62-11e1-9219-406186ea4fc5',
                                   'XML'                                        : 'a994b278-1f62-11e1-96ac-406186ea4fc5'}

    def __init__(self, host=None, port=None, username=None, password=None, verbose=False, config_file=None, _format=None, pretty_print=True):
        self._socket   = None
        self._host     = '127.0.0.1' if host is None else host
        self._port     = 9390 if port is None else port
        self._omp_path = '/usr/bin/omp'
        self._verbose  = verbose
        self._username = 'admin' if username is None else username
        self._password = 'admin' if password is None else password
        self._format   = _format
        self._config_file  = config_file
        self._pretty_print = pretty_print

    def _open(self, username=None, password=None):
        if username is None:
            username = self._username
        if password is None:
            password = self._password
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket = sock = ssl.wrap_socket(sock)
        sock.connect((self._host, self._port))
        self._authenticate(username, password)

    def _close(self):
        self._socket.close()
        self._socket = None

    def _send(self, data):
        BLOCK_SIZE = 1024
        if ElementTree.iselement(data):
            #print '>>>', etree.tostring(data)
            root = ElementTree.ElementTree(data)
            root.write(self._socket, 'utf-8')
        else:
            if isinstance(data, unicode):
                data = data.encode('utf-8')
            self._socket.send(data)
        parser = ElementTree.XMLTreeBuilder()
        while True:
            res = self._socket.recv(BLOCK_SIZE)
            #print repr(res)
            parser.feed(res)
            if len(res) < BLOCK_SIZE:
                break
        root = parser.close()
        #print '<<<', etree.tostring(root)
        return root

    def _check_response2(self, response):
        status = response.get('status')
        if status is None:
            raise RunTimeError('response is missing status: %s' % ElementTree.tostring(response))
        if status.startswith('4'):
            raise ClientError(response.tag, status, response.get('status_text'))
        elif status.startswith('5'):
            raise ServerError(response.tag, status, response.get('status_text'))
        return status

    def _authenticate(self, username, password):
        request = XMLNode('authenticate',
                          XMLNode('credentials',
                                  XMLNode('username', username),
                                  XMLNode('password', password),
                                  ))
        try:
            response = self._send(request)
            self._check_response2(response)
            return response.text
            # if not status: connection closed, raise error
        except ClientError:
            raise AuthFailedError(username)

    def _xml_command(self, xml='<help/>'):
        if xml.find('<',1) != -1:
            from xml.dom import minidom
            reparsed = minidom.parseString(xml)
            logging.debug( 'XML:\n' + reparsed.toprettyxml(indent="  " , encoding="utf-8")[39:].strip() )
        self._open()
        response = self._send(xml)
        self._close()
        return response

    def _generate(self, xml='<help/>'):
        assert( isinstance(xml, str) )
        self._cmd_sequence = ['omp']
        self._cmd_sequence.extend( ['-h', self._host] )
        self._cmd_sequence.extend( ['-p', str(self._port)] )
        self._cmd_sequence.extend( ['-u', self._username] )
        self._cmd_sequence.extend( ['-w', self._password] )
        if( self._verbose ):      self._cmd_sequence.append('-v')
        if( self._pretty_print ): self._cmd_sequence.append('-i')
        self._cmd_string = functools.reduce(lambda x,y: x+' '+y, self._cmd_sequence) + ' -X ' + '"' + xml.replace('"', "'") + '"'
        self._cmd_sequence.extend(['-X', xml])

    def _cmd_execute(self, xml='<help/>'):
        xml = xml.strip()
        self._generate( xml )
        if xml.find('<',1) != -1:
            from xml.dom import minidom
            reparsed = minidom.parseString(xml)
            logging.debug( 'XML:\n' + reparsed.toprettyxml(indent="  " , encoding="utf-8")[39:].strip() )
        import subprocess
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
        except AttributeError as e:
            si = None
        logging.debug( self._cmd_sequence )
        str_stdout, str_stderr = subprocess.Popen(self._cmd_sequence, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=si).communicate()
        logging.debug( 'len(str_stdout)=%d, len(str_stderr)=%d'%(len(str_stdout), len(str_stderr)) )
        try:
            parsed = ElementTree.XML( str_stdout )
        except ElementTree.ParseError:
            logging.error( '[FAIL] Parse response error !!!' )
            logging.debug( 'stdout:\n' + str_stdout )
            logging.debug( 'stderr:\n' + str_stderr )
            return None
        return parsed

    def _download_reports_easy(self, report_id, format_id, ToDisk=None):
        cmd_str = 'omp'
        cmd_str = cmd_str + ' -h ' + self._host
        cmd_str = cmd_str + ' -p ' + str(self._port)
        cmd_str = cmd_str + ' -u ' + self._username
        cmd_str = cmd_str + ' -w ' + self._password
        cmd_str = cmd_str + ' --get-report ' + report_id
        cmd_str = cmd_str + ' --format ' + format_id
        cmd_str = cmd_str + ' > ' + ToDisk

    def _download_reports(self, xml='<help/>', ToDisk=None):
        assert( isinstance(ToDisk, str) )
        self._generate( xml )
        import subprocess
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
        except AttributeError as e:
            si = None
        logging.debug('Download report to %s'%(ToDisk))
        tmpToDisk = ToDisk + '.tmp'
        with open(tmpToDisk, 'wb+') as temp_file, open(ToDisk, 'wb') as dest_file:
            logging.debug( self._cmd_sequence )
            subprocess.Popen(self._cmd_sequence, stdout=temp_file, startupinfo=si).communicate()
            temp_file.seek(0)
            logging.debug('omp exit, parse response ...')
            try:
                parsed = ElementTree.parse( temp_file )
            except ElementTree.ParseError:
                parsed = None
                logging.error( '[FAIL] Parse response error !!!' )
            if isinstance(parsed, ElementTree.ElementTree):
                report = parsed.find('report')
                parsed = parsed.getroot()
                if isinstance(report, ElementTree.Element):
                    logging.debug('begin base64 decode ...')
                    import base64, StringIO
                    base64_str = StringIO.StringIO( report.text )
                    base64.decode(base64_str, dest_file)
                    logging.info('[ OK ] base64 decode OK')
                    report.text = ''
        logging.info('[ OK ] Save report file to %s'%(ToDisk))
        if os.path.isfile( tmpToDisk ):
            try:
                os.unlink( tmpToDisk )
            except Exception as e:
                logging.error('[FAIL] Unlink file %s with %s: %s'%(tmpToDisk, e.__class__.__name__, str(e.args)))
        return parsed

    def _check_response(self, name, result_et, object_='', status='200'):
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == status:
                object_id = result_et.get('id')
                if object_id:
                    if name not in self._task_cache_dictionary:
                        self._task_cache_dictionary[name] = {}
                    self._task_cache_dictionary[name]['%s_id'%(object_)] = object_id
                    logging.info( '[ OK ] create %s_id=%s'%(object_, object_id) )
                    return object_id
            logging.error( list(result_et.items()) )
        return None

    def _create_object(self, object_='', name=None, comment=None):
        assert( object_ in self._new_del_object_list )
        return self._modify_object(object_, '_create_', name, comment)

    def _delete_object(self, object_='', object_id='', ultimate=True):
        assert( object_ in self._new_del_object_list and isinstance(object_id, str) and object_id )
        xml_template = '''<delete_%s %s_id="%s" ultimate="%d"/>''' % (object_, object_, object_id, ultimate)
        result_et = self._cmd_execute( xml_template )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                logging.info( '[ OK ] delete %s_id=%s %s'%(object_, object_id, 'permanently' if ultimate else 'to trashcan') )
                return True
            elif result_et.get('status') == '202' and result_et.get('status_text') == 'OK, request submitted':
                logging.warn( list(result_et.items()) )
                return False
            else:
                logging.error( list(result_et.items()) )
        return None

    def _get_objects(self, objects_='', object_id='', actions=None, filter_=None, filt_id=None, details=None, trash=None, sort_order='descending', sort_field=None):
        assert( objects_ in self._get_objects_list and isinstance(object_id, str) )
        get_objects = ElementTree.Element('get_%s'%(objects_))
        if object_id: get_objects.attrib['%s_id'%(objects_[:-1] if objects_.endswith('s') else objects_)] = object_id
        if details is True: get_objects.attrib['details'] = '%d'%(True)
        if isinstance(sort_order, str) and isinstance(sort_field, str) and sort_field:
            get_objects.attrib['sort_order'] = 'descending' if sort_order == 'descending' else 'ascending'
            get_objects.attrib['sort_field'] = sort_field
        return get_objects

    def _modify_object(self, object_='', object_id='', name=None, comment=None):
        assert( object_id and ( object_id == '_create_' or object_ in self._modify_object_list ) )
        modify_object = ElementTree.Element('%s_%s'%('create'if(object_id=='_create_')else'modify', object_))
        if object_id != '_create_':
            modify_object.attrib['%s_id'%(object_)] = object_id
        if name    is not None: ElementTree.SubElement(modify_object, 'name').text = name
        if comment is not None: ElementTree.SubElement(modify_object, 'comment').text = comment
        return modify_object

    def get_settings(self, setting_id='', filter_=None, first=None, max_=None, sort_order='descending', sort_field=None):
        get_settings_et = self._get_objects('settings', setting_id, None, filter_, None, None, None, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_settings_et) )

    def get_dependencies(self, nvt_oid=''):
        pass

    def get_info(self, info_id='', filter_=None, filt_id=None, details=None, type_=None, name=None):
        get_info_et = self._get_objects('info', info_id, None, filter_, filt_id, details, None, None, None)
        #result_et = self._cmd_execute( ElementTree.tostring(get_info_et) )

    def get_nvts(self, nvt_oid='', actions=None, details=None, sort_order='descending', sort_field=None, config_id=None, preferences=None, preference_count=None, timeout=None, family=None):
        get_nvts_et = self._get_objects('nvts', nvt_oid, actions, None, None, details, None, sort_order, sort_field)
        if preferences      is True: get_nvts_et.attrib['preferences']      = '%d'%(True)
        if preference_count is True: get_nvts_et.attrib['preference_count'] = '%d'%(True)
        if timeout          is True: get_nvts_et.attrib['timeout']          = '%d'%(True)
        if config_id    is not None: get_nvts_et.attrib['config_id']        = config_id
        if family       is not None: get_nvts_et.attrib['family']           = family
        result_et = self._cmd_execute( ElementTree.tostring(get_nvts_et) )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                result_dict = {}
                for nvt_et in result_et.findall('nvt'):
                    name_   = nvt_et.find('name')
                    oid_    = nvt_et.get('oid')
                    result_dict[nvt_et.get('oid')] = name_.text if name_ is not None else None
                return result_dict
            logging.error( list(result_et.items()) )
        return None

    def get_nvt_families(self, sort_order=None):
        pass

    def get_nvt_feed_checksum(self, algorithm=None):
        pass

    def get_preferences(self, nvt_oid=None, config_id=None, preference=None):
        pass

    def get_results(self, result_id='', task_id=None, notes=None, note_details=None, overrides=None, override_details=None, apply_overrides=None):
        get_results_et = self._get_objects('results', result_id, None, None, None, None, None, None, None)
        #result_et = self._cmd_execute( ElementTree.tostring(get_results_et) )

    def get_system_reports(self, slave_id=None, name=None, duration=None, brief=False):
        get_system_reports_et = ElementTree.Element('get_system_reports')
        if name     and isinstance(name, str):     get_system_reports_et.attrib['name']     = name
        if slave_id and isinstance(slave_id, str): get_system_reports_et.attrib['slave_id'] = slave_id
        if isinstance(duration, int):              get_system_reports_et.attrib['duration'] = '%d'%(duration)
        if brief is True:                          get_system_reports_et.attrib['brief']    = '%d'%(True)
        result_et = self._cmd_execute( ElementTree.tostring(get_system_reports_et) )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                result_dict = {}
                for system_report in result_et.findall('system_report'):
                    name_   = system_report.find('name')
                    title   = system_report.find('title')
                    report  = system_report.find('report')
                    if name_ is not None and name_.text and report is not None and report.text:
                        format_   = report.get('format')
                        duration_ = report.get('duration')
                        result_dict[name_.text] = {}
                        if title is not None and title.text:
                            result_dict[name_.text]['title'] = title.text
                        if format_:
                            result_dict[name_.text]['format'] = format_
                        if duration_:
                            result_dict[name_.text]['duration'] = duration_
                        report_text_list = report.text.split('\n\n')
                        if len(report_text_list)==4 and report_text_list[2] == '/proc/meminfo:':
                            try:
                                result_dict[name_.text]['report'] = [tuple([y.strip() for y in x.split(':')]) for x in report_text_list[1].splitlines() + report_text_list[3].splitlines()]
                                continue
                            except ValueError as e:
                                logging.warn('ValueError: '+str(e.args))
                        result_dict[name_.text]['report'] = report.text
                logging.debug( result_dict )
                return result_dict
            logging.error( list(result_et.items()) )
        return None

    def get_target_locators(self):
        pass

    def get_version(self):
        result_et = self._cmd_execute('<get_version/>')
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                version = result_et.find('version')
                if version is not None:
                    return version.text.strip()
        return None

    def get_agents(self, agent_id='', filter_=None, filt_id=None, trash=None, format_=None, sort_order='descending', sort_field=None):
        get_agents_et = self._get_objects('agents', agent_id, None, filter_, filt_id, None, trash, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_agents_et) )

    def delete_agent(self, agent_id='', ultimate=True):
        return self._delete_object('agent', agent_id, ultimate)

    def get_configs(self, config_id='', actions=None, trash=None, export=None, families=None, preferences=None, sort_order='descending', sort_field=None):
        get_configs_et = self._get_objects('configs', config_id, actions, None, None, None, trash, sort_order, sort_field)
        result_et    = self._cmd_execute( ElementTree.tostring(get_configs_et) )
        result_dict  = {}
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                for item in result_et.findall('config'):
                    name              = item.find('name')
                    comment           = item.find('comment')
                    creation_time     = item.find('creation_time')
                    modification_time = item.find('modification_time')
                    config_id_        = item.get('id')
                    if config_id_ and name is not None:
                        result_dict[name.text.strip()] = {'config_id':config_id_.strip()}
                return result_dict
            elif result_et.get('status') == '404':
                return result_dict
            logging.error( list(result_et.items()) )
        return None

    def create_config(self, name, comment=None, copy=None, rcfile=None, response=None):
        create_config_et = self._create_object('config', name, comment);
        if copy     is not None: ElementTree.SubElement(create_config_et, 'copy').text = copy
        if rcfile   is not None: ElementTree.SubElement(create_config_et, 'rcfile').text = rcfile
        if response is not None: pass
        result_et = self._cmd_execute( ElementTree.tostring(create_config_et) )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '201':
                config_id = result_et.get('id')
                if config_id:
                    self._scan_configs_dictionary[name] = config_id
                    logging.info( '[ OK ] create config_id={}'.format(config_id) )
                    return config_id
            logging.error( list(result_et.items()) )
        return None

    def modify_config(self, config_id, preference=None, family=None, nvt=None, name=None, comment=None):
        modify_config_et = self._modify_object('config', config_id, name, comment)
        if isinstance(preference, dict):
            preference_et = ElementTree.SubElement(modify_config_et, 'preference')
            ElementTree.SubElement(preference_et, 'nvt').attrib['oid'] = preference.get('oid')
            ElementTree.SubElement(preference_et, 'name').text = preference.get('name')
            ElementTree.SubElement(preference_et, 'value').text = preference.get('value')
        if isinstance(family, dict):
            family_selection_et = ElementTree.SubElement(modify_config_et, 'family_selection')
            ElementTree.SubElement(family_selection_et, 'growing').text = family.get('growing')
            for item in family.get('family'):
                family_et = ElementTree.SubElement(family_selection_et, 'family')
                ElementTree.SubElement(family_et, 'name').text = item.get('name')
                ElementTree.SubElement(family_et, 'all').text = item.get('all')
                ElementTree.SubElement(family_et, 'growing').text = item.get('growing')
        if isinstance(nvt, dict):
            nvt_selection_et = ElementTree.SubElement(modify_config_et, 'nvt_selection')
            ElementTree.SubElement(nvt_selection_et, 'family').text = nvt.get('family')
            for item in nvt.get('nvt'):
                ElementTree.SubElement(nvt_selection_et, 'nvt').attrib['oid'] = item.get('oid')
        result_et = self._xml_command( ElementTree.tostring(modify_config_et) )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                logging.info( '[ OK ] modify config_id={}'.format(config_id) )
                return config_id
            logging.error( list(result_et.items()) )
        return None

    def delete_config(self, config_id='', ultimate=True):
        return self._delete_object('config', config_id, ultimate)

    def get_alerts(self, alert_id='', filter_=None, trash=None, sort_order='descending', sort_field=None):
        get_alerts_et = self._get_objects('alerts', alert_id, None, filter_, None, None, trash, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_alerts_et) )

    def delete_alert(self, alert_id='', ultimate=True):
        return self._delete_object('alert', alert_id, ultimate)

    def get_filters(self, filter_id='', actions=None, filter_=None, filt_id=None, trash=None, alerts=None):
        get_filters_et = self._get_objects('filters', filter_id, actions, filter_, filter_id, None, trash, None, None)
        #result_et = self._cmd_execute( ElementTree.tostring(get_filters_et) )

    def delete_filter(self, filter_id='', ultimate=True):
        return self._delete_object('filter', filter_id, ultimate)

    def get_lsc_credentials(self, lsc_credential_id='', actions=None, trash=None, format_=None, sort_order='descending', sort_field=None):
        get_lsc_credentials_et = self._get_objects('lsc_credentials', lsc_credential_id, actions, None, None, None, trash, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_lsc_credentials_et) )

    def delete_lsc_credential(self, lsc_credential_id='', ultimate=True):
        return self._delete_object('lsc_credential', lsc_credential_id, ultimate)

    def get_notes(self, note_id='', filter_=None, filt_id=None, nvt_oid=None, task_id=None, details=None, result=None, sort_order='descending', sort_field=None):
        get_notes_et = self._get_objects('notes', note_id, None, filter_, filt_id, details, None, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_notes_et) )

    def delete_note(self, note_id='', ultimate=True):
        return self._delete_object('note', note_id, ultimate)

    def get_overrides(self, override_id='', filter_=None, filt_id=None, nvt_oid=None, task_id=None, details=None, result=None, sort_order='descending', sort_field=None):
        get_overrides_et = self._get_objects('overrides', override_id, None, filter_, filt_id, details, None, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_overrides_et) )

    def delete_override(self, override_id='', ultimate=True):
        return self._delete_object('override', override_id, ultimate)

    def get_port_lists(self, port_list_id='', targets=True, details=None, trash=None, sort_order='descending', sort_field=None):
        get_port_lists_et = self._get_objects('port_lists', port_list_id, None, None, None, details, trash, sort_order, sort_field)
        if isinstance(targets, bool): get_port_lists_et.attrib['targets'] = '%d'%(targets)
        result_et = self._cmd_execute( ElementTree.tostring(get_port_lists_et) )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                result_dict = {}
                for item in result_et.findall('port_list'):
                    name          = item.find('name')
                    targets_      = item.find('targets')
                    port_list_id_ = item.get('id')
                    if port_list_id_ and name is not None and name.text:
                        result_dict[name.text.strip()] = {'port_list_id':port_list_id_.strip()}
                        if targets_ is not None:
                            result_dict[name.text.strip()]['targets'] = {}
                            for target_ in targets_.findall('target'):
                                target_name = target_.find('name')
                                target_id_  = target_.get('id')
                                if target_id_ and target_name is not None and target_name.text:
                                    result_dict[name.text.strip()]['targets'][target_id_] = target_name.text
                result_str = ''
                for key in result_dict:
                    result_str += '\n%36s  %s'%(result_dict[key].get('port_list_id'), key)
                logging.info( '[ OK ] get_port_lists%s (Total:%d)'%(' port_list_id=%s'%(port_list_id) if port_list_id else '', len(result_dict)) )
                logging.debug( 'get_port_lists%s %s'%(' port_list_id=%s'%(port_list_id) if port_list_id else '', result_str) )
                return result_dict
            logging.error( list(result_et.items()) )
        return None

    def create_port_list(self, name='', comment=None, port_range=None, get_port_lists_response=None):
        create_port_list_et = self._create_object('port_list', name, comment);
        if port_range              is not None: ElementTree.SubElement(create_port_list_et, 'port_range').text = port_range
        if get_port_lists_response is not None: pass
        return self._check_response(name, self._cmd_execute( ElementTree.tostring(create_port_list_et) ), 'port_list', '201')

    def delete_port_list(self, port_list_id='', ultimate=True):
        return self._delete_object('port_list', port_list_id, ultimate)

    def delete_port_range(self, port_range_id='', ultimate=True):
        return self._delete_object('port_range', port_range_id, ultimate)

    def get_reports(self,
                    report_id           = '',
                    format_id           = _report_formats_dictionary.get('XML'),
                    type_               = None,
                    alert_id            = None,
                    first_result        = 1,
                    max_results         = None,
                    filter_             = None,
                    filt_id             = None,
                    sort_order          = 'descending',
                    sort_field          = None,
                    levels              = None,
                    search_phrase       = None,
                    min_cvss_base       = None,
                    notes               = True,
                    note_details        = None,
                    overrides           = True,
                    override_details    = None,
                    result_hosts_only   = True,
                    host                = None,
                    host_first_result   = None,
                    host_max_results    = None,
                    host_levels         = None,
                    pos                 = None,
                    delta_report_id     = None,
                    delta_states        = None,
                    autofp              = 0,
                    show_closed_cves    = False,
                    ToDisk              = None):
        get_reports_et = self._get_objects('reports', report_id, None, filter_, filt_id, None, None, sort_order, sort_field)
        if format_id: get_reports_et.attrib['format_id'] = format_id
        if isinstance(first_result     ,  int): get_reports_et.attrib['first_result']      = '%d'%(first_result)
        if isinstance(max_results      ,  int): get_reports_et.attrib['max_results']       = '%d'%(max_results)
        if isinstance(autofp           ,  int): get_reports_et.attrib['autofp']            = '%d'%(autofp)
        if isinstance(notes            , bool): get_reports_et.attrib['notes']             = '%d'%(notes)
        if isinstance(overrides        , bool): get_reports_et.attrib['overrides']         = '%d'%(overrides)
        if isinstance(result_hosts_only, bool): get_reports_et.attrib['result_hosts_only'] = '%d'%(overrides)
        if isinstance(show_closed_cves , bool): get_reports_et.attrib['show_closed_cves']  = '%d'%(show_closed_cves)
        result_et = self._cmd_execute( ElementTree.tostring(get_reports_et) )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                report = result_et.find('report')
                if isinstance(report, ElementTree.Element):
                    content_type = report.get('content_type')
                    if format_id==self._report_formats_dictionary.get('XML'):
                        if isinstance(ToDisk, str):
                            ElementTree.ElementTree(report).write(ToDisk)
                    else:
                        if isinstance(ToDisk, str):
                            text = report.text.decode('base64')
                            with open(ToDisk, 'wb') as dest_file:
                                dest_file.write( text )
                    logging.info( 'get_report %s %s'%('content_type=%s'%(content_type) if content_type is not None else '', 'location=%s'%(ToDisk) if isinstance(ToDisk, str) else '') )
                return True
            logging.error( list(result_et.items()) )
        return False

    def delete_report(self, report_id='', ultimate=True):
        return self._delete_object('report', report_id, ultimate)

    def get_report_formats(self, report_format_id='', trash=None, export=None, params=None, sort_order='descending', sort_field=None):
        get_report_formats_et = self._get_objects('report_formats', report_format_id, None, None, None, None, trash, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_report_formats_et) )

    def delete_report_format(self, report_format_id='', ultimate=True):
        return self._delete_object('report_format', report_format_id, ultimate)

    def get_schedules(self, schedule_id='', details=None, trash=None, sort_order='descending', sort_field=None):
        get_schedules_et = self._get_objects('schedules', schedule_id, None, None, None, details, trash, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_schedules_et) )

    def delete_schedule(self, schedule_id='', ultimate=True):
        return self._delete_object('schedule', schedule_id, ultimate)

    def get_slaves(self, slave_id='', trash=None, tasks=None, sort_order='descending', sort_field=None):
        get_slaves_et = self._get_objects('slaves', slave_id, None, None, None, None, trash, sort_order, sort_field)
        #result_et = self._cmd_execute( ElementTree.tostring(get_slaves_et) )

    def delete_slave(self, slave_id='', ultimate=True):
        return self._delete_object('slave', slave_id, ultimate)

    def get_targets(self, target_id='', actions=None, filter_=None, filt_id=None, trash=None, tasks=True, sort_order='descending', sort_field=None):
        get_targets_et = self._get_objects('targets', target_id, actions, filter_, filt_id, None, trash, sort_order, sort_field)
        if isinstance(tasks, bool): get_targets_et.attrib['tasks'] = '%d'%(tasks)
        result_et = self._cmd_execute( ElementTree.tostring(get_targets_et) )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                result_dict = {}
                for item in result_et.findall('target'):
                    name          = item.find('name')
                    hosts         = item.find('hosts')
                    port_list     = item.find('port_list')
                    tasks_        = item.find('tasks')
                    target_id_    = item.get('id')
                    port_list_id_ = None if port_list is None else port_list.get('id')
                    if target_id_ and port_list_id_ and name is not None and port_list is not None and name.text:
                        result_dict[name.text.strip()] = {'target_id':target_id_.strip(), 'port_list_id':port_list_id_.strip()}
                        if hosts is not None and hosts.text:
                            result_dict[name.text.strip()]['hosts'] = hosts.text
                        if tasks_ is not None:
                            result_dict[name.text.strip()]['tasks'] = {}
                            for task_ in tasks_.findall('task'):
                                task_name = task_.find('name')
                                task_id_  = task_.get('id')
                                if task_id_ and task_name is not None and task_name.text:
                                    result_dict[name.text.strip()]['tasks'][task_id_] = task_name.text
                result_str = ''
                for key in result_dict:
                    result_str += '\n%36s  %36s  %s'%(result_dict[key].get('target_id'), result_dict[key].get('port_list_id'), key)
                logging.info( '[ OK ] get_targets%s (Total:%d)'%(' targets_id=%s'%(target_id) if target_id else '', len(result_dict)) )
                logging.debug( 'get_targets%s %s'%(' targets_id=%s'%(target_id) if target_id else '', result_str) )
                return result_dict
            logging.error( list(result_et.items()) )
        return None

    def create_target(self, hosts=None, port_list_id=None, ssh_lsc_credential_id=None, smb_lsc_credential_id=None, target_locator_username=None, target_locator_password=None, name='', comment=None, copy=None, port_range=None):
        create_target_et = self.modify_target('_create_', hosts, port_list_id, None, smb_lsc_credential_id, target_locator_username, target_locator_password, name, comment)
        return self._check_response(name, self._cmd_execute( ElementTree.tostring(create_target_et) ), 'target', '201')

    def modify_target(self, target_id ='', hosts=None, port_list_id=None, ssh_lsc_credential_id=None, smb_lsc_credential_id=None, target_locator_username=None, target_locator_password=None, name=None, comment=None):
        modify_target_et = self._modify_object('target', target_id, name, comment)
        if hosts        is not None: ElementTree.SubElement(modify_target_et, 'hosts').text = hosts
        if port_list_id is not None: ElementTree.SubElement(modify_target_et, 'port_list', {'id':port_list_id})
        if target_id == '_create_': return modify_target_et
        #result_et = self._cmd_execute( ElementTree.tostring(modify_target_et) )
        return True

    def delete_target(self, target_id ='', ultimate=True):
        return self._delete_object('target', target_id, ultimate)

    def get_tasks(self,
                  task_id               = '',
                  actions               = None,
                  details               = None,
                  trash                 = None,
                  rcfile                = None,
                  apply_overrides       = None,
                  sort_order            = 'descending',
                  sort_field            = None):
        get_tasks_et = self._get_objects('tasks', task_id, actions, None, None, details, trash, sort_order, sort_field)
        result_et    = self._cmd_execute( ElementTree.tostring(get_tasks_et) )
        result_dict  = {}
        result_str   = ''
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                for item in result_et.findall('task'):
                    name     = item.find('name')
                    status   = item.find('status')
                    progress = item.find('progress')
                    task_id_ = item.get('id')
                    if task_id_ and name is not None and status is not None and progress is not None and name.text and status.text and progress.text:
                        result_dict[name.text.strip()] = {'task_id':task_id_.strip(), 'status':status.text.strip(), 'progress':progress.text.strip()}
                for k, v in result_dict.items():
                    result_str += '\n%36s  %-16s  %3s  %5s'%(v.get('task_id'), v.get('status'), v.get('progress'), k)
                logging.info( '[ OK ] get_tasks%s'%(' task_id=%s'%(result_str[1:]) if task_id else ' (Total:%d)'%(len(result_dict))) )
                logging.debug( 'get_tasks%s %s'%(' task_id=%s'%(task_id) if task_id else '', result_str) )
                return result_dict
            elif result_et.get('status') == '404':
                return result_dict
            logging.error( list(result_et.items()) )
        return None

    def create_task(self,
                    config_id           = _scan_configs_dictionary.get('empty'),
                    target_id           = '',
                    alert_id            = None,
                    schedule_id         = None,
                    slave_id            = None,
                    observers           = None,
                    pref_max_checks     = 8,
                    pref_max_hosts      = 20,
                    pref_in_assets      = True,
                    rcfile              = None,
                    name                = '',
                    comment             = None):
        create_task_et = self.modify_task('_create_', alert_id, schedule_id, slave_id, observers, pref_max_checks, pref_max_hosts, pref_in_assets, rcfile, name, comment, None, None)
        if config_id: ElementTree.SubElement(create_task_et, 'config', {'id':config_id})
        if target_id: ElementTree.SubElement(create_task_et, 'target', {'id':target_id})
        return self._check_response(name, self._cmd_execute( ElementTree.tostring(create_task_et) ), 'task', '201')

    def modify_task(self,
                    task_id             = '',
                    alert_id            = None,
                    schedule_id         = None,
                    slave_id            = None,
                    observers           = None,
                    pref_max_checks     = None,
                    pref_max_hosts      = None,
                    pref_in_assets      = None,
                    rcfile              = None,
                    name                = None,
                    comment             = None,
                    file_name           = None,
                    file_action         = None):
        modify_task_et = self._modify_object('task', task_id, name, comment)
        if isinstance(pref_max_checks, int) or isinstance(pref_max_hosts, int) or isinstance(pref_in_assets, bool):
            preferences_et = ElementTree.SubElement(modify_task_et, 'preferences')
            if isinstance(pref_max_checks, int):
                preference_et = ElementTree.SubElement(preferences_et, 'preference')
                ElementTree.SubElement(preference_et , 'scanner_name').text = 'max_checks'
                ElementTree.SubElement(preference_et , 'value').text = '%d'%(pref_max_checks)
            if isinstance(pref_max_hosts,  int):
                preference_et = ElementTree.SubElement(preferences_et, 'preference')
                ElementTree.SubElement(preference_et , 'scanner_name').text = 'max_hosts'
                ElementTree.SubElement(preference_et , 'value').text = '%d'%(pref_max_hosts)
            if isinstance(pref_in_assets, bool):
                preference_et = ElementTree.SubElement(preferences_et, 'preference')
                ElementTree.SubElement(preference_et , 'scanner_name').text = 'in_assets'
                ElementTree.SubElement(preference_et , 'value').text = 'no' if pref_in_assets==False else 'yes'
        if task_id == '_create_': return modify_task_et
        #result_et = self._cmd_execute( ElementTree.tostring(modify_task_et) )
        return True

    def delete_task(self, task_id ='', ultimate=True):
        return self._delete_object('task', task_id, ultimate)

    def _action_task(self, action='start', task_id='', name=None):
        if name is not None and name in self._task_cache_dictionary:
            task_id = self._task_cache_dictionary[name].get('task_id')
        assert( task_id and action in self._action_task_list )
        xml_template = '''<%s_task task_id="%s"/>''' % (action, task_id)
        result_et = self._cmd_execute( xml_template )
        result = {}
        if isinstance(result_et, ElementTree.Element):
            status = result_et.get('status')
            result['status'] = status
            if status == '200' or status == '202':
                report_id_et = result_et.find('report_id')
                report_id = report_id_et.text if isinstance(report_id_et, ElementTree.Element) and report_id_et.text else ''
                if report_id:
                    if name is not None and name in self._task_cache_dictionary:
                        self._task_cache_dictionary[name]['report_id'] = report_id
                    result['report_id'] = report_id
                logging.info( '[ OK ] %s_task status=%s task_id=%s %s %s'%(action, status, task_id, 'name=%s'%(name) if name is not None else '', 'report_id=%s'%(report_id) if report_id else '') )
                return result
            logging.error( list(result_et.items()) )
        return result

    def pause_task(self, task_id=''):
        return self._action_task('pause', task_id)

    def resume_or_start_task(self, task_id=''):
        return self._action_task('resume_or_start_task', task_id)

    def resume_paused_task(self, task_id=''):
        return self._action_task('resume_paused_task', task_id)

    def resume_stopped_task(self, task_id=''):
        return self._action_task('resume_stopped_task', task_id)

    def start_task(self, task_id='', name=None):
        return self._action_task('start', task_id, name).get('report_id')

    def stop_task(self, task_id=''):
        return self._action_task('stop', task_id).get('status')

    def empty_trashcan(self):
        result_et = self._cmd_execute( '<empty_trashcan/>' )
        if isinstance(result_et, ElementTree.Element):
            if result_et.get('status') == '200':
                logging.info( '[ OK ] empty trashcan' )
                return True
            logging.error( '[FAIL] empty trashcan' )
            logging.debug( list(result_et.items()) )
            return False
        return None

    def WaitForTask(self, task_id='', wait_status='Stopped', times=10, sleep=1):
        assert( task_id and wait_status in ('Deleted', 'Running', 'Stopped', 'Paused') and isinstance(times, int) and isinstance(sleep, int) and times>0 and sleep>0 )
        for i in range(times):
            result_dict = self.get_tasks(task_id)
            if not isinstance(result_dict, dict):
                break
            if len(result_dict)==0 and wait_status == 'Deleted':
                logging.info( '[ OK ] task(id=%s) is not in the task list'%(task_id) )
                return True
            elif len(result_dict)!=1:
                break
            else:
                task_status = list(result_dict.items())[0][1].get('status')
                if wait_status == 'Deleted':
                    if task_status == 'Ultimate Delete Requested' or task_status == 'Delete Requested':
                        pass
                    else:
                        break
                if wait_status == 'Running':
                    if task_status == 'Running':
                        logging.info( '[ OK ] task(id=%s) is Running'%(task_id) )
                        return True
                    elif task_status in ('Requested', 'Resume Requested'):
                        pass
                    else:
                        break
                elif wait_status == 'Stopped':
                    if task_status == 'Stopped':
                        logging.info( '[ OK ] task(id=%s) is Stopped'%(task_id) )
                        return True
                    elif task_status == 'Stop Requested':
                        pass
                    else:
                        break
                elif wait_status == 'Paused':
                    if task_status == 'Paused':
                        logging.info( '[ OK ] task(id=%s) is Paused'%(task_id) )
                        return True
                    elif task_status == 'Pause Requested':
                        pass
                    else:
                        break
                else:
                    return False
            logging.debug('Waiting for task(id=%s) %s, current state is %s, will sleep %ds and retry %d times...'%(task_id, wait_status, task_status, sleep, times-i-1))
            time.sleep(sleep)
        logging.error('[FAIL] get_tasks(task_id=%s) wait_for_task:%s times=%d sleep=%d'%(task_id, wait_status, times, sleep))
        logging.debug('get_tasks_result_dict:\n'+str(result_dict))
        return False

    def WaitForAnyRunningTask(self, sleep=30):
        while True:
            tsk_str = ''
            running = {k:v for k, v in self.get_tasks().items() if v.get('status')=='Running'}
            t_count = len(running)
            if t_count == 0:
                break
            for k, v in running.items():
                tsk_str += '\n%36s  %-16s  %3s  %5s'%(v.get('task_id'), v.get('status'), v.get('progress'), k)
            logging.info( '[    ] Waiting for {} tasks to die'.format(t_count) )
            logging.debug( 'WaitForAnyRunningTask{}'.format( tsk_str ) )
            time.sleep( sleep )
        return True

    def RunNewTask(self, name, hosts, port_range, config_name):
        assert( isinstance(name, str) and isinstance(hosts, str) and isinstance(port_range, str) and config_name in self._scan_configs_dictionary )
        if self.create_port_list(name=name, port_range=port_range) is not None:
            for i in (1,):
                if self.create_target(name=name, hosts=hosts, port_list_id=self._task_cache_dictionary[name]['port_list_id']) is None: break
                for i in (1,):
                    if self.create_task(name=name, config_id=self._scan_configs_dictionary.get( config_name ), target_id=self._task_cache_dictionary[name]['target_id']) is None: break
                    for i in (1,):
                        if self.start_task(self._task_cache_dictionary[name]['task_id'], name) is None: break
                        return self._task_cache_dictionary[name]['task_id']
                    self.delete_task(self._task_cache_dictionary[name]['task_id'])
                self.delete_target(self._task_cache_dictionary[name]['target_id'])
            self.delete_port_list(self._task_cache_dictionary[name]['port_list_id'])
        return None

    def DelTaskByName(self, name):
        if name in self._task_cache_dictionary:
            if self.delete_task(self._task_cache_dictionary[name].get('task_id')) == False:
                self.WaitForTask(self._task_cache_dictionary[name].get('task_id'), 'Deleted')
            self.delete_target(self._task_cache_dictionary[name].get('target_id'))
            self.delete_port_list(self._task_cache_dictionary[name].get('port_list_id'))
            self._task_cache_dictionary.pop(name)
        return

    def DisasterRecovery(self):
        pass

    def CustomConfig(self, name, copy=None, comment='Custom Config'):
        configs = self.get_configs()
        if name not in configs:
            config_id = self.create_config(name, comment, copy)
            if config_id:
                assert( self.modify_config(config_id, {'oid':'', 'name':'log_whole_attack', 'value':'eWVz'}, None, None) and
                        self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.12288', 'name':'Global variable settings[entry]:Debug level', 'value':'MTI3'}, None, None) and
                        #self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.12288', 'name':'Global variable settings[entry]:HTTP User-Agent', 'value':'MzYwdnVsblNjYW5uZXJCeUxDWA=='}, None, None) and
                        self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.12288', 'name':'Global variable settings[radio]:Log verbosity', 'value':'RGVidWc='}, None, None) and
                        self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.12288', 'name':'Global variable settings[radio]:Report verbosity', 'value':'VmVyYm9zZQ=='}, None, None) and
                        #self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.14259', 'name':'Nmap (NASL wrapper)[entry]:Ports scanned in parallel (min)', 'value':'MTA='}, None, None) and
                        self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.14259', 'name':'Nmap (NASL wrapper)[radio]:Timing policy :', 'value':'QWdncmVzc2l2ZQ=='}, None, None) and
                        self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.100315', 'name':'Ping Host[checkbox]:Report about unrechable Hosts', 'value':'eWVz'}, None, None) and
                        self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.100315', 'name':'Ping Host[checkbox]:Use ARP', 'value':'bm8='}, None, None) and
                        self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.100315', 'name':'Ping Host[checkbox]:Use nmap', 'value':'eWVz'}, None, None) and
                        self.modify_config(config_id, {'oid':'1.3.6.1.4.1.25623.1.0.100315', 'name':'Ping Host[entry]:nmap additional ports for -PA', 'value':'MjIsODAwNiwzMzg5LDgzNjA='}, None, None) )
                for (family, bnvts) in self._nvt_plugins_blacklist.items():
                    nvts = [{'oid':oid} for oid in self.get_nvts(family=family) if oid not in bnvts]
                    assert( self.modify_config(config_id, None, None, {'family':family,'nvt':nvts}) )
                self._scan_configs_dictionary[name] = config_id
                return config_id
        return None

    def CleanUp(self):
        skip = []
        objects_dict = self.get_tasks(sort_field='status')
        if isinstance(objects_dict, dict):
            for k, v in objects_dict.items():
                if v.get('status') in ('Requested', 'Running'):
                    skip.append(k)
                    logging.warn('[    ] task %s(id=%s) is running, skip'%(k, v.get('task_id')))
                    del objects_dict[k]
            for k, v in objects_dict.items():
                self.stop_task( v.get('task_id') )
            for k, v in objects_dict.items():
                if self.delete_task( v.get('task_id') ) == False:
                    self.WaitForTask(v.get('task_id'), 'Deleted')
        objects_dict = self.get_targets()
        if isinstance(objects_dict, dict):
            for k, v in objects_dict.items():
                if k in self._targets_dictionary or k in skip: continue
                self.delete_target( v.get('target_id') )
        objects_dict = self.get_port_lists()
        if isinstance(objects_dict, dict):
            for k, v in objects_dict.items():
                if k in self._port_lists_dictionary or k in skip: continue
                self.delete_port_list( v.get('port_list_id') )
        objects_dict = self.get_configs()
        if isinstance(objects_dict, dict):
            for k, v in objects_dict.items():
                if k in self._scan_configs_dictionary or k in skip: continue
                self.delete_config( v.get('config_id') )
        self.empty_trashcan()
        self._task_cache_dictionary.clear()

def Main():
    omp = OMP()
    print omp.get_version()
    omp.CleanUp()
    #print omp.CustomConfig('Custom', omp._scan_configs_dictionary.get('Full and fast'))
    #print( omp.get_system_reports() )
    return
    name = 'named'
    omp.RunNewTask(name=name, hosts='127.0.0.1', port_range='T:22,80,443,U:53', config_name='empty')
    print( omp._task_cache_dictionary )
    while True:
        time.sleep(2)
        tasks = omp.get_tasks()
        print( tasks )
        if tasks[named]['status']=='Done':
            omp.get_reports(report_id=omp._task_cache_dictionary[named].get('report_id'), format_id=omp._report_formats_dictionary.get('PDF'), ToDisk='report.pdf')
            break
        print( omp._task_cache_dictionary )
    omp.DelTaskByName(name=named)
    print( omp._task_cache_dictionary )

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    Main()
