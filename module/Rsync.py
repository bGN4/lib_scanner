#!/usr/bin python
# -*- coding: utf-8 -*-

import os
import sys
import logging
import subprocess

__version__ = '1.0.0.1'
PROGRAM = sys.argv[0]
AUTHNAME = 'https://github.com/bGN4'
AUTHEMAIL = 'https://github.com/bGN4'

RSYNC_EXIT_VALUES = {
       0    : 'Success',
       1    : 'Syntax or usage error',
       2    : 'Protocol incompatibility',
       3    : 'Errors selecting input/output files, dirs',
       4    : 'Requested action not supported: an attempt was made to manipulate 64-bit files on a platform that cannot support them; or an option was specified that is supported by the client and not by the server.',
       5    : 'Error starting client-server protocol',
       6    : 'Daemon unable to append to log-file',
       10   : 'Error in socket I/O',
       11   : 'Error in file I/O',
       12   : 'Error in rsync protocol data stream',
       13   : 'Errors with program diagnostics',
       14   : 'Error in IPC code',
       20   : 'Received SIGUSR1 or SIGINT',
       21   : 'Some error returned by waitpid()',
       22   : 'Error allocating core memory buffers',
       23   : 'Partial transfer due to error',
       24   : 'Partial transfer due to vanished source files',
       25   : 'The --max-delete limit stopped deletions',
       30   : 'Timeout in data send/receive',
       35   : 'Timeout waiting for daemon connection'
    }

def rsync(opt_seq, abssrc, dst, fqp=None, pwdfile=None, retry=10):
    if fqp:
        if not ( os.path.isfile(fqp) and os.access(fqp, os.X_OK) ):
            raise EnvironmentError(1, "wrong path or not executable", fqp)
    else:
        fqp = 'rsync'
    if not os.path.isabs( abssrc ):
        raise EnvironmentError(1, "wrong absolute src path", abssrc)
    if os.path.isdir( abssrc ) and abssrc[-1] not in ('/', '\\'):
        abssrc = abssrc + os.sep
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
    except AttributeError as e:
        startupinfo = None
    pwd_seq = []
    if pwdfile:
        pwdfile = os.path.abspath(pwdfile)
        if os.path.isfile( pwdfile ):
            os.chmod(pwdfile, 256+128)
            pwd_seq = ['--password-file', pwdfile]
    if sys.platform == 'win32':
        abssrc = abssrc.replace('\\', '/')
        abssrc = '/cygdrive/' + abssrc[0:1].lower() + abssrc[2:]
        if len(pwd_seq)==2:
            pwd_seq[1] = pwd_seq[1].replace('\\', '/')
            pwd_seq[1] = '/cygdrive/' + pwd_seq[1][0:1].lower() + pwd_seq[1][2:]
    cmd_seq = [fqp] + pwd_seq + opt_seq + [abssrc] + [dst]
    logging.debug( cmd_seq )
    ret = -1
    for i in range(retry+1):
        proc = subprocess.Popen(cmd_seq, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        str_stdout, str_stderr = proc.communicate()
        logging.debug( 'rsync_stdout:\n' + str_stdout )
        ret = proc.returncode
        if ret == 0:
            logging.debug( 'rsync_stderr:\n' + str_stderr )
            break
        else:
            myLog1 = logging.WARN  if i < retry else logging.ERROR
            myLog2 = logging.DEBUG if i < retry else logging.ERROR
            logging.log( myLog1, 'Send files with RSYNC Error {}: {} ({} times left)'.format(ret, RSYNC_EXIT_VALUES.get(ret, 'Unknown Error'), retry-i) )
            logging.log( myLog2, 'rsync_stderr:\n' + str_stderr )
    return ret

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    rsync(['-varztopg', '--port=873', '--timeout=60', '--exclude', '.tmp*'],
          'D:\\IDE\\MyProjects\\SVN\\hubu\\src\\tasks',
          'root@192.168.56.101::test',
          'D:/Tools/cwRsync_5.4.1_x86_Free/rsync.exe',
          os.path.join( os.path.dirname(os.path.abspath(__file__)), 'rsync.pass' ))
