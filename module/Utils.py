#!/usr/bin python2.7
# -*- coding: utf-8 -*-

import os
import sys
import logging
import traceback

__version__ = '1.0.0.1'
PROGRAM = sys.argv[0]
AUTHNAME = 'https://github.com/bGN4'
AUTHEMAIL = 'https://github.com/bGN4'

def FindInPath(program):
    """
    Protected method enabling the object to find the full path of a binary
    from its PATH environment variable.

    :param program: name of a binary for which the full path needs to
    be discovered.

    :return: the full path to the binary.

    :todo: add a default path list in case PATH is empty.
    """
    sep = ';' if sys.platform=='win32' else ':'
    for path in os.environ.get('PATH', '').split( sep ):
        if (os.path.exists(os.path.join(path, program)) and not os.path.isdir(os.path.join(path, program))):
            return os.path.join(path, program)
    return None

def Fork():
    pid = -1
    if sys.platform != 'win32':
        try:
            pid = os.fork()
        except OSError as e:
            logging.error('[FAIL] fork error: %d (%s)'%(e.errno, e.strerror))
            sys.exit(1)
        if pid > 0:
            return pid
        os.setsid()
        os.umask(0)
    return pid

def Run_BK(func):
    try:
        pid = Fork()
        if pid <= 0:
            func()
        if pid != 0:
            logging.info('[    ] background function exit!')
    except (GeneratorExit, SystemExit) as e:
        logging.critical( traceback.format_exc() )

def test():
    print 'test'

if __name__ == '__main__':
    Run_BK(test)
