from __future__ import absolute_import, print_function

import sys

import logging
import pprint
import random
from getpass import getpass

logFormatter = logging.Formatter(
    "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
log = logging.getLogger('joinmarket')
log.setLevel(logging.DEBUG)

joinmarket_alert = ['']
core_alert = ['']
debug_silence = [False]

#TODO pass this through from client, bitcoin paramater:
DUST_THRESHOLD = 2730

#consoleHandler = logging.StreamHandler(stream=sys.stdout)
class JoinMarketStreamHandler(logging.StreamHandler):

    def __init__(self, stream):
        super(JoinMarketStreamHandler, self).__init__(stream)

    def emit(self, record):
        if joinmarket_alert[0]:
            print('JoinMarket Alert Message: ' + joinmarket_alert[0])
        if core_alert[0]:
            print('Core Alert Message: ' + core_alert[0])
        if not debug_silence[0]:
            super(JoinMarketStreamHandler, self).emit(record)


consoleHandler = JoinMarketStreamHandler(stream=sys.stdout)
consoleHandler.setFormatter(logFormatter)
log.addHandler(consoleHandler)

def get_log():
    """
    provides joinmarket logging instance
    :return: log instance
    """
    return log

def set_logging_level(level):
    consoleHandler.setLevel(level)

def chunks(d, n):
    return [d[x:x + n] for x in range(0, len(d), n)]

def get_password(msg): #pragma: no cover
    return getpass(msg)

def debug_dump_object(obj, skip_fields=None):
    if skip_fields is None:
        skip_fields = []
    log.debug('Class debug dump, name:' + obj.__class__.__name__)
    for k, v in obj.__dict__.items():
        if k in skip_fields:
            continue
        if k == 'password' or k == 'given_password':
            continue
        log.debug('key=' + k)
        if isinstance(v, str):
            log.debug('string: len:' + str(len(v)))
            log.debug(v)
        elif isinstance(v, dict) or isinstance(v, list):
            log.debug(pprint.pformat(v))
        else:
            log.debug(str(v))

def _byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.items()
        }
    # if it's anything else, return it in its original form
    return data
