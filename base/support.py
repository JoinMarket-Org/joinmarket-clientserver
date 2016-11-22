from __future__ import absolute_import, print_function

import sys

import logging
import pprint
import random

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

log.debug('hello joinmarket')


def get_log():
    """
    provides joinmarket logging instance
    :return: log instance
    """
    return log

def chunks(d, n):
    return [d[x:x + n] for x in xrange(0, len(d), n)]

def debug_dump_object(obj, skip_fields=None):
    if skip_fields is None:
        skip_fields = []
    log.debug('Class debug dump, name:' + obj.__class__.__name__)
    for k, v in obj.__dict__.iteritems():
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
