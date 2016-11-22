#!/usr/bin/python
import json, re
import random
import sys
import time
import platform
from base.support import get_log
if platform.system() == "Windows":
    import ssl
    import urllib2
else:
    try:
        from urllib.request import build_opener
    except:
        from urllib2 import build_opener

log = get_log()

# Makes a request to a given URL (first arg) and optional params (second arg)
def make_request(*args):
    if platform.system() == "Windows":
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sh = urllib2.HTTPSHandler(debuglevel=0, context=sctx)
        opener = urllib2.build_opener(sh)
    else:
        opener = build_opener()
    opener.addheaders = [('User-agent',
                          'Mozilla/5.0' + str(random.randrange(1000000)))]
    try:
        return opener.open(*args).read().strip()
    except Exception as e:
        try:
            p = e.read().strip()
        except:
            p = e
        raise Exception(p)

def make_request_blockr(*args):
    counter = 0
    while True:
        data = json.loads(make_request(*args))
        if data['status'] == 'error' and data['code'] == 429:
            log.debug('Blockr service error: ' + data['message'])
            time.sleep(min(60, 2**counter / 2.))
            counter += 1
            continue
        return data

# Pushes a transaction to the network using https://blockchain.info/pushtx
def bci_pushtx(tx):
    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    return make_request('https://blockchain.info/pushtx', 'tx=' + tx)

def blockr_pushtx(tx, network='btc'):
    if network == 'testnet':
        blockr_url = 'https://tbtc.blockr.io/api/v1/tx/push'
    elif network == 'btc':
        blockr_url = 'https://btc.blockr.io/api/v1/tx/push'
    else:
        raise Exception('Unsupported network {0} for blockr_pushtx'.format(
            network))

    if not re.match('^[0-9a-fA-F]*$', tx):
        tx = tx.encode('hex')
    return make_request(blockr_url, '{"hex":"%s"}' % tx)







