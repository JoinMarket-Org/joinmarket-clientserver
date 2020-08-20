
import logging, sys
import binascii
from getpass import getpass
from os import path, environ
from functools import wraps
# JoinMarket version
JM_CORE_VERSION = '0.7.0'

# global Joinmarket constants
JM_WALLET_NAME_PREFIX = "joinmarket-wallet-"
JM_APP_NAME = "joinmarket"

# Exit status codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_ARGERROR = 2

from chromalog.log import (
    ColorizingStreamHandler,
    ColorizingFormatter,
)
from chromalog.colorizer import GenericColorizer, MonochromaticColorizer
from colorama import Fore, Back, Style

# magic; importing e.g. 'info' actually instantiates
# that as a function that uses the color map
# defined below. ( noqa because flake doesn't understand)
from chromalog.mark.helpers.simple import (  # noqa: F401
    debug,
    info,
    important,
    success,
    warning,
    error,
    critical,
)

# our chosen colorings for log messages in JM:
jm_color_map = {
    'debug': (Style.DIM + Fore.LIGHTBLUE_EX, Style.RESET_ALL),
    'info': (Style.BRIGHT + Fore.BLUE, Style.RESET_ALL),
    'important': (Style.BRIGHT, Style.RESET_ALL),
    'success': (Fore.GREEN, Style.RESET_ALL),
    'warning': (Fore.YELLOW, Style.RESET_ALL),
    'error': (Fore.RED, Style.RESET_ALL),
    'critical': (Back.RED, Style.RESET_ALL),
}

class JMColorizer(GenericColorizer):
    default_color_map = jm_color_map

jm_colorizer = JMColorizer()

logFormatter = ColorizingFormatter(
    "%(asctime)s [%(levelname)s]  %(message)s")
log = logging.getLogger('joinmarket')
log.setLevel(logging.DEBUG)

joinmarket_alert = ['']
core_alert = ['']
debug_silence = [False]

#TODO pass this through from client, bitcoin paramater:
DUST_THRESHOLD = 2730

class JoinMarketStreamHandler(ColorizingStreamHandler):

    def __init__(self):
        super().__init__(colorizer=jm_colorizer)

    def emit(self, record):
        if joinmarket_alert[0]:
            print('JoinMarket Alert Message: ' + joinmarket_alert[0])
        if core_alert[0]:
            print('Core Alert Message: ' + core_alert[0])
        if not debug_silence[0]:
            super().emit(record)

handler = JoinMarketStreamHandler()
handler.setFormatter(logFormatter)
log.addHandler(handler)

# hex/binary conversion routines used by dependent packages
def hextobin(h):
    """Convert a hex string to bytes"""
    return binascii.unhexlify(h.encode('utf8'))


def bintohex(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')


def lehextobin(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h.encode('utf8'))[::-1]


def bintolehex(b):
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.hexlify(b[::-1]).decode('utf8')

def utxostr_to_utxo(x):
    if not isinstance(x, str):
        return (False, "not a string")
    y = x.split(":")
    if len(y) != 2:
        return (False,
                "string is not two items separated by :")
    try:
        n = int(y[1])
    except:
        return (False, "utxo index was not an integer.")
    if n < 0:
        return (False, "utxo index must not be negative.")
    if len(y[0]) != 64:
        return (False, "txid is not 64 hex characters.")
    try:
        txid = binascii.unhexlify(y[0])
    except:
        return (False, "txid is not hex.")
    return (True, (txid, n))

def utxo_to_utxostr(u):
    if not isinstance(u, tuple):
        return (False, "utxo is not a tuple.")
    if not len(u) == 2:
        return (False, "utxo should have two elements.")
    if not isinstance(u[0], bytes):
        return (False, "txid should be bytes.")
    if not isinstance(u[1], int):
        return (False, "index should be int.")
    if u[1] < 0:
        return (False, "index must be a positive integer.")
    if not len(u[0]) == 32:
        return (False, "txid must be 32 bytes.")
    txid = binascii.hexlify(u[0]).decode("ascii")
    return (True, txid + ":" + str(u[1]))

def jmprint(msg, level="info"):
    """ Provides the ability to print messages
    with consistent formatting, outside the logging system
    (in case you don't want the standard log format).
    Example applications are: REPL style stuff, and/or
    some very important / user workflow affecting communication.
    Note that this exclusively for console printout, NOT for
    logging to file (chromalog will handle file streams
    properly, but this will not).
    """
    if not level in jm_color_map.keys():
        raise Exception("Unsupported formatting")

    # .colorize_message function does a .format() on the string,
    # which does not work with string-ified json; this should
    # result in output as intended:
    msg = msg.replace('{', '{{')
    msg = msg.replace('}', '}}')

    fmtfn = eval(level)
    print(jm_colorizer.colorize_message(fmtfn(msg)))

def get_log():
    """
    provides joinmarket logging instance
    :return: log instance
    """
    return log

def set_logging_level(level):
    handler.setLevel(level)

def set_logging_color(colored=False):
    if colored:
        handler.colorizer = jm_colorizer
    else:
        handler.colorizer = MonochromaticColorizer()

def chunks(d, n):
    return [d[x:x + n] for x in range(0, len(d), n)]

def get_password(msg): #pragma: no cover
    password = getpass(msg)
    if not isinstance(password, bytes):
        password = password.encode('utf-8')
    return password

def lookup_appdata_folder(appname):
    """ Given an appname as a string,
    return the correct directory for storing
    data for the given OS environment.
    """
    if sys.platform == 'darwin':
        if "HOME" in environ:
            data_folder = path.join(environ["HOME"],
                                   "Library/Application support/",
                                   appname) + '/'
        else:
            jmprint("Could not find home folder")
            sys.exit(EXIT_FAILURE)

    elif 'win32' in sys.platform or 'win64' in sys.platform:
        data_folder = path.join(environ['APPDATA'], appname) + '\\'
    else:
        data_folder = path.expanduser(path.join("~", "." + appname + "/"))
    return data_folder

def print_jm_version(option, opt_str, value, parser):
    print("JoinMarket " + JM_CORE_VERSION)
    sys.exit(EXIT_SUCCESS)

# helper functions for conversions of format between over-the-wire JM
# and internal. See details in hexbin() docstring.

def _convert(x):
    good, utxo = utxostr_to_utxo(x)
    if good:
        return utxo
    else:
        try:
            b = hextobin(x)
            return b
        except:
            return x

def listchanger(l):
    rlist = []
    for x in l:
        if isinstance(x, list):
            rlist.append(listchanger(x))
        elif isinstance(x, dict):
            rlist.append(dictchanger(x))
        else:
            rlist.append(_convert(x))
    return rlist

def dictchanger(d):
    rdict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            rdict[_convert(k)] = dictchanger(v)
        elif isinstance(v, list):
            rdict[_convert(k)] = listchanger(v)
        else:
            rdict[_convert(k)] = _convert(v)
    return rdict

def hexbin(func):
    """ Decorator for functions of taker and maker receiving over
    the wire AMP arguments that may be in hex or hextxid:n format
    and converting all to binary.
    Functions to which this decorator applies should have all arguments
    be one of:
    - hex string (keys), converted here to binary
    - lists of keys or txid:n strings (converted here to binary, or
      (txidbytes, n))
    - lists of lists or dicts, to which these rules apply recursively.
    - any other string (unchanged)
    - dicts with keys as per above; values are altered recursively according
      to the rules above.
    """
    @wraps(func)
    def func_wrapper(inst, *args, **kwargs):
        newargs = []
        for arg in args:
            if isinstance(arg, (list, tuple)):
                newargs.append(listchanger(arg))
            elif isinstance(arg, dict):
                newargs.append(dictchanger(arg))
            else:
                newargs.append(_convert(arg))
        return func(inst, *newargs, **kwargs)

    return func_wrapper