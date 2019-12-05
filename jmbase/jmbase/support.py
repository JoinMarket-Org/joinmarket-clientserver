
import logging, sys
from getpass import getpass
from os import path, environ

# JoinMarket version
JM_CORE_VERSION = '0.6.2'

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
        super(JoinMarketStreamHandler, self).__init__(colorizer=jm_colorizer)

    def emit(self, record):
        if joinmarket_alert[0]:
            print('JoinMarket Alert Message: ' + joinmarket_alert[0])
        if core_alert[0]:
            print('Core Alert Message: ' + core_alert[0])
        if not debug_silence[0]:
            super(JoinMarketStreamHandler, self).emit(record)

handler = JoinMarketStreamHandler()
handler.setFormatter(logFormatter)
log.addHandler(handler)

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
