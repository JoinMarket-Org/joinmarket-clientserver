#! /usr/bin/env python
import random
from optparse import OptionParser, OptionValueError
from configparser import NoOptionError

import jmclient.support
from jmbase import JM_APP_NAME
from jmclient import jm_single, RegtestBitcoinCoreInterface, cryptoengine
from jmbase.support import print_jm_version

"""This exists as a separate module for two reasons:
to reduce clutter in main scripts, and refactor out
options which are common to more than one script in a base class.
"""

order_choose_algorithms = {
    'random_under_max_order_choose': '-R',
    'cheapest_order_choose': '-C',
    'weighted_order_choose': '-W'
}

def add_base_options(parser):
    """ Options for scripts common to all scripts
    including maker, taker and non-coinjoin scripts.
    See https://github.com/JoinMarket-Org/joinmarket-clientserver/issues/430
    for more on how to further improve this.
    Note that it's fine to have options here that are not used
    in *all* scripts, as long as there is no conflict with another
    usage of the option.
    """
    parser.add_option(
        '--datadir',
        dest='datadir',
        default="",
        help='Specify the path to a directory you want to use to store your user'
        'data - wallets, logs and commitment files - and your joinmarket.cfg. '
        'By default, the directory .' + JM_APP_NAME + ' is used.'
    )
    parser.add_option('--recoversync',
                      action='store_true',
                      dest='recoversync',
                      default=False,
                      help=('choose to do detailed wallet sync, '
                            'used for recovering on new Core instance.'))
    parser.add_option('--wallet-password-stdin',
                      action='store_true',
                      default=False,
                      dest='wallet_password_stdin',
                      help='Read wallet password from stdin')
    parser.add_option('--version',
                      action='callback',
                      callback=print_jm_version,
                      help='Print JoinMarket version and exit.')

def add_common_options(parser):
    add_base_options(parser)
    parser.add_option(
        '-f',
        '--txfee',
        action='store',
        type='int',
        dest='txfee',
        default=-1,
        help='Bitcoin miner tx_fee to use for transaction(s). A number higher '
        'than 1000 is used as "satoshi per KB" tx fee. A number lower than that '
        'uses the dynamic fee estimation of your blockchain provider as '
        'confirmation target. This temporarily overrides the "tx_fees" setting '
        'in your joinmarket.cfg. Works the same way as described in it. Check '
        'it for examples.')
    parser.add_option(
        '-x',
        '--max-cj-fee-abs',
        type='int',
        dest='max_cj_fee_abs',
        help="Maximum absolute coinjoin fee in satoshi to pay to a single "
             "market maker for a transaction. Both the limits given in "
             "--max-cj-fee-abs and --max-cj-fee-rel must be exceeded in order "
             "to not consider a certain offer.")
    parser.add_option(
        '-r',
        '--max-cj-fee-rel',
        type='float',
        dest='max_cj_fee_rel',
        help="Maximum relative coinjoin fee, in fractions of the coinjoin "
             "value, to pay to a single market maker for a transaction. Both "
             "the limits given in --max-cj-fee-abs and --max-cj-fee-rel must "
             "be exceeded in order to not consider a certain offer.\n"
             "Example: 0.001 for a maximum fee of 0.1% of the cj amount")
    parser.add_option(
        '--order-choose-algorithm',
        action='callback',
        type='string',
        default=jmclient.support.random_under_max_order_choose,
        callback=get_order_choose_algorithm,
        help="Set the algorithm to use for selecting orders from the order book.\n"
             "Default: {}\n"
             "Available options: {}"
             .format('random_under_max_order_choose',
                     ', '.join(order_choose_algorithms.keys())),
        dest='order_choose_fn')
    add_order_choose_short_options(parser)


def add_order_choose_short_options(parser):
    for name in sorted(order_choose_algorithms.keys()):
        option = order_choose_algorithms[name]
        parser.add_option(
            option,
            help="alias for --order-choose-algorithm={}".format(name),
            nargs=0,
            action='callback',
            callback=get_order_choose_algorithm,
            callback_kwargs={'value_kw': name},
            dest='order_choose_fn')


def get_order_choose_algorithm(option, opt_str, value, parser, value_kw=None):
    value = value_kw or value
    if value not in order_choose_algorithms:
        raise OptionValueError("{} must be one of {}".format(
                opt_str, list(order_choose_algorithms.keys())))
    fn = getattr(jmclient.support, value, None)
    if not fn:
        raise OptionValueError("internal error: '{}' order choose algorithm not"
                               " found".format(value))
    setattr(parser.values, option.dest, fn)


"""
The following defaults are maintained as accessed via functions for
flexibility.
TODO This should be moved from this module."""
MAX_DEFAULT_REL_FEE = 0.001
MIN_MAX_DEFAULT_ABS_FEE = 1000
MAX_MAX_DEFAULT_ABS_FEE = 10000

def get_default_max_relative_fee():
    return MAX_DEFAULT_REL_FEE

def get_default_max_absolute_fee():
    return random.randint(MIN_MAX_DEFAULT_ABS_FEE, MAX_MAX_DEFAULT_ABS_FEE)

def prompt_user_for_cj_fee(rel_val, abs_val):
    msg = """Joinmarket will choose market makers randomly as long as their
fees are below a certain maximum value, or fraction. The suggested maximums are:

X = {rel_val}
Y = {abs_val} satoshis

Those values were chosen randomly for you (unless you already set one of them
in your joinmarket.cfg or via a CLI option).

Since you are using N counterparties, if you agree to these values, your
**maximum** coinjoin fee will be either N*Y satoshis or N*X percent of your
coinjoin amount, depending on which is larger. The actual fee is likely to be
significantly less; perhaps half that amount, depending on which
counterparties are selected."""

    def prompt_user_value(m, val, check):
        while True:
            data = input(m)
            if data == 'y':
                return val
            try:
                val_user = float(data)
            except ValueError:
                print("Bad answer, try again.")
                continue
            if not check(val_user):
                continue
            return val_user

    rel_prompt = False
    if rel_val is None:
        rel_prompt = True
        rel_val = get_default_max_relative_fee()

    abs_prompt = False
    if abs_val is None:
        abs_prompt = True
        abs_val = get_default_max_absolute_fee()

    print(msg.format(rel_val=rel_val, abs_val=abs_val))
    if rel_prompt:
        msg = ("\nIf you want to keep this relative limit, enter 'y';"
               "\notherwise choose your own fraction (between 1 and 0): ")

        def rel_check(val):
            if val >= 1:
                print("Choose a number below 1! Else you will spend all your "
                      "bitcoins for fees!")
                return False
            return True

        rel_val = prompt_user_value(msg, rel_val, rel_check)
        print("Success! Using relative fee limit of {:%}".format(rel_val))

    if abs_prompt:
        msg = ("\nIf you want to keep this absolute limit, enter 'y';"
               "\notherwise choose your own limit in satoshi: ")

        def abs_check(val):
            if val % 1 != 0:
                print("You must choose a full number!")
                return False
            return True

        abs_val = int(prompt_user_value(msg, abs_val, abs_check))
        print("Success! Using absolute fee limit of {}".format(abs_val))

    print("""\nIf you don't want to see this message again, make an entry like
this in the POLICY section of joinmarket.cfg:

max_cj_fee_abs = {abs_val}
max_cj_fee_rel = {rel_val}\n""".format(rel_val=rel_val, abs_val=abs_val))

    return rel_val, abs_val

def get_max_cj_fee_values(config, parser_options,
                          user_callback=prompt_user_for_cj_fee):
    """ Given a config object, retrieve the chosen maximum absolute
    and relative coinjoin fees chosen by the user, or prompt
    the user via the user_callback function, if not present in
    the config.

    user_callback:
    Arguments: relative value(default None), absolute value (default None)
    Returns: relative value (float), absolute value (int, satoshis)
    """

    CONFIG_SECTION = 'POLICY'
    CONFIG_OPTION = 'max_cj_fee_'
    # rel, abs
    fee_values = [None, None]
    fee_types = [float, int]

    for i, option in enumerate(('rel', 'abs')):
        if parser_options is not None:
            value = getattr(parser_options, CONFIG_OPTION + option, None)
            if value is not None:
                fee_values[i] = fee_types[i](value)
                continue
        try:
            fee_values[i] = config.get(CONFIG_SECTION, CONFIG_OPTION + option)
        except NoOptionError:
            pass

    if any(x is None for x in fee_values):
        fee_values = user_callback(*fee_values)

    return tuple(map(lambda j: fee_types[j](fee_values[j]),
                     range(len(fee_values))))

def check_regtest(blockchain_start=True):
    """ Applies any regtest-specific configuration
    """
    if not isinstance(jm_single().bc_interface,
                      RegtestBitcoinCoreInterface):
        return
    if blockchain_start:
        #to allow testing of confirm/unconfirm callback for multiple txs
        jm_single().bc_interface.tick_forward_chain_interval = 10
        jm_single().bc_interface.simulating = True
    # handles the custom regtest hrp for bech32
    cryptoengine.BTC_P2WPKH.VBYTE = 100

def get_tumbler_parser():
    parser = OptionParser(
            usage='usage: %prog [options] [wallet file] [destaddr(s)...]',
            description=
            'Sends bitcoins to many different addresses using coinjoin in'
            ' an attempt to break the link between them. Sending to multiple '
            ' addresses is highly recommended for privacy. This tumbler can'
            ' be configured to ask for more address mid-run, giving the user'
            ' a chance to click `Generate New Deposit Address` on whatever service'
            ' they are using.')
    parser.add_option(
            '-m',
            '--mixdepthsource',
            type='int',
            dest='mixdepthsrc',
            help=
            'Mixing depth to start tumble process from. default=0.',
            default=0)
    parser.add_option('--restart',
        action='store_true',
        dest='restart',
        default=False,
        help=('Restarts the schedule currently found in the schedule file in the '
              'logs directory, with name TUMBLE.schedule or what is set in the '
              'schedulefile option.'))
    parser.add_option('--schedulefile',
            type='string',
            dest='schedulefile',
            default='TUMBLE.schedule',
            help=('Name of schedule file for tumbler, useful for restart, default '
                  'TUMBLE.schedule'))
    parser.add_option(
            '-a',
            '--addrcount',
            type='int',
            dest='addrcount',
            default=3,
            help=
            'How many destination addresses in total should be used. If not enough are given'
            ' as command line arguments, the script will ask for more. This parameter is required'
            ' to stop amount correlation. default=3')
    parser.add_option(
            '-N',
            '--makercountrange',
            type='float',
            nargs=2,
            action='store',
            dest='makercountrange',
            help=
            'Input the mean and spread of number of makers to use. e.g. 9 1 will be a normal distribution '
            'with mean 9 and standard deviation 1 inclusive, default=9 1 (floats are also OK)',
            default=(9, 1))
    parser.add_option(
            '--minmakercount',
            type='int',
            dest='minmakercount',
            default=4,
            help=
            'The minimum maker count in a transaction, random values below this are clamped at this number. default=4')
    parser.add_option(
            '-M',
            '--mixdepthcount',
            type='int',
            dest='mixdepthcount',
            help='How many mixing depths to mix through',
            default=4)
    parser.add_option(
            '-c',
            '--txcountparams',
            type='float',
            nargs=2,
            dest='txcountparams',
            default=(2, 1),
            help=
            'The number of transactions to take coins from one mixing depth to the next, it is'
            ' randomly chosen following a normal distribution. Should be similar to --addrask. '
            'This option controls the parameters of the normal distribution curve. (mean, standard deviation). default=2 1')
    parser.add_option(
            '--mintxcount',
            type='int',
            dest='mintxcount',
            default=2,
            help='The minimum transaction count per mixing level, default=2')
    parser.add_option(
            '--donateamount',
            type='float',
            dest='donateamount',
            default=0,
            help=
            'percent of funds to donate to joinmarket development, or zero to opt out (default=0%)')
    parser.add_option(
            '-l',
            '--timelambda',
            type='float',
            dest='timelambda',
            default=60,
            help=
            'Average the number of minutes to wait between transactions. Randomly chosen '
            ' following an exponential distribution, which describes the time between uncorrelated'
            ' events. default=60')
    parser.add_option(
            '--stage1-timelambda-increase',
            type='float',
            dest='stage1_timelambda_increase',
            default=3,
            help=
            'Stage 1 sweep coinjoins have a longer wait time. This parameter'
            ' controls by what factor longer is this average wait time compared to stage2 coinjoins'
            ' which are controlled by `--timelambda`, default=3')
    parser.add_option(
            '-w',
            '--wait-time',
            action='store',
            type='float',
            dest='waittime',
            help='wait time in seconds to allow orders to arrive, default=20',
            default=20)
    parser.add_option(
            '-s',
            '--mincjamount',
            type='int',
            dest='mincjamount',
            default=100000,
            help='minimum coinjoin amount in transaction in satoshi, default 100k')
    parser.add_option(
            '-q',
            '--liquiditywait',
            type='int',
            dest='liquiditywait',
            default=60,
            help=
            'amount of seconds to wait after failing to choose suitable orders before trying again, default 60')
    parser.add_option(
            '--maxbroadcasts',
            type='int',
            dest='maxbroadcasts',
            default=4,
            help=
            'maximum amount of times to broadcast a transaction before giving up and re-creating it, default 4')
    parser.add_option(
            '--maxcreatetx',
            type='int',
            dest='maxcreatetx',
            default=9,
            help=
            'maximum amount of times to re-create a transaction before giving up, default 9')
    # note that this is used slightly differently in tumbler from sendpayment,
    # hence duplicated:
    parser.add_option('-A',
            '--amtmixdepths',
            action='store',
            type='int',
            dest='amtmixdepths',
            help='number of mixdepths ever used in wallet, '
                 'only to be used if mixdepths higher than '
                 'mixdepthsrc + number of mixdepths to tumble '
                 'have been used.',
            default=-1)
    parser.add_option(
            '--rounding-chance',
            action='store',
            type='float',
            dest='rounding_chance',
            help='probability of non-sweep coinjoin amount being rounded, default=0.25 (25%)',
            default=0.25)
    parser.add_option(
            '--rounding-sigfig-weights',
            type='float',
            nargs=5,
            dest='rounding_sigfig_weights',
            default=(55, 15, 25, 65, 40),
            help=
            "If rounding happens (determined by --rounding-chance) then the weights of how many"
            " significant figures to round to. The five values refer to the probability of"
            " rounding to one, two, three, four and five significant figures respectively."
            " default=(55, 15, 25, 65, 40)")
    add_common_options(parser)
    return parser


def get_sendpayment_parser():
    parser = OptionParser(
        usage=
        'usage: %prog [options] wallet_file amount destination\n' +
        '       %prog [options] wallet_file bitcoin_uri',
        description='Sends a single payment from a given mixing depth of your '
        +
        'wallet to an given address using coinjoin and then switches off. '
        +
        'Setting amount to zero will do a sweep, where the entire mix depth is emptied')
    parser.add_option(
        '-w',
        '--wait-time',
        action='store',
        type='float',
        dest='waittime',
        help='wait time in seconds to allow orders to arrive, default=15',
        default=15)
    parser.add_option(
        '-N',
        '--makercount',
        action='store',
        type='int',
        dest='makercount',
        help='how many makers to coinjoin with, default random from 4 to 6',
        default=random.randint(8, 10))
    parser.add_option('-S',
                      '--schedule-file',
                      type='string',
                      dest='schedule',
                      help='schedule file name; see file "sample-schedule-for-testnet" for explanation and example',
                      default='')
    parser.add_option(
        '-P',
        '--pick-orders',
        action='store_true',
        dest='pickorders',
        default=False,
        help=
        'interactively pick which orders to take. doesn\'t work while sweeping.')
    parser.add_option('-m',
                      '--mixdepth',
                      action='store',
                      type='int',
                      dest='mixdepth',
                      help='mixing depth to spend from, default=0',
                      default=0)
    parser.add_option('-a',
                      '--amtmixdepths',
                      action='store',
                      type='int',
                      dest='amtmixdepths',
                      help='number of mixdepths in wallet, default 5',
                      default=5)
    parser.add_option('-g',
                      '--gap-limit',
                      type="int",
                      action='store',
                      dest='gaplimit',
                      help='gap limit for wallet, default=6',
                      default=6)
    parser.add_option('--yes',
                      action='store_true',
                      dest='answeryes',
                      default=False,
                      help='answer yes to everything')
    parser.add_option('--psbt',
                      action='store_true',
                      dest='with_psbt',
                      default=False,
                      help='output as psbt instead of '
                      'broadcasting the transaction. '
                      'Currently only works with direct '
                      'send (-N 0).')

    add_common_options(parser)
    return parser
