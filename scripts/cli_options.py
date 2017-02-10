#! /usr/bin/env python
from __future__ import absolute_import, print_function
import random

"""This exists as a separate module for two reasons:
to reduce clutter in main scripts, and (TODO) refactor out
options which are common to more than one script in a base class.
"""

from optparse import OptionParser

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
            'Mixing depth to spend from. DEPRECATED, do not use.',
            default=0)
    parser.add_option(
            '-f',
        '--txfee',
        action='store',
        type='int',
        dest='txfee',
        default=-1,
        help='number of satoshis per participant to use as the initial estimate '+
        'for the total transaction fee, default=dynamically estimated, note that this is adjusted '+
        'based on the estimated fee calculated after tx construction, based on '+
        'policy set in joinmarket.cfg.')
    parser.add_option('--restart',
        action='store_true',
        dest='restart',
        default=False,
        help=('Restarts the schedule currently found in the schedule file in the '
              'logs directory, with name TUMBLE.schedule or what is set in the '
              'schedulefile option.'))
    parser.add_option('--schedulefile',
            type='str',
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
            '-x',
            '--maxcjfee',
            type='float',
            dest='maxcjfee',
            nargs=2,
            default=(0.01, 10000),
            help='maximum coinjoin fee and bitcoin value the tumbler is '
                 'willing to pay to a single market maker. Both values need to be exceeded, so if '
                 'the fee is 30% but only 500satoshi is paid the tx will go ahead. default=0.01, 10000 (1%, 10000satoshi)')
    parser.add_option(
            '-N',
            '--makercountrange',
            type='float',
            nargs=2,
            action='store',
            dest='makercountrange',
            help=
            'Input the mean and spread of number of makers to use. e.g. 6 1 will be a normal distribution '
            'with mean 6 and standard deviation 1 inclusive, default=6 1 (floats are also OK)',
            default=(6, 1))
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
            default=(4, 1),
            help=
            'The number of transactions to take coins from one mixing depth to the next, it is'
            ' randomly chosen following a normal distribution. Should be similar to --addrask. '
            'This option controls the parameters of the normal distribution curve. (mean, standard deviation). default=4 1')
    parser.add_option(
            '--mintxcount',
            type='int',
            dest='mintxcount',
            default=1,
            help='The minimum transaction count per mixing level, default=1')
    parser.add_option(
            '--donateamount',
            type='float',
            dest='donateamount',
            default=0,
            help=
            'percent of funds to donate to joinmarket development, or zero to opt out (default=0%)')
    parser.add_option(
            '--amountpower',
            type='float',
            dest='amountpower',
            default=100.0,
            help=
            'The output amounts follow a power law distribution, this is the power, default=100.0')
    parser.add_option(
            '-l',
            '--timelambda',
            type='float',
            dest='timelambda',
            default=30,
            help=
            'Average the number of minutes to wait between transactions. Randomly chosen '
            ' following an exponential distribution, which describes the time between uncorrelated'
            ' events. default=30')
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
    parser.add_option('--fast',
                      action='store_true',
                      dest='fastsync',
                      default=False,
                      help=('choose to do fast wallet sync, only for Core and '
                      'only for previously synced wallet'))
    return parser

def get_sendpayment_parser():
    parser = OptionParser(
        usage=
        'usage: %prog [options] [wallet file / fromaccount] [amount] [destaddr]',
        description='Sends a single payment from a given mixing depth of your '
        +
        'wallet to an given address using coinjoin and then switches off. Also sends from bitcoinqt. '
        +
        'Setting amount to zero will do a sweep, where the entire mix depth is emptied')
    parser.add_option(
        '-f',
        '--txfee',
        action='store',
        type='int',
        dest='txfee',
        default=-1,
        help=
        'number of satoshis per participant to use as the initial estimate ' +
        'for the total transaction fee, default=dynamically estimated, note that this is adjusted '
        +
        'based on the estimated fee calculated after tx construction, based on '
        + 'policy set in joinmarket.cfg.')
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
        default=random.randint(4, 6))
    parser.add_option('-S',
                      '--schedule-file',
                      type='str',
                      dest='schedule',
                      help='schedule file name',
                      default='')
    parser.add_option(
        '-C',
        '--choose-cheapest',
        action='store_true',
        dest='choosecheapest',
        default=False,
        help=
        'override weightened offers picking and choose cheapest. this might reduce anonymity.')
    parser.add_option(
        '-P',
        '--pick-orders',
        action='store_true',
        dest='pickorders',
        default=False,
        help=
        'manually pick which orders to take. doesn\'t work while sweeping.')
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
    parser.add_option(
        '--rpcwallet',
        action='store_true',
        dest='userpcwallet',
        default=False,
        help=('Use the Bitcoin Core wallet through json rpc, instead '
              'of the internal joinmarket wallet. Requires '
              'blockchain_source=json-rpc'))
    parser.add_option('--fast',
                      action='store_true',
                      dest='fastsync',
                      default=False,
                      help=('choose to do fast wallet sync, only for Core and '
                            'only for previously synced wallet'))
    return parser

    