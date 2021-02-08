from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from builtins import *
import pytest
import re
import os
import time
import subprocess

bitcoin_path = None
bitcoin_conf = None
bitcoin_rpcpassword = None
bitcoin_rpcusername = None
miniircd_procs = []

def get_bitcoind_version(version_string):
    # this utility function returns the version number
    # as a tuple in the form (major, minor, patch)
    version_tuple = re.match(
        b'.*v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)',
        version_string).groups()
    return tuple(map(lambda x: int(x), version_tuple))

def local_command(command, bg=False, redirect=''):
    if redirect == 'NULL':
        if OS == 'Windows':
            command.append(' > NUL 2>&1')
        elif OS == 'Linux':
            command.extend(['>', '/dev/null', '2>&1'])
        else:
            print("OS not recognised, quitting.")
    elif redirect:
        command.extend(['>', redirect])

    if bg:
        #using subprocess.PIPE seems to cause problems
        FNULL = open(os.devnull, 'w')
        return subprocess.Popen(command,
                                stdout=FNULL,
                                stderr=subprocess.STDOUT,
                                close_fds=True)
    else:
        #in case of foreground execution, we can use the output; if not
        #it doesn't matter
        return subprocess.run(command, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

def root_path():
    # returns the directory in which this file is contained
    return os.path.dirname(os.path.realpath(__file__))

def pytest_addoption(parser):
    parser.addoption("--btcroot", action="store", default='',
                     help="the fully qualified path to the directory containing "+\
                     "the bitcoin binaries, e.g. /home/user/bitcoin/bin/")
    parser.addoption("--btcconf", action="store",
                         default=os.path.join(root_path(), 'test/bitcoin.conf'),
                         help="the fully qualified path to the location of the "+\
                         "bitcoin configuration file you use for testing, e.g. "+\
                         "/home/user/.bitcoin/bitcoin.conf")
    parser.addoption("--btcpwd",
                     action="store",
                     help="the RPC password for your test bitcoin instance")
    parser.addoption("--btcuser",
                     action="store",
                     default='bitcoinrpc',
                     help="the RPC username for your test bitcoin instance (default=bitcoinrpc)")
    parser.addoption("--nirc",
                         type="int",
                         action="store",
                         default=1,
    help="the number of local miniircd instances")

def teardown():
    #didn't find a stop command in miniircd, so just kill
    global miniircd_procs
    for m in miniircd_procs:
        m.kill()
    #shut down bitcoin and remove the regtest dir
    local_command([bitcoin_path + "bitcoin-cli", "-regtest", "-rpcuser=" + bitcoin_rpcusername,
                   "-rpcpassword=" + bitcoin_rpcpassword, "stop"])
    #note, it is better to clean out ~/.bitcoin/regtest but too
    #dangerous to automate it here perhaps


@pytest.fixture(scope="session", autouse=True)
def setup(request):
    request.addfinalizer(teardown)

    global bitcoin_conf, bitcoin_path, bitcoin_rpcpassword, bitcoin_rpcusername
    bitcoin_path = request.config.getoption("--btcroot")
    bitcoin_conf = request.config.getoption("--btcconf")
    print("Here is the bitcoin_conf path:")
    print(bitcoin_conf)
    bitcoin_rpcpassword = request.config.getoption("--btcpwd")
    bitcoin_rpcusername = request.config.getoption("--btcuser")

    #start up miniircd
    #minor bug in miniircd (seems); need *full* unqualified path for motd file
    cwd = os.getcwd()
    n_irc = request.config.getoption("--nirc")
    global miniircd_procs
    for i in range(n_irc):
        miniircd_proc = local_command(
            ["./miniircd/miniircd", "--ports=" + str(6667+i),
             "--motd=" + cwd + "/miniircd/testmotd"],
            bg=True)
        miniircd_procs.append(miniircd_proc)

    # determine bitcoind version
    bitcoind_version_string = subprocess.check_output([bitcoin_path + "bitcoind", "-version"]).split(b'\n')[0]
    bitcoind_version = get_bitcoind_version(bitcoind_version_string)

    #start up regtest blockchain
    bitcoin_args = ["-regtest", "-daemon", "-conf=" + bitcoin_conf]

    btc_proc = subprocess.call([bitcoin_path + "bitcoind"] + bitcoin_args)
    root_cmd = [bitcoin_path + "bitcoin-cli", "-regtest",
                       "-rpcuser=" + bitcoin_rpcusername,
                       "-rpcpassword=" + bitcoin_rpcpassword]
    # Bitcoin Core v0.21+ does not create default wallet
    local_command(root_cmd + ["-rpcwait"] +
        ["createwallet", "jm-test-wallet"])
    local_command(root_cmd + ["loadwallet", "jm-test-wallet"])
    for i in range(2):
        cpe = local_command(root_cmd + ["-rpcwallet=jm-test-wallet"] +
            ["getnewaddress"])
        if cpe.returncode == 0:
            destn_addr = cpe.stdout[:-1].decode('utf-8')
            local_command(root_cmd + ["-rpcwallet=jm-test-wallet"] +
                ["generatetoaddress", "301", destn_addr])
        else:
            pytest.exit("Cannot setup tests, bitcoin-cli failing.\n" +
                str(cpe.stdout))
        time.sleep(1)
    
