import pytest
import os
import time
import subprocess

bitcoin_path = None
bitcoin_conf = None
bitcoin_rpcpassword = None
bitcoin_rpcusername = None
miniircd_procs = []

def local_command(command, bg=False, redirect=''):
    if redirect == 'NULL':
        if OS == 'Windows':
            command.append(' > NUL 2>&1')
        elif OS == 'Linux':
            command.extend(['>', '/dev/null', '2>&1'])
        else:
            print "OS not recognised, quitting."
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
        return subprocess.check_output(command)

def pytest_addoption(parser):
    parser.addoption("--btcroot", action="store", default='',
                     help="the fully qualified path to the directory containing "+\
                     "the bitcoin binaries, e.g. /home/user/bitcoin/bin/")
    parser.addoption("--btcconf", action="store",
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
    #start up regtest blockchain
    btc_proc = subprocess.call([bitcoin_path + "bitcoind", "-regtest",
                                "-daemon", "-conf=" + bitcoin_conf])
    time.sleep(3)
    #generate blocks; segwit activates around block 500-600
    for i in range(2):
        local_command([bitcoin_path + "bitcoin-cli", "-regtest",
                       "-rpcuser=" + bitcoin_rpcusername,
                       "-rpcpassword=" + bitcoin_rpcpassword, "generate", "301"])
        time.sleep(1)
    
