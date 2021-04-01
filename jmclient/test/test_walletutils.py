import pytest
from jmbitcoin import select_chain_params
from jmclient import (SegwitLegacyWallet, SegwitWallet, get_network,
                      jm_single, VolatileStorage, load_test_config)
from jmclient.wallet_utils import (bip32pathparse, WalletView,
                                   WalletViewAccount, WalletViewBranch,
                                   WalletViewEntry, wallet_signmessage)

# The below signatures have all been verified against Electrum 4.0.9:
@pytest.mark.parametrize('seed, hdpath, walletcls, message, sig, addr', [
    [b"\x01"*16, "m/84'/0'/0'/0/0", SegwitWallet, "hello",
     "IOLk6ct/8aKtvTNnEAc+xojIWKv5FOwnzHGcnHkTJJwRBAyhrZ2ZyB0Re+dKS4SEav3qgjQeqMYRm+7mHi4sFKA=",
     "bc1qq53d9372u8d50jfd5agq9zv7m7zdnzwducuqgz"],
    [b"\x01"*16, "m/49'/0'/0'/0/0", SegwitLegacyWallet, "hello",
     "HxVaQuXyBpl1UKutiusJjeLfKHwJYBzUiWuu6hEbmNFeSZGt/mbXKJ071ANR1gvdICbS/AnEa2RKDq9xMd/nU8s=",
     "3AdTcqdoLHFGNq6znkahJDT41u65HAwiRv"],
    [b"\x02"*16, "m/84'/0'/2'/1/0", SegwitWallet, "sign me",
     "IA/V5DG7u108aNzCnpNPHqfrJAL8pF4GQ0sSqpf4Vlg5UWizauXzh2KskoD6Usl13hzqXBi4XDXl7Xxo5z6M298=",
     "bc1q8mm69xs740sr0l2umrhmpl4ewhxfudxg2zvjw5"],
    [b"\x02"*16, "m/49'/0'/2'/1/0", SegwitLegacyWallet, "sign me",
     "H4cAtoE+zL+Mr+U8jm9DiYxZlym5xeZM3mcgymLz+TF4YYr4lgnM8qTZhFwlK4izcPaLuF27LFEoGJ/ltleIHUI=",
     "3Qan1D4Vcy1yMGHfR9j7szDuC8QxSFVScA"],
])
def test_signmessage(seed, hdpath, walletcls, message, sig, addr):
    load_test_config()
    jm_single().config.set('BLOCKCHAIN', 'network', 'mainnet')
    select_chain_params("bitcoin/mainnet")
    storage = VolatileStorage()
    walletcls.initialize(
        storage, get_network(), entropy=seed, max_mixdepth=3)
    wallet = walletcls(storage)
    s, m, a = wallet_signmessage(wallet, hdpath, message,
                                        out_str=False)
    assert (s, m, a) == (sig, message, addr)
    jm_single().config.set("BLOCKCHAIN", "network", "testnet")
    select_chain_params("bitcoin/regtest")

def test_bip32_pathparse():
    assert bip32pathparse("m/2/1/0017")
    assert not bip32pathparse("n/1/1/1/1")
    assert bip32pathparse("m/0/1'/100'/3'/2/2/21/004/005")
    assert not bip32pathparse("m/0/0/00k")


def test_walletview():
    rootpath = "m/0"
    walletbranch = 0
    accounts = range(3)
    acctlist = []
    for a in accounts:
        branches = []
        for address_type in range(2):
            entries = []
            for i in range(4):
                entries.append(WalletViewEntry(rootpath, a, address_type,
                    i, "DUMMYADDRESS" + str(i+a), [i*10000000, i*10000000]))
            branches.append(WalletViewBranch(rootpath, a, address_type,
                branchentries=entries,
                xpub="xpubDUMMYXPUB" + str(a + address_type)))
        acctlist.append(WalletViewAccount(rootpath, a, branches=branches))
    wallet = WalletView(rootpath + "/" + str(walletbranch),
        accounts=acctlist)
    assert(wallet.serialize() == (
        'JM wallet\n'
        'mixdepth\t0\n'
        'external addresses\tm/0\txpubDUMMYXPUB0\n'
        'm/0                 \tDUMMYADDRESS0\t0.00000000\tnew\n'
        'm/0                 \tDUMMYADDRESS1\t0.10000000\tnew\n'
        'm/0                 \tDUMMYADDRESS2\t0.20000000\tnew\n'
        'm/0                 \tDUMMYADDRESS3\t0.30000000\tnew\n'
        'Balance:\t0.60000000\n'
        'internal addresses\tm/0\txpubDUMMYXPUB1\n'
        'm/0                 \tDUMMYADDRESS0\t0.00000000\tnew\n'
        'm/0                 \tDUMMYADDRESS1\t0.10000000\tnew\n'
        'm/0                 \tDUMMYADDRESS2\t0.20000000\tnew\n'
        'm/0                 \tDUMMYADDRESS3\t0.30000000\tnew\n'
        'Balance:\t0.60000000\n'
        'Balance for mixdepth 0:\t1.20000000\n'
        'mixdepth\t1\n'
        'external addresses\tm/0\txpubDUMMYXPUB1\n'
        'm/0                 \tDUMMYADDRESS1\t0.00000000\tnew\n'
        'm/0                 \tDUMMYADDRESS2\t0.10000000\tnew\n'
        'm/0                 \tDUMMYADDRESS3\t0.20000000\tnew\n'
        'm/0                 \tDUMMYADDRESS4\t0.30000000\tnew\n'
        'Balance:\t0.60000000\n'
        'internal addresses\tm/0\txpubDUMMYXPUB2\n'
        'm/0                 \tDUMMYADDRESS1\t0.00000000\tnew\n'
        'm/0                 \tDUMMYADDRESS2\t0.10000000\tnew\n'
        'm/0                 \tDUMMYADDRESS3\t0.20000000\tnew\n'
        'm/0                 \tDUMMYADDRESS4\t0.30000000\tnew\n'
        'Balance:\t0.60000000\n'
        'Balance for mixdepth 1:\t1.20000000\n'
        'mixdepth\t2\n'
        'external addresses\tm/0\txpubDUMMYXPUB2\n'
        'm/0                 \tDUMMYADDRESS2\t0.00000000\tnew\n'
        'm/0                 \tDUMMYADDRESS3\t0.10000000\tnew\n'
        'm/0                 \tDUMMYADDRESS4\t0.20000000\tnew\n'
        'm/0                 \tDUMMYADDRESS5\t0.30000000\tnew\n'
        'Balance:\t0.60000000\n'
        'internal addresses\tm/0\txpubDUMMYXPUB3\n'
        'm/0                 \tDUMMYADDRESS2\t0.00000000\tnew\n'
        'm/0                 \tDUMMYADDRESS3\t0.10000000\tnew\n'
        'm/0                 \tDUMMYADDRESS4\t0.20000000\tnew\n'
        'm/0                 \tDUMMYADDRESS5\t0.30000000\tnew\n'
        'Balance:\t0.60000000\n'
        'Balance for mixdepth 2:\t1.20000000\n'
        'Total balance:\t3.60000000'))

