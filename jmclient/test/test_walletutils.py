
from jmclient.wallet_utils import bip32pathparse, WalletView, \
    WalletViewAccount, WalletViewBranch, WalletViewEntry


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

