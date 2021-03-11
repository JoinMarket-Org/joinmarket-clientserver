# Fidelity bonds

Fidelity bonds are a feature of JoinMarket which improves the resistance to
sybil attacks, and therefore improves the privacy of the system.

## This feature is incomplete and so is disabled for now

A fidelity bond is a mechanism where bitcoin value is deliberately sacrificed
to make a cryptographic identity expensive to obtain. The sacrifice is done in
a way that can be proven to a third party. Takers in JoinMarket will
have a higher probability to create coinjoins with makers who publish more
valuable fidelity bonds. This has the effect of making the system much more
expensive to sybil attack, because an attacker would have to sacrifice a lot of
value in order to be chosen very often by takers when creating coinjoin.

As a maker you can take part in many more coinjoins and therefore earn more
fees if you sacrifice bitcoin value to create a fidelity bond. The most
practical way to create a fidelity bond is to send bitcoins to a time-locked
address which uses the opcode [OP_CHECKLOCKTIMEVERIFY](https://en.bitcoin.it/wiki/Timelock#CheckLockTimeVerify).
The valuable thing being sacrificed is the time-value-of-money. Note that a
long-term holder (or hodler) of bitcoins can buy time-locked fidelity bonds
essentially for free, assuming they never intended to transact with their coins
anyway.

Another way to create fidelity bonds is to destroy coins by sending them to a
[OP_RETURN](https://en.bitcoin.it/wiki/Script#Provably_Unspendable.2FPrunable_Outputs)
output.

The private keys to fidelity bonds can be kept in [cold storage](https://en.bitcoin.it/wiki/Cold_storage)
for added security.

For a more detailed explanation of how fidelity bonds work see these documents:

* [Design for improving JoinMarket's resistance to sybil attacks using fidelity
bonds](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af/)

* [Financial mathematics of JoinMarket fidelity bonds](https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b)

#### Note on privacy

Bitcoin outputs which create fidelity bonds will be published to the entire
world, so before and after creating them make sure the outputs are not linked
to your identity in any way. Perhaps mix with JoinMarket before and after.

### Creating a JoinMarket wallet which supports fidelity bonds

When generating a JoinMarket wallet on the command line, supporting versions
will offer an option to make the wallet support fidelity bonds.

    (jmvenv) $ python3 wallet-tool.py generate
    Would you like to use a two-factor mnemonic recovery phrase? write 'n' if you don't know what this is (y/n): n
    Not using mnemonic extension
    Enter wallet file encryption passphrase: 
    Reenter wallet file encryption passphrase: 
    Input wallet file name (default: wallet.jmdat): testfidelity.jmdat
    Would you like this wallet to support fidelity bonds? write 'n' if you don't know what this is (y/n): y
    Write down this wallet recovery mnemonic

    evidence initial knee image inspire plug dad midnight blast awkward clean between

    Generated wallet OK

As always, it is crucially important to write down the 12-word [seed phrase](https://en.bitcoin.it/wiki/Seed_phrase)
as a backup. It is also recommended to write down the name of the creating wallet
"JoinMarket" and that the fidelity bond option was enabled. Writing the wallet
creation date is also useful as it can help with rescanning.

### Obtaining time-locked addresses

The `wallet-tool.py` script supports a new method `gettimelockaddress` used for
obtaining time-locked addresses. If coins are sent to these addresses they will
be locked up until the timelock date passes. Only mixdepth zero can have
fidelity bonds in it.

This example creates an address which locks any coins sent to it until April 2020.

    (jmvenv) $ python3 wallet-tool.py testfidelity.jmdat gettimelockaddress 2020-4
    Enter wallet decryption passphrase: 
    path = m/49'/1'/0'/2/3:1585699200
    Coins sent to this address will be not be spendable until April 2020. Full date: 2020-04-01 00:00:00
    bcrt1qrc2qu3m2l2spayu5kr0k0rnn9xgjz46zsxmruh87a3h3f5zmnkaqlfx7v5

If coins are sent to these addresses they will appear in the usual `wallet-tool.py`
display:

    (jmvenv) $ python3 wallet-tool.py -m 0 testfidelity.jmdat
    Enter wallet decryption passphrase: 
    JM wallet
    mixdepth    0   fbonds-mpk-tpubDDCbCPdf5wJVGYWB4mZr3E3Lys4NBcEKysrrUrLfhG6sekmrvs6KZNe4i5p5z3FyfwRmKMqB9NWEcEUiTS4LwqfrKPQzhKj6aLihu2EejaU
    external addresses  m/49'/1'/0'/0   tpubDEGdmPwmQRcZmGKhaudjch9Fgw4J5yP4bYw5B8LoSDkMdmhBxM4ndEQXHK4r1TPexGjLidxdpeEzsJcdXEe7khWToxCZuN6JiLzvUoHAki2
    m/49'/1'/0'/0/0         2N8jHuQaApgFtQ8UKxKbREAvNxKn4BGX4x2 0.00000000  new
    m/49'/1'/0'/0/1         2Mx5CwDoNcuCT38EDmgenQxv9skHbZfXFdo 0.00000000  new
    m/49'/1'/0'/0/2         2N1tNTTwNyucGGmfDWNVk3AUi3i5S8jVKqn 0.00000000  new
    m/49'/1'/0'/0/3         2N8eBEU5wpWb6kS1gvbRgewtxsmXsMkShV6 0.00000000  new
    m/49'/1'/0'/0/4         2MuHgeSgMsvkcn6aGNW2uk2UXP3xVVnkfh2 0.00000000  new
    m/49'/1'/0'/0/5         2NA8d8um5KmBNNR8dadhbEDYGiTJPFCdjMB 0.00000000  new
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/1   
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/2   tpubDEGdmPwmQRcZrzjRmUFqXXyLdRedwxCWQviAFqDe6sXJeZzRNTwmwqMfxN6Ka3v7hEebstrU5kqUNoHsFKaA3RoB2vopL6kLHVo1EQq6USw
    m/49'/1'/0'/2/0:1585699200  bcrt1qrc2qu3m2l2spayu5kr0k0rnn9xgjz46zsxmruh87a3h3f5zmnkaqlfx7v5    0.15000000  2020-04-01 [LOCKED]
    Balance:    0.15000000
    Balance for mixdepth 0: 0.15000000

#### Spending time-locked coins

Once the time-lock of an address expires the coins can be spent with JoinMarket.

Coins living on time-locked addresses are automatically frozen with
JoinMarket's coin control feature, so before spending you need to unfreeze the
coins using `python3 wallet-tool.py <walletname> -m 0 freeze`.

Once unfrozen and untimelocked the coins can be spent normally with the scripts
`sendpayment.py`, `tumber.py`, or yield generator.

### Burning coins

Coins can be burned with a special method of the `sendpayment.py` script. Set
the destination to be `BURN`. Transactions which burn coins must only have one
input and one output, so use coin control to freeze all coins in the zeroth
mixdepth except one.

    $ python3 sendpayment.py -N 0 testfidelity3.jmdat 0 BURN
    User data location: .
    2020-04-07 20:45:25,658 [INFO]  Using this min relay fee as tx fee floor: 1000 sat/vkB (1.0 sat/vB)
    Enter wallet decryption passphrase: 
    2020-04-07 20:46:50,449 [INFO]  Estimated miner/tx fees for this coinjoin amount: 0.0%
    2020-04-07 20:46:50,452 [INFO]  Using this min relay fee as tx fee floor: 1000 sat/vkB (1.0 sat/vB)
    2020-04-07 20:46:50,452 [INFO]  Using a fee of : 0.00000200 BTC (200 sat).
    2020-04-07 20:46:50,454 [INFO]  Got signed transaction:

    2020-04-07 20:46:50,455 [INFO]  {'ins': [{'outpoint': {'hash': '61d69b4e7abe0ef8a5a9cbabb05463259c3b497a142130a56f81a9259f048cb0',
                           'index': 0},
              'script': '160014295beb4eba9b35896683d5b5ff455ee2c646054c',
              'sequence': 4294967294,
              'txinwitness': ['3045022100939de908e30015c6b22d2c0f25153e395268466ce44eeeb4ec03a8920440e87b0220155d1c43dedb3fc2654205541bb2821dd5211180e2d7f93d67301470652830d401',
                              '03ec0f8b267f99ff5259195ce63813d58f38ffbaada894ce06af0c0303c74bbf82']}],
     'locktime': 1361,
     'outs': [{'script': '6a147631c805d8ad9239677b8d7530353fda3fec07ca',
               'value': 11999800}],
     'version': 2}
    2020-04-07 20:46:50,455 [INFO]  In serialized form (for copy-paste):
    2020-04-07 20:46:50,455 [INFO]  02000000000101b08c049f25a9816fa53021147a493b9c256354b0abcba9a5f80ebe7a4e9bd6610000000017160014295beb4eba9b35896683d5b5ff455ee2c646054cfeffffff01381ab70000000000166a147631c805d8ad9239677b8d7530353fda3fec07ca02483045022100939de908e30015c6b22d2c0f25153e395268466ce44eeeb4ec03a8920440e87b0220155d1c43dedb3fc2654205541bb2821dd5211180e2d7f93d67301470652830d4012103ec0f8b267f99ff5259195ce63813d58f38ffbaada894ce06af0c0303c74bbf8251050000
    2020-04-07 20:46:50,456 [INFO]  Sends: 0.11999800 BTC (11999800 sat) to destination: BURNER OUTPUT embedding pubkey at m/49'/1'/0'/3/0

    WARNING: This transaction if broadcasted will PERMANENTLY DESTROY your bitcoins

    Would you like to push to the network? (y/n):y
    2020-04-07 20:47:52,047 [DEBUG]  rpc: sendrawtransaction ['02000000000101b08c049f25a9816fa53021147a493b9c256354b0abcba9a5f80ebe7a4e9bd6610000000017160014295beb4eba9b35896683d5b5ff455ee2c646054cfeffffff01381ab70000000000166a147631c805d8ad9239677b8d7530353fda3fec07ca02483045022100939de908e30015c6b22d2c0f25153e395268466ce44eeeb4ec03a8920440e87b0220155d1c43dedb3fc2654205541bb2821dd5211180e2d7f93d67301470652830d4012103ec0f8b267f99ff5259195ce63813d58f38ffbaada894ce06af0c0303c74bbf8251050000']
    2020-04-07 20:47:52,049 [WARNING]  Connection had broken pipe, attempting reconnect.
    2020-04-07 20:47:52,440 [INFO]  Transaction sent: 656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7
    done

Embedded in the `OP_RETURN` output is the hash of a pubkey from the wallet.

Now `OP_RETURN` outputs are not addresses, and because of technical reasons the
first time they are synchronized the flag `--recoversync` must be used. When
this is done the burn output will appear in the `wallet-tool.py` display.
`--recoversync` only needs to be used once, and after that the burner output is
saved in the `wallet.jmdat` file which can be accesses by all future
synchronizations.

    $ python3 wallet-tool.py --datadir=. --recoversync testfidelity2.jmdat
    Enter wallet decryption passphrase: 
    2020-04-07 23:09:54,644 [INFO]  Found a burner transaction txid=656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7 path = m/49'/1'/0'/3/0
    2020-04-07 23:09:54,769 [WARNING]  Merkle branch not available, use wallet-tool `addtxoutproof`
    2020-04-07 23:09:55,420 [INFO]  Found a burner transaction txid=656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7 path = m/49'/1'/0'/3/0
    2020-04-07 23:09:55,422 [WARNING]  Merkle branch not available, use wallet-tool `addtxoutproof`
    JM wallet
    mixdepth    0   fbonds-mpk-tpubDDCXgSpdxuVbXgzRYBggFeMRNeV9eH24jJuQNunyqwYtDFiB7ZS63LhXwHkf7o9ZcZW4qUz7uvD6yk4BkkF3bBPmJRPv7RBTEA5hHwEdV2f
    external addresses  m/49'/1'/0'/0   tpubDEJGorVywRb6LoLQbaqWZh2gYwpdZqViCNZ2ejB5kpBuUp16LHpK6ESFaJLixidtbmmjcDwVZ4QjnAbKmypfuGaEk3ifgonPv4vsugqgp9G
    m/49'/1'/0'/0/2         2MviB2FfLKZjFb3W2dJ8kXcQBj3jqMJg7TL 0.00000000  new
    m/49'/1'/0'/0/3         2MtsAQhE2u9VGV3aZ7XM4PzwWGHXr4PAhqP 0.00000000  new
    m/49'/1'/0'/0/4         2N3iXNjS4vkTXzy5Jidnovc6FJeNQJx5Fnt 0.00000000  new
    m/49'/1'/0'/0/5         2MtT4XAjwQQ7PBbrTxv7qcQMMmz4Rs5XrE3 0.00000000  new
    m/49'/1'/0'/0/6         2NEuG23BQESuZTqSDtab9zYsd1Jb4KfMULB 0.00000000  new
    m/49'/1'/0'/0/7         2N6NGJRX6KYQWtYWK8iHFuJNpZRs8NbUAC9 0.00000000  new
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/1
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/2   tpubDEJGorVywRb6T34X7ZAEz9hQYn6CCEhrcFa8kA2mqNau2DvoggZP2QTtXRe8t9NSfMkx3ye8QDzqCE9gEqso6fw5ALk5xycWLFwTRLSqSUV
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/3   tpubDEJGorVywRb6V5em9Q7LFJ9eLEAEZmZxUdDmkknrKNUs7vKcCWPKwP8YPjuxFCCXk2F1wJnubNbmgbtWed5yiE3D1qxzLonVuXT6QEZPaof
    m/49'/1'/0'/3/0         BURN-7631c805d8ad9239677b8d7530353fda3fec07ca   0.11999800  656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7 [NO MERKLE PROOF]
    Balance:    0.11999800
    Balance for mixdepth 0: 0.11999800

#### Adding the merkle proof of a burn transaction if missing

In order to prove a burn output exists, a merkle proof is needed. If the Core
node is pruned and the block deleted then JoinMarket will not be able to obtain
the merkle proof (as in the above example). In this case the proof can be
added separately.

Any other unpruned Core node can trustlessly obtain the proof and give it to
the user with the RPC call `gettxoutproof`.

First obtain the merkle proof:

    $ bitcoin-cli gettxoutproof "[\"656bb4538f14f2cc874043915907b6c9c46a807ef9818bde771d07630d54b0f7\"]" 4cce28f4eb1ea1762ec4ceb90529b3ab28c0423ac630c6292319e2b2712daada
    0000002056e4050f54084a1d6e6944b209cce76ebe2da4b37f3aa47ab6c612831d3220471015e80d3050cf0ee05b216036030fe3d4906221196943a30e828741ad4cfaeb05d98c5effff7f20010000000200000002a5910e5cf4e6cb6d55e1e2ca979987772a482e8a8f30b7a6cab8c5671f5c161df7b0540d63071d77de8b81f97e806ac4c9b6075991434087ccf2148f53b46b650105

Then add it to the JoinMarket wallet:

    $ python3 wallet-tool.py -H "m/49'/1'/0'/3/0" testfidelity2.jmdat addtxoutproof 0000002056e4050f54084a1d6e6944b209cce76ebe2da4b37f3aa47ab6c612831d3220471015e80d3050cf0ee05b216036030fe3d4906221196943a30e828741ad4cfaeb05d98c5effff7f20010000000200000002a5910e5cf4e6cb6d55e1e2ca979987772a482e8a8f30b7a6cab8c5671f5c161df7b0540d63071d77de8b81f97e806ac4c9b6075991434087ccf2148f53b46b650105
    Enter wallet decryption passphrase: 
    Done

The `-H` flag must point to the path containing the burn output.

Then synchronizing the wallet won't output the no-merkle-proof warning.

### Creating watch-only fidelity bond wallets

Fidelity bonds can be held on an offline computer in
[cold storage](https://en.bitcoin.it/wiki/Cold_storage). To do this we create
a watch-only fidelity bond wallet.

When fidelity bonds are displayed in `wallet-tool.py`, their master public key
is highlighted with a prefix `fbonds-mpk-`.

This master public key can be used to create a watch-only wallet using
`wallet-tool.py`.

    $ python3 wallet-tool.py createwatchonly fbonds-mpk-tpubDDCbCPdf5wJVGYWB4mZr3E3Lys4NBcEKysrrUrLfhG6sekmrvs6KZNe4i5p5z3FyfwRmKMqB9NWEcEUiTS4LwqfrKPQzhKj6aLihu2EejaU
    Input wallet file name (default: watchonly.jmdat): watchfidelity.jmdat
    Enter wallet file encryption passphrase: 
    Reenter wallet file encryption passphrase: 
    Done

Then the wallet can be displayed like a regular wallet, although only the zeroth
mixdepth will be shown.

    $ python3 wallet-tool.py watchfidelity.jmdat
    User data location: .
    Enter wallet decryption passphrase: 
    JM wallet
    mixdepth    0   fbonds-mpk-tpubDDCbCPdf5wJVGYWB4mZr3E3Lys4NBcEKysrrUrLfhG6sekmrvs6KZNe4i5p5z3FyfwRmKMqB9NWEcEUiTS4LwqfrKPQzhKj6aLihu2EejaU
    external addresses  m/49'/1'/0'/0   tpubDEGdmPwmQRcZmGKhaudjch9Fgw4J5yP4bYw5B8LoSDkMdmhBxM4ndEQXHK4r1TPexGjLidxdpeEzsJcdXEe7khWToxCZuN6JiLzvUoHAki2
    m/49'/1'/0'/0/0         2N8jHuQaApgFtQ8UKxKbREAvNxKn4BGX4x2 0.00000000  used
    m/49'/1'/0'/0/1         2Mx5CwDoNcuCT38EDmgenQxv9skHbZfXFdo 0.00000000  new
    m/49'/1'/0'/0/2         2N1tNTTwNyucGGmfDWNVk3AUi3i5S8jVKqn 0.00000000  new
    m/49'/1'/0'/0/3         2N8eBEU5wpWb6kS1gvbRgewtxsmXsMkShV6 0.00000000  new
    m/49'/1'/0'/0/4         2MuHgeSgMsvkcn6aGNW2uk2UXP3xVVnkfh2 0.00000000  new
    m/49'/1'/0'/0/5         2NA8d8um5KmBNNR8dadhbEDYGiTJPFCdjMB 0.00000000  new
    m/49'/1'/0'/0/6         2NG76BAHPccfyy6sH68EHrB9QJBycx3FKb6 0.00000000  new
    Balance:    0.25000000
    internal addresses  m/49'/1'/0'/1
    Balance:    0.00000000
    internal addresses  m/49'/1'/0'/2   tpubDEGdmPwmQRcZrzjRmUFqXXyLdRedwxCWQviAFqDe6sXJeZzRNTwmwqMfxN6Ka3v7hEebstrU5kqUNoHsFKaA3RoB2vopL6kLHVo1EQq6USw
    m/49'/1'/0'/0/3:1585699200  bcrt1qrc2qu3m2l2spayu5kr0k0rnn9xgjz46zsxmruh87a3h3f5zmnkaqlfx7v5    0.15000000  2020-04-01 [UNLOCKED]
    Balance:    0.15000000
    internal addresses  m/49'/1'/0'/3   tpubDEGdmPwmQRcZuX3uNrCouu5bRgp2GJcoQTvhkFAJMTA3yxhKmQyeGwecbnkms4DYmBhCJn2fGTuejTe3g8oyJW3qKcfB4b3Swj2hDk1h4Y2
    Balance:    0.00000000
    Balance for mixdepth 0: 0.15000000

### BIP32 Paths

Fidelity bond wallets extend the BIP32 path format to include the locktime
values. In this example we've got `m/49'/1'/0'/2/0:1583020800` where the
number after the colon is the locktime value in Unix time.

This path can be passed to certain wallet methods like `dumpprivkey`.

    $ python3 wallet-tool.py -H "m/49'/1'/0'/2/0:1583020800" testfidelity.jmdat dumpprivkey
    Enter wallet decryption passphrase: 
    cNEuE5ypNTxVFCyC5iH7u5AQTrddamcUHRPNweiLvmHUWd6XXDkz

