# UPGRADING YOUR JOINMARKET TO NATIVE SEGWIT (bech32)

## Motivation: why?

I guess the large majority of Joinmarket users know, but for completeness: native segwit p2wpkh is substantially (perhaps 25% on average?) cheaper than p2sh-p2wpkh which we currently use, and is rapidly becoming industry standard amongst most users wallets and other Bitcoin transaction operators, including other coinjoin systems, e.g. Wasabi - this latter point is very important in that it helps with privacy to join in with the crowd. In particular, Payjoins require both wallets to use the same scriptPubkey (or address) type.

## Do I need to do anything at all?

Technically, no, but realistically, yes.

If you do nothing here's what will happen:

### As a maker

You can continue to run your maker bot (yield generator), serving Taker customers still using p2sh ('3') addresses with your existing wallet. The traffic on these will go down over time because (a) native segwit transactions are cheaper, and Takers bear most of that cost, and (b) the default new wallet type is now native segwit, so new entrants will be creating wallets of that type, and using the native segwit pit, and so ignoring your bots.

### As a taker

If you have an existing wallet and still want to do joins with it with '3' addresses, you can do so, but you must set `native=false` in `[POLICY]` section of `joinmarket.cfg` - assuming you don't have this setting already (the point here is that the *default* value of that setting has changed from `false` to `true` as of 0.8.0). If you are just using `wallet-tool` or direct-sending payments, you don't even need to make that change, but you may as well do it, for as long as you are using the old wallet type.

## How is the orderbook changing?

So what we sometimes call the "trading pit" is basically all the bots announcing their offers on the different IRC servers. Currently they all take the form:

`!swreloffer blah blah`
`!swabsoffer blah blah`

(because there are no bots left using non-segwit offers or wallets). These offers will continue for some time, but in parallel, as of v0.8.0, you will start to see bots making offers with '0' included ('0' because segwit v0, albeit this is not a scientific distinction, but it was just easiest to use a single character):

`!sw0reloffer blah blah`
`!sw0absoffer blah blah`

Under the hood, there will be very little difference in the way the bots behave; the set of messages they pass is almost the same (but not quite, technical details). **This set of offers is entirely distinct; we are creating new coinjoins with native coinjoin outputs only, not a mixture of native and p2sh together**. This is unfortunately necessary in order for users to be able to make reasonable assumptions about anonymity sets (i.e. mixed address types screw that up).

## How is the wallet changing, when I make a new one?

First, this feature has been present in Joinmarket since early 2019 (see [release notes for v0.5.1](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.5.1.md#add-native-segwit-wallet-to-backend); it is not actually new.
Second the actual wallet type is [BIP 84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki), the de facto industry standard for native segwit single-key wallets, and is directly analogous to [BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) that we use for p2sh-p2wpkh addresses.
The seed creation and recovery are therefore unchanged: we use the same BIP39 12 word seed phrase, with optional mnemonic extension as before. What changes is the HD path (e.g. m/84'/0'/0'/0/0) and address, of course. At the bottom of this page is an example mainnet wallet-tool output for the new wallet type.

## OK, so how do I actually migrate, i.e. move to the new wallet type and orderbook?

* Create a new wallet: either omitting the `native=` setting or setting it to `true`, *before* you run `python wallet-tool.py generate` or 'Generate' in Qt.
* Move funds into it, like any new wallet; if you are moving from an old Joinmarket wallet to this new one, I suggest doing sweeps per-mixdepth, but (a) you can use coin-freezing to use individual coins and not connect them, if you prefer, (b) using a coinjoin on the *old* Joinmarket pit to do the transfer may not make much sense, since the output address will be 'bc1' not '3' and so the anon set effect will be lost.

Once the funds are migrated, you can just go back to what you were doing before - except with lower fees. All pre-existing functions work the same way with these BIP84 wallets.

##### Example output of wallet-tool display:

```
JM wallet
mixdepth	0	xpub6CnATD8P29cQT8q4TWBFjGeAtxzq87WsoiCdmMTxBWu9mgpW1kruDA6kHrcYPYiYbjGWnM6wrFZN18MqYgcpyRjmrfVvxVUUTaD6F3mvqM3
external addresses	m/84'/0'/0'/0	xpub6EUm47xofFfo6QY1nYq6ASX3xfbhfFqS1XqMqayNUsjzTze2sPvCHtd9MmZ258jmMq26ViDUsXjEEmUVvTNyW72P688nVHn4gHBs59oR55F
m/84'/0'/0'/0/0     	bc1qfljx5g2jdgf8y6r5mx94um43vqy73uxrrfu2rc	0.00000000	new
m/84'/0'/0'/0/1     	bc1qq2y0vnzdxmvelfgp9au37v4acqc9vapkpn6s0e	0.00000000	new
m/84'/0'/0'/0/2     	bc1qkeaqdwn49djzwqmaqgqathd23ygq0reu9clgl2	0.00000000	new
m/84'/0'/0'/0/3     	bc1qj0e2kjc2dkqn4drh4l8vdmygdp5z6mzqm84xlj	0.00000000	new
m/84'/0'/0'/0/4     	bc1qwrfpc565l4n5yq073lkht62zztfjy8qck5c75r	0.00000000	new
m/84'/0'/0'/0/5     	bc1q4ju2gvrqdv4epxcezydmd9jjuk7yf4l6trnmsl	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/0'/1	
Balance:	0.00000000
Balance for mixdepth 0:	0.00000000
mixdepth	1	xpub6CnATD8P29cQWAVv5chkF9dShxFTtkp68C92d6XvWneqMpqgxd5V3kxCJkiCBGfuMvHNa8MAiJ28THMSGGaQdScJBiEdvDBUnybJz8JZUW5
external addresses	m/84'/0'/1'/0	xpub6Ebnfv1i4JTB9hR7fsTQeoFK9pTkJ1C1xUcWh63e2nfs8ECSAsMLtdGfZCogpSRBcua8q1YzPg4LtigW4mZW8kNUqGeyKfbv1FL7PYB73Bi
m/84'/0'/1'/0/0     	bc1q26rwwgl72qgq2jpc8jemkv2d6chegcjldl3tmu	0.00000000	new
m/84'/0'/1'/0/1     	bc1qvh5d5n84rehtjugzvckel7av2cenw4aejdv3wp	0.00000000	new
m/84'/0'/1'/0/2     	bc1qhtg32hj93nvaj0j3mtmf83k7957agl30484yka	0.00000000	new
m/84'/0'/1'/0/3     	bc1qq34fnkdjewvsq4ftrpgjf39724kwae7gn5fs6f	0.00000000	new
m/84'/0'/1'/0/4     	bc1q8s6c25qahuzgrhd79engxgsk83ykmgxc26gwny	0.00000000	new
m/84'/0'/1'/0/5     	bc1qjmd2arkjr03z70h7jeueg8yq84c4c0ae8mlgcq	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/1'/1	
Balance:	0.00000000
Balance for mixdepth 1:	0.00000000
mixdepth	2	xpub6CnATD8P29cQYCTdfy2CyXGTYssFdZ3Ah3pkSyQbeBLTHbBzFwa1t6nbdHWGswECMhzeYDrkfd2TBZbAdiMcsXqSUqfPfh3B2zAuv8cS4RJ
external addresses	m/84'/0'/2'/0	xpub6Dax3dojj4m54pE9CgTm3mEuXxEG6wu1yv4qoJcBng7ip7UKJqmfphXKySjkiDaX8tRFdPc7uNbrZuteHJxxRtQcCJw9gG2hnwALAJJwuHH
m/84'/0'/2'/0/0     	bc1qsjq3fqlhpvl6zdlx4keaptqvnsvlq9wvs6htnp	0.00000000	new
m/84'/0'/2'/0/1     	bc1qfhwq2nl3s3wvd87ecs7n5y4eg48wggumznx8gv	0.00000000	new
m/84'/0'/2'/0/2     	bc1qcp8ksz9jlkeltkuvxqypmkd92jtdsw8z6v9zuz	0.00000000	new
m/84'/0'/2'/0/3     	bc1q7mnglcgdcshnuc9p0s50slr98ysmur8qvqzlc9	0.00000000	new
m/84'/0'/2'/0/4     	bc1qk9ewvfet6a2cw2rzykwz2q96ue8amras4j9676	0.00000000	new
m/84'/0'/2'/0/5     	bc1qatmlhx4zphrsh3p97c2kvhmze8k556592pl6wx	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/2'/1	
Balance:	0.00000000
Balance for mixdepth 2:	0.00000000
mixdepth	3	xpub6CnATD8P29cQcqg9mDxc2pRMT5syBfLsVMJdJ2QbvpV52VHbBrjRpYgwg9rtAVRYuWnDGdk9T2ZXhD9XhbTnZnd5k8QxPXKXFwXKCGDNAM4
external addresses	m/84'/0'/3'/0	xpub6FAfwaxVRmjFadt3hmR9dnALSCQ6Gs3ZzfLVodLnkyBVNhpeZaUD2ePWCqYdmsPbW8XcvTB3ZoW2wWXBhAsNNPbyFrJevnuisBG1XhLbRpU
m/84'/0'/3'/0/0     	bc1qnvc2v6y5xp00ps7c7xe7762d033hfeunu93txk	0.00000000	new
m/84'/0'/3'/0/1     	bc1q4tcwnjp4afywkknr3vnsfnfkancdgtty9wpduw	0.00000000	new
m/84'/0'/3'/0/2     	bc1qtwgfxgjuh2qt5mss0yu4f8gtfyl6qx40et00s0	0.00000000	new
m/84'/0'/3'/0/3     	bc1q6dqwcztdxd8j0t4md8knrs9mj2tn5pyxjlv6gw	0.00000000	new
m/84'/0'/3'/0/4     	bc1qwsf8jtu3rcvhfr2z9qm5umwz75q88pp3wsclu8	0.00000000	new
m/84'/0'/3'/0/5     	bc1q669ss06j9c7ycf5jdg7zf8ctxa4yudn4tyug2y	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/3'/1	
Balance:	0.00000000
Balance for mixdepth 3:	0.00000000
mixdepth	4	xpub6CnATD8P29cQemJKvXNbkw7VhmezjUJAzTan2TsRKCai4ssTVWdghHNa9TaSggZtctToaewCA1KzBA8zdbx3ZCc8ez3cJQxAx96HhgABx6i
external addresses	m/84'/0'/4'/0	xpub6ExY4c7otX7GvGHuL4NZpoLhxzfEkyiKngcmqeYnNQpiwBpPmEgDWAqr5qu7dPUTwHNsjUyWPrBJo9e9MNPsonnfxc4fnT2XtgBMDwN8T5h
m/84'/0'/4'/0/0     	bc1q8xvvyzty8ejy6epywekjzakkt7nutxxmvq0u9w	0.00000000	new
m/84'/0'/4'/0/1     	bc1q9mn6e64zmuzccqa4xeh80zm2nqqmylpa8w7ndj	0.00000000	new
m/84'/0'/4'/0/2     	bc1qrgstfgjzmrvwcv6v05ugl28ss46qywk92ksn30	0.00000000	new
m/84'/0'/4'/0/3     	bc1qc06d3xdfj5lq8slezk2sl8krrr08qzku07gewr	0.00000000	new
m/84'/0'/4'/0/4     	bc1qz0tfa6e9yqzxqzlj56ge24t7z7rftj9janpsed	0.00000000	new
m/84'/0'/4'/0/5     	bc1q2utkj2rqqw4wdr7z2fu9cgfv5zdpsnt47uns6u	0.00000000	new
Balance:	0.00000000
internal addresses	m/84'/0'/4'/1	
Balance:	0.00000000
Balance for mixdepth 4:	0.00000000
Total balance:	0.00000000
```