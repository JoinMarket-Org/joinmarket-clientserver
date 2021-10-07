A "yield generator" is a JoinMarket bot which does market-making of CoinJoins to produce an income as a join "Maker". The bot connects to the JoinMarket trading pit on the available messaging channels, announces its offers and waits. Market "Takers" will communicate with it to create a CoinJoin transaction.

## A few words about incentives
The first thing to understand is that this is not a bank account with a guaranteed interest rate. You are selling a product, namely coinjoins, and your customers can take it or leave it depending on your offered fee, range of available coinjoin amount, value of advertised fidelity bond, internet speed, latency and so on. Most of the actual decision-making is done by software bots rather than humans but the same principles apply. The algorithm for market takers remembers yield generators they previously dealt with and avoid those who did not offer a good experience. You have an incentive to be on your best behavior.

### Things You Need
+ A local Bitcoin full node running with JoinMarket. No other Bitcoin blockchain access is currently supported. Your node can be pruned.
+ A reliable, relatively fast, always-on internet connection. CoinJoins require multiple people to take part, if one yield generator times-out or is slow, the entire process is held up or must be restarted. People are looking for joins 24/7, so you'll need to run Joinmarket all the time to make joins as well. The entire point of a market maker is to offer a deal immediately, without any waiting or hold-ups.
+ A significant enough Bitcoin balance in your joinmarket wallet to offer a wide range of coinjoin amounts. If you can only offer from zero to 1 million satoshis (0.01 BTC), you're unlikely to get many coinjoin deals. The bigger your balance, the better.
+ Update often. This software is still in the very early stages. Keep an eye out of updates. Perhaps subscribe to the [twitter](https://twitter.com/joinmarket/) or [subreddit](https://www.reddit.com/r/joinmarket) to get news about updates.

## Requirements / How-to
You will need to:
+ Install JoinMarket (see the README file of this repository, then follow the [usage guide](USAGE.md)).
+ If you've followed the usage guide and funded your wallet with some coins (anywhere is fine, but the 0th mixdepth is most logical), you can then configure your yield generator script:
+ First, choose a yg script. For beginners, use one of the defaults (as in the next bullet point). But you can also use more customised and advanced scripts, found [here](https://github.com/Joinmarket-Org/custom-scripts)
+ Edit `yg-privacyenhanced.py` or `yield-generator-basic.py` (former is recommended) at the top of the file with your chosen fee selections, then run this variant yield-generator.py on a permanently-on computer with a stable internet connection. For example:
        (jmvenv)$ python yg-privacyenhanced.py yournewwallet.jmdat
+ Wait and be patient. The volume of joins is always dependent on the number of takers. A successful join may take a day or longer to appear.
+ (Optional) [Create and advertise a fidelity bond](fidelity-bonds.md) to increase your coinjoin volume

## Configuring
Open the configuration file `joinmarket.cfg` and edit the `[YIELDGENERATOR]` section to configure relevant values. Most of them can just be left at the default values.

    [YIELDGENERATOR]
    # [string, 'reloffer' or 'absoffer'], which fee type to actually use
    ordertype = reloffer

    # [satoshis, any integer] / absolute offer fee you wish to receive for coinjoins (cj)
    cjfee_a = 500

    # [fraction, any str between 0-1] / relative offer fee you wish to receive based on a cj's amount
    cjfee_r = 0.00002

    # [fraction, 0-1] / variance around the average fee. Ex: 200 fee, 0.2 var = fee is btw 160-240
    cjfee_factor = 0.1

    # [satoshis, any integer] / the average transaction fee you're adding to coinjoin transactions
    txfee_contribution = 100

    # [fraction, 0-1] / variance around the average fee. Ex: 1000 fee, 0.2 var = fee is btw 800-1200
    txfee_contribution_factor = 0.3

    # [satoshis, any integer] / minimum size of your cj offer. Lower cj amounts will be disregarded
    minsize = 100000

    # [fraction, 0-1] / variance around all offer sizes. Ex: 500k minsize, 0.1 var = 450k-550k
    size_factor = 0.1

## Keeping Track of Returns

As well as simply viewing your balance in-wallet occasionally as explained in the [usage guide](USAGE.md), the history can also be calculated with the `history` method, also explained in that document.

## I deposited X btc into yield generator, why is it only offering Y (< X) btc in the market?

Short answer: privacy

Long answer: https://bitcointalk.org/index.php?topic=919116.msg11465848#msg11465848

## My bitcoins have been split up into many small UTXOs

You may wish to change the input merging policy in `joinmarket.cfg`, see this page: https://github.com/JoinMarket-Org/joinmarket/wiki/Configuring-with-joinmarket.cfg#input-merging-policy

The value of `gradual` or `greedy` is usually good for keeping the number of inputs from getting too large.

## How to run yield generator in background

Use [tmux](https://man.openbsd.org/OpenBSD-current/man1/tmux.1) or [GNU Screen](https://www.gnu.org/software/screen/).

## Modifying the algorithm
If you are a programmer you could try creating your own algorithm for the yield generator.

Other yield-generator algorithms are in a separate github repository: https://github.com/JoinMarket-Org/custom-scripts Many more people can work on them without the possibility of putting the main JoinMarket code in danger.
