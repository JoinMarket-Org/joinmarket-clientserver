
Notable changes
===============

### Fidelity bond for improving sybil attack resistance

From the very beginning of JoinMarket it was possible to attack the system by creating many many maker bots all controlled by the same person. If an unlucky taker came along and created a coinjoin only with those fake maker bots then their coinjoins could be easily unmixed. This is called a sybil attack and until now it was relatively cheap to do against JoinMarket. Some yield generators were already doing this by running multiple bots, because they could earn higher coinjoin fees from their multiple makers.

Fidelity bonds are a new feature intended to make this sybil attack a lot more expensive. It works by allowing JoinMarket makers to lock up bitcoins into time locked addresses. Takers will still choose makers to coinjoin with randomly but they have a greater chance of choosing makers who have advertised more valuable fidelity bonds. Any sybil attacker then has to lock up many many bitcoins into time locked addresses.

For full details of the scheme see: [Design for improving JoinMarket's resistance to sybil attacks using fidelity bonds](https://gist.github.com/chris-belcher/18ea0e6acdb885a2bfbdee43dcd6b5af/)

This release implements all the features needed to add fidelity bonds to JoinMarket. Takers (via scripts such as `sendpayment.py` or `tumbler.py` or the Joinmarket-Qt app) will automatically give preference to makers who advertise fidelity bonds. Makers can optionally update their wallets to fidelity bond wallets. When a fidelity bond wallet is used with a yield generator script, it will automatically announce its fidelity bond publicly. Makers who don't create fidelity bonds by locking up bitcoins will still be chosen for coinjoins occasionally, but probably much less often than before.

For full user documentation see the file `/docs/`fidelity-bonds.md` in the repository.

With realistic assumptions we have calculated that an adversary would need to lock up around 50000 bitcoins for 6 months in order to sybil attack the JoinMarket system with 95% success rate. Now that fidelity bonds are being added to JoinMarket for real we can see how the system behaves in practice.

Fidelity bond coins cannot be yet be held in cold storage, but this is easy to add later because the JoinMarket protocol is set up in a way that the change would be backward-compatible.
