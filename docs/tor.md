### How to use Tor with Joinmarket

(You've installed using the `install.sh` or similar as per instructions in the README before
reading this).

This document gives short notes on any necessary configuration steps for using Joinmarket as a Maker or a Taker, in coinjoins.
The requirements for Takers are lesser.

### Contents

1. [Checking Tor is installed](#torinstall)

2. [Using Tor as a Taker](#tortaker)

3. [Using Tor as a Maker](#tormaker)

   a. [Configuring Tor to setup an onion service](#torconfig)

<a name="torinstall">

### Checking Tor is installed

(Insert sanity check advice for system `tor`.)

If you don't currently have a Tor daemon running on your machine you can use the flag `--with-local-tor` appended to your invocation of `./install.sh` as per the installation instructions in the README.

<a name="tortaker">

### Using Tor as a Taker

Insert basic instructions on checking Tor is functional and SOCKS port.

<a name="tormaker">

### Using Tor as a Maker

To use the new onion messaging system (see [here](onion-message-channels.md)) as a maker it's necessary for your bot to be reachable directly p2p by takers, so you need to run an onion service. This often requires a little extra configuration of your Tor setup, which we now explain:

<a name="torconfig" />

#### Configuring Tor to setup an onion service

(These steps were prepared using Ubuntu; you may have to adjust for your distro).

First, ensure you have Tor installed:

```
sudo apt install tor
```

Don't start the tor daemon yet though, since we need to do some setup. Edit Tor's config file with sudo:

```
sudo vim /etc/tor/torrc
```

and uncomment these two lines to enable onion service startup:

```
ControlPort 9051
CookieAuthentication 1
```

However if you proceed at this point to try to start your yieldgenerator with `python yg-privacyenhanced.py wallet.jmdat` or similar, you will almost certainly get an error like this:

```
Permission denied: '/var/run/tor/control.authcookie'
```

... because reading this file requires being a member of the group `debian-tor`. So add your user to this group:

```
sudo usermod -a -G debian-tor yourusername
```

... and then you must *restart the computer/server* (or maybe just logout, login) for that change to take effect (check it with `groups yourusername`).

Finally, after system restart, ensure Tor is started (it may be automatically, but anyway):

```
sudo service tor start
```

Once this is done, you should be able to start the yieldgenerator successfully.
