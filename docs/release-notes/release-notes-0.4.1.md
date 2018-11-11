Joinmarket-clientserver 0.4.1:
=================

<https://github.com/joinmarket-org/joinmarket-clientserver/releases/tag/v0.4.1>

This is a bugfix release, and to be considered essential for Tor (i.e. hidden service) users.
See "Notable changes" for details of the issue.

If you are upgrading from pre-0.4.0 you **must** read the [release notes for 0.4.0](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.4.0.md) and follow
the relevant upgrade instructions, which apply here exactly the same.

Please report bugs using the issue tracker at github:

<https://github.com/joinmarket-org/joinmarket-clientserver/issues>

Upgrading 
=========

To upgrade:

As mentioned above, follow the instructions as per "Upgrading" in [release 0.4.0](https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/release-notes/release-notes-0.4.0.md).


Notable changes
===============

### Fix IRC configuration loading

There is some background in the next paragraph for context; if you just want to know
what issue was fixed, you can skip it and go to the TLDR.

The ConfigParser module used to load Joinmarket configuration files does not support
nesting sections. So previously to #201, to support multiple IRC servers, we used comma
separated lists. This was inconvenient for users; to remove one server, they had to edit
each comma separated list by hand. #201 addressed this by having a separate section for each
server. The names given to the sections were `MESSAGING:server1` and `MESSAGING:server2`. At
least two users reported issues (see #210) when attempting to use custom server names, e.g.
`MESSAGING:cyberguerrilla`. The cause was that, in case the user creates such a newly-named
section, the *existing default* sections (server1, server2) are still loaded. These defaults
are specified to connect to CGan and Agora over clearnet. Hence if a user modifies these section
names, one of two things can happen: failure to connect from trying to unwittingly connect to
the same server multiple times, or, worse, a default clearnet connection for servers that you
actually removed from the config. (In case that doesn't make sense: a default configuration is
always loaded, and the settings in the joinmarket.cfg file overwrite them; but the overwrite
doesn't happen if you actually change the name of the section).

**The TLDR: Previous to this fix, if you edited the two given MESSAGING:server1 and MESSAGING:server2 sections, you could
end up either failing to connect, or using a default connection for a deleted server, which is
clearnet. Hence this could be annoying in terms of unexpected connection failures, but it could
also in certain circumstances result in IP leakage for a user who thinks they are connecting over Tor.
It's for this last reason that this release was pushed out immediately; now you can specify any
name you like e.g. MESSAGING:agora and it will work as expected.**

0d7a91f quit after creating a new config file
426cb87 fix loading of irc configuration

=====

Thanks to @HamishMacEwan @the9ull @qubenix for helping by reporting the bug and testing, and to @undeath for patching.

