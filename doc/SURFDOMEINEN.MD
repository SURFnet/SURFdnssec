# History of SURFdomeinen

> *This software implements the Signer infrastructure for DNSSEC as part
> of SURFdomeinen.  This is the managed DNS environment offered by SURFnet
> to Dutch acedemia and higher education institutions.  The (initial)
> development of this software was funded by SURFnet.*

The vision behind DNSSEC in SURFdomeinen has always been that it should
be as simple to users as an on/off switch.  This means that a lot of work
should be automatically handled.  As a result, many details about DNS and
more specifically the chain of trust in DNSSEC are built into the software
of the Signer, so that nothing happens before its time.

The software presented here is a next generation, incorporating a lot
of experience from running an older infrastructure and learning how it
could be simplified, and made more controllable.

Though SURFdomeinen started as a full OpenDNSSEC deployment based on both
`ods-signer` and `ods-enforcer` modules, we decided early in the development
of this process to use only `ods-signer` and place a web API `ods-rpc`
in front of it.  This was possible because we decided to migrate from RSA
signatures to ECDSA, after Roland van Rijswijk's work showing that this
has no performance penalties and is generally practical.  As a bonus, the
risk of "wear and tear" under RSA was no longer considered a threat, so
key rolling was no longer necessary and, as a consequence, we could
combine KSK and ZSK into one key, usually called a CSK.

So this software assumes that a key is generated when a zone's DNSSEC is
switched on, and dropped when it is switched off.  As before, care is
taken not to break the chain of trust by moving in a bad order, or too
fast.  The TTL on various DNS records means that someone, somewhere may
have an old copy of our data, so we regularly abide our time before a
process continues.

This new situation makes zone signing orthogonal to the zone data, and
that is precisely what has been implemented in the Signer infrastructure.
Yes, there are concerns at a lower level, but these are wrapped into the
scripts so as to convey that conceptual notion and thus make the on/off
switch strongly rooted in the framework.

In a relatively late stage we decided to switch the actual signing backend
from OpenDNSSEC to Knot DNS.  This required us to develop `ldns-zonediff`,
which is now a generally useful utility for comparisons between zone files,
but otherwise not unlike `diff` on text files.  It also meant that we had
to make our infrastructure modular, with a pluggable backend for each of
the two signing backends.  As a result, if you require another signing
backend (like ZKT, or BIND9) you can probably add it without much trouble.

Although we depend on `ods-rpc` and `ldns-zonediff`, we distribute these
pieces of software separately.  They are all available in open source.

