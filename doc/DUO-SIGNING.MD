# Live Signing Duo for DNSSEC

> *This software assumes two DNSSEC Signer machines
> to be live at the same time.  How do we keep them
> from getting entangled?  We don't.  And the result
> is the most redundant approach possible!*

```
From: Rick van Rein <rick@openfortress.nl>
```

Most DNSSEC signing approaches integrate state for
keys and signatures.  And because signatures need
to be refreshed regularly, and redundant Signer
machines might get into a struggle about who should
sign what, we have hitherto implemented DNSSEC
signing with a single master and a hot spare as a
backup.  With this software, we take a radically
different approach.

Now, we have two Signer machines that sign zones
in parallel.  They are both live at the same time.
One might see it as the "maturity level" of
master-master replication for DNSSEC signatures.

## Shared Fixed Keys

Our zones are added to the Signer machine's working
set as soon as their zone data is submitted.  It
may not be signed yet, as that requires key material.

An explicit command to create a singing key for a
zone is then issued, which is sent to any one of the
Signer machines.  This machine creates the requested
key and passes it to the other Signer machine, as well
as a backup store from which we might recover if the
two Signers would somehow end up as flatliners.  The
Backup machines hold on to key material somewhat longer
than desired for the operation of the Signer machines.

We now have two Signer machines who can operate on
the same DNSKEY for the zone.  The use of sharing
this key material is that we only need to add one
DS record to the parent zone, instead of one for
each of our Signer machines.  In terms of network
bandwidth, that is a pleasant guesture and worth
the explicit distribution of key material.

## Independent Signing

The striking thought behind our work here is that
the zones are now signed independently by each of
the Signer machines.  There is no more coordination
and so the `RRSIG` and `NSEC3` records will be made
as different signatures.  This takes more compute
time, but it also means that both Signer machines
are constantly tested, so dead code has a zero
chance of lurking in the wings.

Note that not even `NSEC3PARAM` records need to be
coordinated between the Signer machines.  Authenticated
denial holds the information from the record used, and
the TTL of that original record is set to 0 so cannot
be cached at all.  As a result, authenticated denial
can be processed in isolation without a need to
lookup the parameters and risking to find the value
from generated locally on another Signer machine.
In the end, the `RRSIG` on the `NSEC3` is what prooves
matters; the `NSEC3PARAM` are not an authentication
matter but one of privacy and concealment.

The result of this work can be used in any mix,
which is an unexpected result of the way DNSSEC
works.  It is due to the requirement that caches
may load each of the records separately, and end
up with values from different runs of the signing
algorithms; in our case, we merely institutionalise
these different runs, and rely heavily on the
existing support for it in validating resolvers.

## Distributing Data

The most redundant mechanism for distribution of
this separately signed data is by splitting the
public authoritative name servers into as many
sets as we have Signer machines, and have them
retrieve the data from the one they are allocated
to.  This may or may not work in given pragmatic
settings, where a single hidden master is currently
the norm.

Note what we are saying: Your name servers do not
need to provide the same data, as long as they
adhere to the same validation rules, which is the
case with the approach described here.

More in line with current mechanisms might be to
simplify swapping between the Signer machines,
where they may be doing the signing in comparable
mode but one would simply be seen as the first
server to try, the other as the second.  It is
also possible to assign the IP addresses of the
live Signer machines to one host name, and let
software handle this as it wants; basically
relying on fallback mechanisms for host-to-IP
translations.

When a client may switch seemlessly between
the Signer machines as input for any given zone,
it is important to understand that `IXFR` cannot
be used.  This is because the old records are
explicitly removed, by mentioning their content,
and when these differ between the origin servers
then the `IXFR` would fail.  In (at least) that
situation, the client of the Signer machines
should rely on `AXFR` instead.  If it switches
fluently, it is probably a good idea to only
use `AXFR` as a transfer mode.

## Staying with Recent Data

Whenever a zone is signed, the Signing machine
will increment its SOA serial counter.  Important
in the scheme we describe here is that these
cannot run far apart.  When that would happen, the
heading name server could not die without leaving
behind a backup that looks like it is behind to the
client.

Note that the perfect scenario is one where the
Signer machines independently count with the same
counter values, in pretty much the same speed.
This would mean that the different `RRSIG` and
`NSEC3` which may be ignored can be gradually
replaced when crossing over to a next version.

By using the `YYYYMMDDNN` scheme for SOA serial
numbers, we already cause a regular synchronisation
of state.  The only thing that is added relative
to this is the initiative of the Signer machines
themselves; this is due to re-signing records
whose `RRSIG` is about to expire; this process
will look similar on both Signer machines, with
a possible variation due to random fuzz of the
timing to spread the work load somewhat.  At
least OpenDNSSEC implements such a fuzz.

Even with such a fuzz, the result would be
harmless; SOA serial counters are incremented
by one during automated re-signing, and it is
completely unlikely that this will outrun the
progression of the `YYYYMMDDNN` scheme, unless
a zone remains static for a long time.  In this
one case however, there is no problem in the
zones diverting somewhat between the Signer
machines and the one thing that matters, namely
that an update is promptly picked up, does
hold because the `YYYYMMDDNN` scheme progresses
much faster than the increment-by-one of the
automated process.

In short, we anticipate no problems when it
comes to this scheme staying up to date with
SOA serial counters that will trigger a reload
in the clients of the Signer machines.

