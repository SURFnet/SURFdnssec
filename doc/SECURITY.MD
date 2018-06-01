# Configuration of Security Architecture

> *Most daemons use their own username and password when connecting to
> RabbitMQ.  These usernames are independent of the UNIX userid system,
> and various mappings are possible.  We advise one that may be prudent
> to most.*


## Configuration on a Need-to-Know Basis

Though scripts and plugin libraries will normally be installed centrally
on a system, this is not true for configuration, which is stored in a
file `~/ods-amqp/config` residing under the caller's user account.

On top of this account-local file, a central configuration file
`/etc/opendnssec/ods-amqp.config` can be created; this will then
serve as a fallback but only for section entries that are not
defined (overridden) in the account-local files.  Security improves
when sensitive information is only made available in the various
account-local files.  One should mind that `root` has enough facilities
left to play the roles of various probing and tickling programs.

The configuration has general sections, which are nonetheless replicated
for maximum flexibility (and also for simplicity of the configuration system).
These sections are `[rabbitmq]` and `[pkcs11]` and the backend usually has
an additional one named `[knot]` or `[opendnssec]` too.  These sections
need not be copied to all accounts; instead, they may be made in the
central configuration in `/etc/opendnssec/ods-amqp.config` which makes
them available everywhere.  When considered sensitive or account-local,
it is simply possible to define the entire `[pkcs11]` section or just its
`pinfile` configuration variable in the account-local file.

There are specific settings per daemon in a section that is (usually)
named after the daemon's executable name.  The exact section names can be
found in the sample configuration file.  These settings can also be stored
in the system-central file `/etc/opendnssec/ods-amqp.config` inasfar as
there are no security implications.  

There is one more general section named `[accounts]` which holds
`username=password` entries.  The entries made here should almost
always be on a need-to-know basis only, and so to mention them only in
account-local configuration files.  It is worth noting that some accounts
are used in multiple places and must then be replicated.  Since these
rarely change and complain loudly when failed, and lead to no faulty
or lossy behaviour, it is practical to spread such knowledge in the
interest of security.


## Splitting Functionality over UNIX Accounts

The various programs connect to the RabbitMQ infrastructure using their
own RabbitMQ accounts.  The ability to configure these in `[accounts]`
locally under a UNIX account enables better access control.  On the
other hand, splitting everything may lead to practical limitations.
This raises the question how RabbitMQ accounts should be mapped to UNIX
accounts.

The most useful purpose for using this is probably the reduction of impact
from an intruder entering one of the subsystems.  This applies mostly to
parts of the system that interact with the outside world, and especially
in a server capacity.  Clients are usually much more controllable, by
authentication of the server identity or the data supplied.

This leads to the separation of `ods-rpc` (from another Git repository)
and `ods-rsync-zonedata` to each get their own UNIX account.  The two
processes produce RabbitMQ events, but do not need to read back anything.
Their RabbitMQ accounts can be setup to allow that, and only that, and
by that mitigating any further impact on the flow of messages.

The links outwards, in a client capacity, are mostly made to DNS and to
parent registries.  These are not usually things that lead to attacks,
or that would benefit from separating them out into separate UNIX
processes.  So the suggestion is to leave those bundled in the same
UNIX account as the remaining processes.

Note that `root` may need proper access to the RabbitMQ infrastructure,
and that may include playing the role of the various components, through
probing or tickling scripts.  This may either mean that the respective
`[accounts]` need to be supplied to the `root` account as well as to the
individual users running the majority of processes, or that the `root`
account is the one under which the majority of processes is run.


## SSL Certificates for RabbitMQ

There is one more security factor of some influence, and that is the
SSL certificate used by the client when connecting to RabbitMQ.  These
certificates can be shared or not, as desired; in the end it is the
username/password of each RabbitMQ account that determines access.

To avoid making the certificates available to all, it is probably better
to keep them stored in user accounts, so they are expected under
`~/ods-amqp/ssl`, which is then shaped like `/etc/ssl` with subdirectories
`certs` and `private`.  The path of `ca_certs` can be separately set in
the `[rabbitmq]` section of the configuration files.

