# ods-rsync-zonedata -- Receive zones over RSync and relay over AMQP

This script accepts uploads of zone files over RSync, and forwards
them over AMQP with the zone as its subject.  In short, it is a
gentle way into the Signer's AMQP infrastructure.

The command to use is:

```
rsync -dc --delete /path/to/zonedir portal@signer-cluster:upload
```

Please note:

  * We use `-d --delete` to cause removal of files.  This will trigger
    an empty AMQP message, which in turn leads to the removal of a zone
    from the `zonelist.xml` and `.signconf` files
  * We use `-c` to avoid overwriting zone files that have not changed;
    this protection even works when zone files are generated anew, as
    long as the order has not changed
  * We upload to `signer-cluster` so we can fallback during downtime;
    the AMQP system will then be spiked with changes that may already
    have been suggested on the other system, but that is quickly
    detected and not harmful (the process is idempotent)
  * Note that *directories* are moved, not *files* and certainly not
    a *tarball* or anything else that might collapse change detection

On the Signer machines, we configure an account `portal` with an
initially empty directory named `upload`.  In the `.ssh/authorized_keys`
we setup the command to run,

```
command="/path/to/ods-rsync-wrapper" ssh-... AAAAB3NzaC1kc3...
```

This command does two things:

 1. It runs the RSync server side, using all the right settings
 2. It triggers the `ods-rsync-zonedata` script running under another
    user account

Don't forget to create the pipe over which the RSync wrapper kicks the
zonedata passing script.
