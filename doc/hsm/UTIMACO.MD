# Utimaco HSM

> *Any PKCS #11 implementation should work under this Signer infrastructure.
> We added some specific support for replication on Utimaco HSMs.*

Replication is not part of the PKCS #11 specification, but is often
implemented underneath the API.  Especially the high-end vendors like
to do this, possibly because it doubles the sales of their precious
machines `;-)`

For Utimaco HSMs the data is stored on disk and it can even be searched
through to some degree.  This makes it easy to send the HSM data whenever
something has changed; and it also allows the integration.  We do the
latter in a way that favours addition and is cautious about deletion of
keys, as is popular with replication methods for PKCS #11 -- the loss of
a concealed key is too devastating to risk it.

The script `ods-utimaco-send` is called after a change to the contents
of the HSM, and the result is that the data is passed over to the replica,
as well as to a backup queue.

The script `ods-utimaco-recv` listens for incoming HSM state transfers,
and integrates them with the local state, as said favouring addition
of keys over removal.

The script `ods-backup-stash` takes in backed up files from either
Signer machine, and stores it in a directory.  This script is not
specific to Utimaco HSMs, but it integrates nicely and any new state
in the HSMs is also sent to the backup queue where this script will
pick it up.  It is usually a nice idea to run this script on a
separate machine from the Signer machines.

The scripts in `ods-votes` are meant as a system where removal of keys
can be agreed upon by voting.  This may need some form of garbage
collection to work completely.  At present, that work is not completely
done.

