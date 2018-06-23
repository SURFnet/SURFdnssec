# Backups and Retention

> *There is nothing more useful than being able to play back time
> when something has dramatically gone wrong.  This requires a
> stable method for returning the HSM in a prior state.*

Usually a HSM supports export of keys in an encrypted form, and future
restoration if need be.  Ideally, the set of keys is very close
to the set of keys just lost.  But minimally, the set of keys that were
in use should be replaced; if more is installed alongside, then so be it.

##  Near-Perfect Backups

The perfect backup is always up to date, can replay all of history,
and takes a minimum of storage.  We can get really close to that.

Ideally, full backups are retained every now and then, with
incremental merges for every change.  This is indeed practical with the small
data sets describing keys, also because they do not change much.  If
it is really possible depends on the permissivity of your HSM and
the openness of the backup format.

We therefore develop code that can summarise recent backups into a
midnight merge, containing all the keys in use on at least one of
the HSMs at midnight.  This can be derived from the last known state
of each HSM preceding midnight.  Then, we look at the additional
keys and store those in incremental merges during the day.  We do not remove
keys while the day is in progress and we are happy to create multiple
keys in one incremental merge.

At the end of the day, the stable state of the HSMs is once again
merged to form the next midnight summary.  When keys have been
removed from both HSMs, they should also have disappeared from the
following midnight summary.

We wish to keep a few of the full HSM backups for a few days, but
a much longer history can be supported when these more incremental
states are kept.  The resulting storage capacity per day is in the
order of the HSM capacity used plus the changes on a day, and this
is enough to recover just about any key one might desire because the
backups are immediate and incremental.

## General Principles

To support this scheme, the backup files of an HSM must be somewhat
manipulated.  This is done after they have been received and stored
in full on the Backup machine.  The `ods-backup-stash` daemon will
receive and store files, while `ods-backup-prune` looks around and
summarises the backups and prunes the full files as well as its
own history from branches that are too old to keep (with a possible
exception for occasional statistical information).

To accommodate this, a plugin specific to the file format of an HSM
is needed which supports the following:

  * Merging two files into one;
  * Subtracting two files, yielding what is in the second but not the first.

The midnight summaries are made by merging each HSM's last file before
midnight; the increments are then made by looking at the new content
that they bring, if any.  Reproduction of timed state is possible
by using the merging function on a midnight summary and increments,
though that is not usually needed because the full backups tend to be
preferred for that, original as they are.

Not all HSMs enable these operations.  Such plugins are then limited
in function.  An HSM that only supports merging would be usable to
provide midnight summaries but not merges.  An HSM that only provides
subtraction makes little sense, so is not assumed.  An HSM that
provides neither, or that has no plugin, is not able to construct
any summary information, and is held to the management of full
backup files.

## Utimaco HSM support

Our Utimaco HSM stores (or so it seems) keys in separate lines in a
text file, so we can indeed take the backups apart, also because the
same key seems to be backed up in a consistent encoded form.

We don't know how to unravel that form, but we can sure compare it!
As a result, we can merge and subtract.  In other words, we can
fully support the summarising scheme described above.  A plugin to
accommodate that is provided.

## Configuration

**Basic Configuration.** The least configuration possible is

```
[pkcs11]
backup_dir = /var/opendnssec/backup

[rabbitmq]
signer_machines = signer1 signer2
host = localhost
port = 5671
```

This directs `ods-backup-stash` to write its data into that directory.
The data is retrieved over RabbitMQ, by connecting to the Signer machines
and waiting for them to pass information to the `HOSTNAME_pkcs11_backup`
queue.

The `backup_dir` is also used by `ods-backup-prune`, which must run on
the same host.  It will subscribe to the directory and takes note of any
file formatted as `YYYYMMDD-HHMMSS-SIGNERHOST.keys` stored in it.  These
trigger processing as well as automatic removal.


**Summary Directory.**  This is where midnight and merges summaries
will be stored.  It may be different from `backup_dir` but does not
have to be; it defaults to the `backup_dir` when not provided and
if `summary_dir` is not an absolute path it will be considered a
path relative to `backup_dir`:

```
[pkcs11]
backup_dir = /var/opendnssec/backup

[ods-backup-prune]
# relative to backup_dir
summary_dir = summary
```


**Historic Directory.**  This is where midnight summaries to be
retained forever (see `retain_forever` below) will be stored.
The entries in this directory are written, but never pruned by
`ods-backup-prune`.  Their file name format is
`YYYYMMDD-HHMMSS.historic` so the files can be distinguished from
other files, even if it overlaps `summary_dir` and/or `backup_dir`.
The `historic_dir` defaults to the `summary_dir` when not provided.
if `historic_dir` is not an absolute path it will be considered a
path relative to `backup_dir` (so, not relative to `summary_dir`):

```
[pkcs11]
backup_dir = /var/opendnssec/backup

[ods-backup-prune]
# relative to backup_dir
historic_dir = historic
```


**Delaying Pruning.** Normally, you will want to keep some of the files
around, not just a last in each of its kind.  This is possible with the
`retain_xxx` settings that all take an ISO 8601 period.

```
[ods-backup-prune]
retain_keys = P2D
retain_midnight = P14D
retain_merges = P7D
retain_forever = P1M
```

These represent different forms of retention:

  * `retain_keys` indicates how long a full `.keys` backup stored
    by `ods-backup-stash` will be kept.  If midnight summaries are
    made, it is usually possible to reduce this to just a few days.
  * `retain_midnight` indiciates how long a midnight summary must
    be kept.  This indicates how long one can wind back to a full
    backup during that day.  The use of midnight merges is that they
    can remove keys; merges only add keys.
  * `retain_merges` indicates how long individual merges are kept.
    Note that it is complete to concatenate merges from many days,
    so an older midnight summary can help to still recall the state
    as it was at some point.
  * `retain_forever` indicates the period for which the first
    midnight summary must never be removed by `ods-backup-prune`
    so that statistics may be applied, for example.  Usually this
    is the first midnight entry of a month, year or week, and it
    may accommodate statistics.  Whether it provides full
    restorative capabilities depends on other policies as well.

The `retain_forever` format consists of at least one specifier that will be incremented to skip between backups.  When the surrounding unit (in this case, the year) cycles then counting starts again at its beginning, so the last period retained may be shorter than the period specified (but never longer).  In return, we get historic values stored at the start of a (calendar or clock) period, rather than something based on a fixed number of seconds (such as a full moon).

These settings are all optional:

  * When unspecified, the `.keys` files will be pruned at the
    `retain_forever` period.
  * When `retain_midnight` and/or `retain_merges` are absent,
    the respective summaries are not made.  Use this when your
    HSM plugin does not support the required functionality or
    has no plugin (unless you like your logs to fill up).
  * When `retain_forever` is present but `retain_midnight`
    is not, then the policy of retaining forever is applied
    to the `.keys` files instead of `.midnight` files.

**Plugin for HSM:**
These are used to process the backup file format.  We provide
a first one, targeted at Utimaco's backup files (tested on
external keys).

```
[ods-backup-prune]
fileops_plugin = fileops-utimaco
```

**Callback Commands (Future Extension):**
A number of `cmd_xxx` settings may be used in the
`[ods-backup-prune]` section to trigger actions at key moments
such as:

  * `cmd_have_keys` when a Signer delivered a `.keys` file
  * `cmd_have_midnight` when a new midnight summary was written
  * `cmd_have_merges` when a new merges summary was written
  * `cmd_drop_keys`, `cmd_drop_midnight`, `cmd_drop_merges`
     may be called just before removal of the same files.
