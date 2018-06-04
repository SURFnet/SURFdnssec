# Systemd Control of DNSSEC Daemons

> *The various daemons collaborate in a way that systemd can automate.*

## Service Configurations

Several of the `ods-*` directories contain `.service` files that will
bootstrap their daemons.  Even if you don't employ `systemd`, the
files can guide the setup of processes for your configuration.

We are not religuous about `systemd` and welcome anyone who wishes
to add `.init` files for the daemons next to our `systemd`
configuration files.  We do prefer the major operating systems to
work, namely GNU/Debian and RHEL.

## Example Targets

We include to `.target` files that summerise a set of daemons to run
together.  This reflects our own setup for SURFdomeinen.  These files
are not installed by `install.sh` because they usually ask for local
tinkering.

The target `surfdomeinen-signer-machine.target` is run on each of our
two Signer machines.  These machines are live at the same time, so we
made no distinction between master and slave machines.

The target `surfdomeinen-backup-machine.target` is run on our Backup
Stashing machine.  This is a fairly simple setup, which pulls backups
made when the HSM changes state, and stores it in the filesystem.

It is easy to ask `systemd` whether the total target is working; targets
are taking down when one of their components goes down.  The targets are
also nice work units to bootstrap the machine as a whole.


