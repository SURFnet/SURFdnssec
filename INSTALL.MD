# Installation Instructions

> *Most of these scripts can readily be installed.  We shall give an
> example with a local prefix, which is then needed in the paths of
> all environments that run the scripts.*


## Basic Installation

You can install in any prefix that you like.  When you run the script
`install.sh` from the commandline, it will say what it has in mind and,
if it is a relative path, where it starts from.

The default is `../PREFIX`, but it can be overridden by an environment
variable `$PREFIX`, so you might run

```
PREFIX=/usr/local/myniche ./install.sh
```

The output will then be along the lines of

```
Installation settings:
PREFIX="/usr/local/myniche"

I will install systemd files in /etc/systemd/system

Is this okay? y
PYTHONPATH=lib python -m py_compile lib/rabbitdnssec.py
PYTHONPATH=lib python -m py_compile ods-parenting-exchange/ods-parenting-exchange-knot.py
PYTHONPATH=lib python -m py_compile ods-parenting-exchange/ods-parenting-exchange-opendnssec.py
PYTHONPATH=lib python -m py_compile ods-registry/ods-registry-knot.py
PYTHONPATH=lib python -m py_compile ods-registry/ods-registry-local-parent.py
PYTHONPATH=lib python -m py_compile ods-registry/ods-registry-opendnssec.py
PYTHONPATH=lib python -m py_compile ods-registry/ods-registry-sidn.py
PYTHONPATH=lib python -m py_compile ods-registry/ods-registry-stargate.py
PYTHONPATH=lib python -m py_compile ods-zonedata/ods-zonedata-recv-knot.py
PYTHONPATH=lib python -m py_compile ods-zonedata/ods-zonedata-recv-opendnssec.py
cp -p lib/rabbitdnssec.py lib/rabbitdnssec.pyc /usr/local/myniche/lib
cp -pr doc/hsm /usr/local/myniche/doc
cp -pr doc/images /usr/local/myniche/doc
cp -pr doc/SECURITY.MD /usr/local/myniche/doc
cp -pr doc/SURFDOMEINEN.MD /usr/local/myniche/doc
cp -pr doc/SYSTEMD.MD /usr/local/myniche/doc
cp -pr INSTALL.MD /usr/local/myniche/doc
cp -pr LICENSE.MD /usr/local/myniche/doc
cp -pr README.MD /usr/local/myniche/doc
cp -p ods-backup-stash/ods-backup-stash /usr/local/myniche/bin
sed -e s/@PREFIX@/\/usr\/local\/myniche/g < ods-backup-stash/ods-backup-stash.service > /lib/systemd/system/ods-backup-stash.service
cp -p ods-key-management/ods-keyops /usr/local/myniche/bin
cp -p ods-key-management/ods-keyops-knot-addkey /usr/local/myniche/bin
cp -p ods-key-management/ods-keyops-opendnssec-addkey /usr/local/myniche/bin
cp -p ods-key-management/ods-keyops-test-send /usr/local/myniche/bin
sed -e s/@PREFIX@/\/usr\/local\/myniche/g < ods-key-management/ods-keyops.service > /lib/systemd/system/ods-keyops.service
cp -p ods-key-management/ods-votes-test-send /usr/local/myniche/bin
cp -p ods-parenting-exchange/ods-generic-parent /usr/local/myniche/bin
sed -e s/@PREFIX@/\/usr\/local\/myniche/g < ods-parenting-exchange/ods-generic-parent.service > /lib/systemd/system/ods-generic-parent.service
cp -p ods-parenting-exchange/ods-parenting-exchange /usr/local/myniche/bin
cp -p ods-parenting-exchange/ods-parenting-exchange-hint /usr/local/myniche/bin
cp -p ods-parenting-exchange/ods-parenting-exchange-knot.py /usr/local/myniche/lib/ods-parenting-exchange
cp -p ods-parenting-exchange/ods-parenting-exchange-knot.pyc /usr/local/myniche/lib/ods-parenting-exchange
cp -p ods-parenting-exchange/ods-parenting-exchange-opendnssec.py /usr/local/myniche/lib/ods-parenting-exchange
cp -p ods-parenting-exchange/ods-parenting-exchange-opendnssec.pyc /usr/local/myniche/lib/ods-parenting-exchange
sed -e s/@PREFIX@/\/usr\/local\/myniche/g < ods-parenting-exchange/ods-parenting-exchange.service > /lib/systemd/system/ods-parenting-exchange.service
cp -p ods-registry/ods-registry /usr/local/myniche/bin
cp -p ods-registry/ods-registry-knot.py /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-knot.pyc /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-local-parent.py /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-local-parent.pyc /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-opendnssec.py /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-opendnssec.pyc /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-sidn.py /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-sidn.pyc /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-stargate.py /usr/local/myniche/lib/ods-registry
cp -p ods-registry/ods-registry-stargate.pyc /usr/local/myniche/lib/ods-registry
sed -e s/@PREFIX@/\/usr\/local\/myniche/g < ods-registry/ods-registry.service > /lib/systemd/system/ods-registry.service
cp -p ods-rsync-zonedata/README.md /usr/local/myniche/doc/ods-rsync-zonedata
cp -p ods-rsync-zonedata/ods-rsync-zonedata /usr/local/myniche/bin
cp -p ods-rsync-zonedata/ods-rsync-zonedata-wrapper /usr/local/myniche/bin
cp -p ods-utimaco/ods-utimaco-recv /usr/local/myniche/bin
sed -e s/@PREFIX@/\/usr\/local\/myniche/g < ods-utimaco/ods-utimaco-recv.service > /lib/systemd/system/ods-utimaco-recv.service
cp -p ods-utimaco/ods-utimaco-send /usr/local/myniche/bin
cp -p ods-votes/ods-votes-knot-delkey /usr/local/myniche/bin
cp -p ods-votes/ods-votes-opendnssec-delkey /usr/local/myniche/bin
cp -p ods-votes/ods-votes-recv /usr/local/myniche/bin
sed -e s/@PREFIX@/\/usr\/local\/myniche/g < ods-votes/ods-votes-recv.service > /lib/systemd/system/ods-votes-recv.service
cp -p ods-votes/ods-zonedata-signconf /usr/local/myniche/bin
cp -p ods-zonedata/ods-zonedata-recv /usr/local/myniche/bin
cp -p ods-zonedata/ods-zonedata-recv-knot.py /usr/local/myniche/lib/ods-zonedata
cp -p ods-zonedata/ods-zonedata-recv-knot.pyc /usr/local/myniche/lib/ods-zonedata
cp -p ods-zonedata/ods-zonedata-recv-opendnssec.py /usr/local/myniche/lib/ods-zonedata
cp -p ods-zonedata/ods-zonedata-recv-opendnssec.pyc /usr/local/myniche/lib/ods-zonedata
sed -e s/@PREFIX@/\/usr\/local\/myniche/g < ods-zonedata/ods-zonedata-recv.service > /lib/systemd/system/ods-zonedata-recv.service
cp -p ods-zonedata/ods-zonedata-signconf /usr/local/myniche/bin
cp -p ods-zonedata/ods-zonedata-unsigned /usr/local/myniche/bin

Script installation done.  You also need to setup RabbitMQ.

You can now setup accounts with configurations for the scripts.

Binaries  need       PATH="$PATH:/usr/local/myniche/bin"
Libraries need PYTHONPATH="$PYTHONPATH:/usr/local/myniche/lib"
```

## Afterwork

**Path settings:**
Note the last few lines of the installer output; their instructions
help you setup your system!

**RSync:**
You probably want to create a fifo of some kind, so the RSync wrapper
can hint the RabbitMQ daemon that the state should be read and updated.
You might do this with

```
mknod p /home/portal/newzonedata.fifo
chown portal:portal /home/portal/newzonedata.fifo
```

The filename is setup in the `trigger_fifo` setting in secion
`[ods-rsync-zonedata]` of the configuration.

**Configuration:**
We include an example configuration file in `example/ods-amqp.config`.
It can be installed either in `/etc/opendnssec/ods-amqp.config`
or in individual accounts' `~/ods-amqp/config` or a combination.
You should setup passwords for the RabbitMQ accounts and you should
strip away any configuration settings that are not needed either
centrally or in an individual account.

## Interaction with Systemd

If your setup did not install the `systemd` scripts, you may have to do
this manually from `ods-*/*.service` while replacing `@PREFIX@` with the
installation prefix used when `install.sh` was run.

You can now start and stop the individual services through `systemd`,
refercing the various services that were installed from `ods-*/*.service`,

  * `ods-backup-stash.service`
  * `ods-keyops.service`
  * `ods-generic-parent.service`
  * `ods-parenting-exchange.service`
  * `ods-registry.service`
  * `ods-utimaco-recv.service`
  * `ods-votes-recv.service`
  * `ods-zonedata-recv.service`

The set of daemons that you will want to run depends on the purpose
of the machine running it.  In general, you may want a composed target.
We included a few examples of machine targets that can be installed
to combine the individual `systemd` scripts.  These targets can be
found in `example/*.target` and will not be installed by default.

