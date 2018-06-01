# Modular DNSSEC Signing Infrastructure

These processes combine into a modular DNSSEC signer management
infrastructure on replicated nodes.  Properties are:

  * Infrastructure based on RabbitMQ for replication and helpful management
  * Choice of signer backend: OpenDNSSEC or Knot DNS
  * Key storage in PKCS #11
  * Replicated signing: multiple signers can be active
  * Uses [ods-rpc](http://github.com/vanrein/ods-rpc) for DNSSEC on/off switching
  * DNSSEC on/off switching is orthogonal to zone data
  * Parenting support, both locally and towards upstream registries
  * Framework for HSM state replication (currently implemented: Utimaco HSM)
  * Flexible security model by separation of concerns into accounts
  * Flexible configuration security rooted in a need-to-know basis

The processes are all programmed in Python, so they can be easily modified.

