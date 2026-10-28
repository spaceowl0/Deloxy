# Deloxy security notes (alpha)
This is a design description plus an honest list of what is NOT protected. It is not a security audit; nobody has audited this code.

## Model
* **No ambient authority.** A process can only act through capabilities in its table: `Tty`, `Dir`/`File` (read-only initramfs), `Spawn`, `Sys`, `Power`,
  `NetAdmin`, `Net`, audit, memory/channel, io-port. There is no global filesystem namespace and no path-based open. Rights can only be reduced
  (`cap_derive`); handles are generation-tagged; revoking a parent invalidates its children. Exception kept for bring-up: `write_debug` (serial output).
* **Audit.** Syscalls, capability denials, faults, process lifecycle and every firewall decision are recorded in a lockless ring (`audit` builtin). The ring is bounded; floods are counted, not stored.
* **Memory.** W^X mappings, NX, WP, SMEP when the CPU reports it (QEMU's default CPU does not), guard-paged kernel stacks. No SMAP yet, single CPU.
* **Loaders** (`exec/`) treat images as hostile: checked arithmetic, bounded sizes, 10,000-case mutation fuzz in the selftest. The initramfs tar parser has its own 20,000-case fuzz.

## Networking: air-gapped by default
1. At boot the virtio-net device is probed and **reset**: no queues, no DRIVER_OK, it cannot move a packet. Tested: packet capture contains 0 frames until a grant exists.
2. Only code holding `NetAdmin` can mint a `NetGrant` (the shell, after the human answers `y`). A grant = TCP, one /32 host, one port, <= 1 hour, <= 1 GiB budget; loopback/multicast refused.
3. While >= 1 live grant exists the NIC is started; when the last one expires, is revoked or is dropped the device is reset again. Sockets whose grant dies are aborted.
4. Every Ethernet frame in both directions passes the default-deny firewall: allowed = ARP, the DHCP client exchange, granted outbound flows, and replies to those flows. No listening sockets, no IPv6, fragments dropped, spoofed source addresses dropped. All parsing is bounds-checked and fuzzed (30,000 mutated frames). Denials are audited (rate-limited).
5. Threats this does **not** cover: a malicious host/hypervisor, DMA attacks (no IOMMU), a bug in virtio/smoltcp/firewall, traffic analysis, no TLS (updates are authenticated, not confidential).

## Updater (`deloxy-upd`)
Pull-only and user-initiated; no timers, no telemetry. `manifest.sig` (Ed25519, `deloxy-sig-v1` format) is verified over the raw manifest bytes **before** the manifest is parsed;
the parser is strict (no unknown or duplicate keys, bounded sizes, safe names/paths). Rollback protection: offered version must be newer than the running kernel and than anything already staged.
Artifacts are accepted only if size and SHA-256 match. Verified artifacts are staged in RAM and, if a store disk is mounted, persisted as kernel-owned `upd.*` files (see Persistent store); **activating an update is not implemented** (the boot medium is read-only).
**The compiled-in trusted key is a TEST key whose private half is published in `tools/mock-update-server.py`.** Anyone can sign updates for it. Before a real release:
generate a key on an offline machine, store the seed offline (ideally split across >=2 holders), put only the public key + its key id (first 8 bytes of SHA-256(pubkey)) in `src/upd/keys.rs`,
sign each release manifest offline, and document a revocation/rotation path (the alpha has none: a lost key means shipping a new kernel). `tools/lib/ed25519_ref.py` is a non-constant-time test signer and must never touch a real key.

## Persistent store
Access is by capability only (`Store`: READ list/open, WRITE write/delete, GRANT format); the shell is the only holder. A blank or unrecognised disk is never formatted automatically, and formatting needs an explicit human `yes`.
Integrity: CRC-32 on every file and on both directory copies (detects accidental corruption and torn writes, **not** a malicious writer: CRC-32 is not a MAC, and the disk is not encrypted or authenticated).
Crash safety is tested against a fault-injecting RAM disk and QEMU only. `upd.*` names are reserved to the kernel updater: the rollback floor (`upd.floor`) cannot be forged or lowered by user programs through the syscall interface,
but anyone who can write the raw disk can (no secure storage/TPM); a signed manifest is still required to raise it. Stored programs are executable via `Spawn` and are not signature-checked.
Threats not covered: physical access to the disk, DMA, a compromised hypervisor, power-loss behaviour of real devices with volatile write caches that ignore FLUSH.

## Application permissions
Foreign programs are untrusted by default: no file access until the user decides, asked at the first file access on the program's console (once/always/no/deny always), keyed by program name + image hash, stored in `perms.db` (kernel-owned, `store::is_reserved`). Enforcement is in the kernel (`abi::vfs::can`), not in the shell: the shell can only record decisions through the `Policy` capability. Programs without a console are denied. A grant is all-or-nothing (initramfs read + store read/write), there is no per-file scoping yet, and network/device permissions do not exist because those APIs do not exist.
**Network:** a foreign program may create sockets freely but each `connect` needs the user's consent (once / always for this host / **full access** / no / deny always; stored per program + image hash + destination). "This host" mints a `NetGrant` limited to that host and port (default 10 minutes, 64 MiB); **full access is an any-host grant with no time or data limit** (still never loopback/multicast, and it can reach the local network unless the rule is internet-only), and users can set custom time/data limits per rule. Limits cover the whole program run (one shared grant per rule), so extra sockets cannot bypass them; the NIC is inert unless a grant is live; loopback and multicast can never be granted; the kernel firewall remains default-deny and audits denials. There is no DNS, UDP, TLS or listening socket, so programs need numeric addresses and speak plaintext TCP.
Limits: foreign processes are capped at 128 MiB, 32 threads and 64 open files. A user can end any non-shell process from the Task Manager.

## Foreign programs (deloxy-wltd)
File access is a capability: Linux/Windows programs see files only if they were spawned with `Dir`/`Store` capabilities (the shell grants both to what it runs; native children never get them). Writes are limited to the store, flat names, 4 MiB per file, never `upd.*`.
The Linux/NT syscall layers are a large attack surface written for compatibility, not hardened beyond the existing user-pointer checks (`copy_from/to_user`) and fuzzing of the loaders; they run foreign code in ring 3 under the same page-table isolation as native code.

## Known weak spots
Single global audit producer; capability transfer over channels missing; polling drivers; `getrandom` for Linux programs is not cryptographic; the smoltcp TCP initial sequence numbers
use a non-cryptographic seed; no ASLR; no stack canaries in user programs; no SMP-safety review.
