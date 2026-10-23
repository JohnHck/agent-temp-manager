# ADR-0010: Pseudonymization of exported identifiers

Status: PROPOSED (maintainer gate after P1-B4-d; D-7 and D-8 open)
Date: 2026-10-23
Phase: P1 (P1-B4-d)

## Context

`atm.diagnose/1` exported the path of every temporary partition as its finding key. For Claude Code the session root
name in that path is the session identifier: a read-only check on the development machine found 2 of 2 live sessions.
The export therefore carried raw session identifiers. P1-B4-c pseudonymized agent session keys with an unkeyed SHA-256
over the provider, the profile SID and path, and the session id. Anyone holding the export could recompute those keys,
because the partition paths gave the profile path and the identity gave the SID. The maintainer chose option (b) at the
gate of 2026-10-23: protect session and partition identifiers in every diagnose output, with a schema version if needed.

ADR-0009 makes `diagnose` read-only, so it cannot create or store a secret on its own.

## Decision

1. **Keyed pseudonyms.** Exported keys of temporary partitions and agent sessions are HMAC-SHA256 values, truncated to
   128 bits and written as 32 hex characters. The HMAC input is length-prefixed fields after a domain label:
   * `atm-partition/1`: provider and partition path;
   * `atm-session/2`: provider, profile SID, profile path and session id;
   * `atm-key-id/1`: key identifier, no fields.
   Formats: `<provider>/p-<hex>` for partitions and `<provider>/s-<hex>` for sessions. Without the key nobody can
   compute or check a pseudonym from the inputs, and the export does not contain the key.
2. **Key source.**
   * **Default:** an ephemeral random key of 32 bytes for one run. Session and partition pseudonyms are then not
     comparable between runs.
   * **Operator key:** correlation between runs is possible only through a key file the operator provides
     (`diagnose -PseudonymKeyFile <file>`). The file is read only and is refused, with nothing run, unless all of these
     hold:
     * it is a drive-absolute path on a fixed drive (`Test-AtmPathChain`);
     * no folder in the path and not the file itself is a reparse point;
     * it is a regular file of 32 to 4096 bytes;
     * its owner is the current user, SYSTEM or Administrators;
     * no other account may read or change it (generic rights included).
     The file is opened once, without write or delete sharing, so the file checked is the file read. The refusal shows
     a code only, never the path or the content.
   * **Key id:** an operator key has an identifier (`keyId`, the HMAC of its own domain label) so two exports can be
     known to be comparable. An ephemeral key has no identifier.
3. **Handling the key.** The key lives only inside one `Invoke-AtmDiagnose` call. When the call returns or throws, the
   HMAC object is disposed and the private copy of the key is cleared. The key is never written to a result, a
   string, a log or a message. The result carries only the scheme, the key source and the key id.
4. **No paths in the diagnose export.** Temporary partitions are identified only by their pseudonym; no other field
   carries a path. The diagnose report shows no partition path.
5. **Schema `atm.diagnose/2`.** The meaning of `findings[].key` changed for `TempPartition` and `AgentSession`, and a
   top-level `pseudonymization` object was added. ADR-0009 rule 4 requires a new version for that; the change
   history is in `DIAGNOSE-SCHEMA.md`.
6. **Collisions fail closed.**
   * Two partitions with the same pseudonym become one `UNKNOWN` finding (`PARTITION_KEY_COLLISION`); neither
     partition is overwritten.
   * The same holds for sessions (`SESSION_KEY_COLLISION`).
   * One session listed with different PIDs also stays `UNKNOWN` (`SESSION_ENTRIES_CONFLICT`).
7. **Reads across profiles.** `diagnose` reads the session registries of other profiles under these limits:
   * **minimal scope:** only `<profile>\.claude\sessions\*.json`, through the provider member that V0.1 already uses;
   * **minimal privilege:** elevation is never requested;
   * **explicit purpose:** session evidence;
   * **honest coverage:** an unreadable profile makes `sessions-<provider>` `PARTIAL`, never "no session".

## Open decision

**D-7, a persistent key.** Under this ADR the default key is ephemeral, which drops the "same session, same key in
every run" property of the earlier D1 unless the operator supplies a key file. Options:

* **K1 (implemented):** ephemeral by default, operator key file for correlation. `diagnose` stays read-only.
* **K2:** a separate, explicit command creates a per-user key protected with DPAPI (for example under
  `%LOCALAPPDATA%\AgentTempManager`), and `diagnose` reads it when it is present. `diagnose` stays read-only, but the
  product owns a secret and its lifecycle: rotation, loss, backup, elevated runs and multi-user machines.
* **K3:** `diagnose` creates the key on first use. This needs a new ADR overriding the read-only rule of ADR-0009.

`diagnose` behaves the same under K1 and K2: it uses a supplied key when there is one and an ephemeral key otherwise.
Nothing beyond K1 is built until the maintainer decides D-7.

**D-8, order of partition findings.** D6 keeps temporary partitions in the V0.1 order, which links pseudonyms to paths
by position for whoever can list the temporary bases (see the boundary below). Options: keep D6 (implemented; the link
is documented), or order partition findings by pseudonym (the position link is gone; with an ephemeral key the order
then changes between runs). Recommendation: order by pseudonym. Not built until decided.

## Boundary (not changed by this ADR)

* **V0.1 governed outputs keep their paths**, because the operator needs them to review and select what to clean:
  * the `audit` report and `audit -ExportJson` (`path`, `scope`, `profiles[].path`, which carry session-root names);
  * `Show-AtmPathDetail`;
  * `preview`;
  * the clean plan and `clean -LogFile`;
  * the TUI detail view.
  The V0.1 export is a different document and is unchanged. Whether it also needs a redacted mode is a separate
  decision.
* **Identity in the diagnose export:** `machine`, `identity.user` and `identity.sid` stay, because the identity and
  elevation state explain every coverage record (PRIV-10). They identify the account and the machine. They are no
  longer a way to rebuild a pseudonym, but they remain identifying, and the export privacy notice says so.
* **Not pseudonymized:**
  * process keys (`<pid>@<creation ticks>`);
  * counts, coverage records and resource totals.
  They stay linkable between runs.
* **Order of `AgentSession` findings:** runtime findings are ordered by key, so with an ephemeral key the order of
  `AgentSession` findings differs between runs. The content does not change; the order is the same for one key.
* **Linkage by position and evidence (independent review):** partition findings keep the V0.1 order (D6), which is the
  file-system enumeration order, and keep the audit class and flags. Whoever can list the temporary bases, or holds a
  V0.1 `audit -ExportJson` of the same moment (which already carries the paths), can relate partition pseudonyms to
  paths by position. A process key (`pid@ticks`) with `SESSION_PROCESS_MATCH` can be tied to a session file by whoever
  can read the session directory. The HMAC prevents computing or checking a pseudonym; it does not make the findings
  unlinkable for someone with that local access. Ordering partition findings by pseudonym would remove the position
  link but changes the approved D6: open decision D-8.
* **Weak operator keys:** any 32 bytes are accepted. A key that is not random (a passphrase) can be guessed offline
  from the exported `keyId`, and then every pseudonym computed for candidate identifiers. The documentation asks for
  bytes from a random generator; the tool cannot measure a key's entropy.
* **In memory:** the result object keeps the V0.1 inventory the run was built on (`Inventory`, with paths and the
  session registries), as before. It is never exported nor printed by `diagnose`.
* **Progress and errors:** while `diagnose` runs, the progress line shows no path; an unexpected failure is reported by
  its exception type only.

## Rejected alternatives

* **Unkeyed hash (P1-B4-c):** it can be recomputed from the export and from any source of the raw identifiers.
* **A key derived from machine or account data** (MachineGuid, SID, user name): it is not secret, so anyone on the
  machine, or with the export, can recompute it.
* **Keep paths and redact only the session root name:** the rest of the path still names the user and the project
  (the scope slug comes from the project path).
* **Encrypt the paths in the export:** that would protect the identifiers only as long as the key is never shared,
  and it adds a decryption path the product does not need.

## Consequences

* Without a key file, two diagnose exports cannot be compared item by item for partitions and sessions.
* A lost operator key cannot be recovered. A new key starts a new, non-comparable series.
* Consumers of `atm.diagnose/1` must move to version 2. Keys look different, and partition keys no longer carry a
  path.

## Verification

* **Tests "Pseudonimos (P1-B4-d)":**
  * with the ephemeral default, partition and session keys differ between runs, while process keys stay comparable;
  * the same key file gives the same keys and key id, and another file gives others;
  * the caller's key is not changed;
  * the JSON, the report and the in-memory result apart from its `Inventory` contain none of these: the session id,
    paths, root names, the key in hex or base64, or the key file path;
  * a closed pseudonymizer is disposed and its key copy cleared.
* **Test "Reconstrucao adversarial (P1-B4-d)":** starting from the export, none of these rebuilds a pseudonym:
  * the P1-B4-c unkeyed formula;
  * HMAC keys built from the exported machine, SID, user, key id, schema or scheme;
  * an empty key;
  * an all-zero key.
  A control computation with the real key does match.
* **Test "Arquivo de chave do operador (P1-B4-d)":**
  * relative, drive-relative or rooted-without-drive paths, missing files, directories, short or long files, and files
    readable or writable by another account (Everyone, INTERACTIVE, Users, generic read) are refused;
  * the CLI fails closed with exit code 2 and shows only the code.
* **Test "Colisao de chave de particao (P1-B4-d)":** a forced collision gives one `UNKNOWN` finding, with nothing
  overwritten.
* **Real read-only run on the development machine:** no session id or partition path appears in the export or the
  report.
