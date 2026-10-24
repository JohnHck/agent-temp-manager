# ADR-0012: Service account privacy

Status: ACCEPTED (maintainer decision at the HUMAN_GATE of PR #42, "P2-A-S security, coverage and privacy
correction", 2026-10-24: account names that are personal or specific to an organization are not exported by default)
Date: 2026-10-24
Phase: P2 (P2-A-S)
Replaces: ADR-0005 rule 6 only (the rest of ADR-0005 is unchanged; ADR-0005 keeps rule 6 as history)

## Context

ADR-0005 rule 6 reported a service's `StartName` as the account name: `LocalSystem`, `NT AUTHORITY\...` and virtual
service accounts as such, and any other account by its name. P2-A implemented it. A user account (`DOMAIN\user`,
`.\user`, `user@domain`), a group managed service account (`DOMAIN\name$`) or a virtual account (`NT SERVICE\name`)
names a person, an organization or a specific installation. Such a name would reach the JSON export and the report,
which may be shared.

## Decision

1. `StartName` is read in memory only, to classify the account, and is never stored, printed or exported.
2. Every readable account gives its kind (`SERVICE_ACCOUNT_KIND`): `LOCAL_SYSTEM`, `LOCAL_SERVICE`,
   `NETWORK_SERVICE`, `VIRTUAL`, `BUILTIN`, `MANAGED` or `USER`.
3. A standard identifier (`SERVICE_ACCOUNT`) is given only for the three built-in service accounts, recognized by
   exact text without regard to case: `LocalSystem` (also `NT AUTHORITY\SYSTEM`, `.\LocalSystem`),
   `NT AUTHORITY\LocalService` (also `NT AUTHORITY\Local Service`) and `NT AUTHORITY\NetworkService` (also
   `NT AUTHORITY\Network Service`). The exported value is the standard spelling, never the raw text.
4. `VIRTUAL` (`NT SERVICE\...`), `MANAGED` (ending with `$`), `USER` (anything else, including UPN forms) and
   `BUILTIN` (any other `NT AUTHORITY\...`, since no list of them is recognized safely) give the kind only: no domain,
   user, UPN, managed or service-specific name.
5. A kind given without a name for privacy is not an unreadable value: no `SERVICE_ACCOUNT_UNREADABLE`, no `PARTIAL`.
   A missing, empty, overlong or malformed value (control characters, more than 256 characters, not text) is
   unreadable: `SERVICE_ACCOUNT_UNREADABLE` and `service-properties` `PARTIAL`.
6. There is no option to export account names in this macro-phase.

## Rejected alternatives

* *Exporting the name, as ADR-0005 rule 6 did:* a shared report would carry personal and organizational identifiers.
* *A keyed pseudonym of the account (ADR-0010):* allows correlation of the same account across services and runs,
  which nothing in P2 needs; can be proposed later with its own decision.
* *An opt-in switch:* not authorized in this macro-phase.

## Consequences

* The report and the JSON show which kind of account a service runs as, never which user or organization.
* Two services running as two different user accounts look the same in the export.

## Verification

* Tests with `DOMAIN\user`, `.\user`, `user@domain`, `DOMAIN\gmsa$`, `NT SERVICE\service`, `LocalSystem`,
  `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, other `NT AUTHORITY\...`, and missing, empty, overlong,
  malformed and non-text values; the whole JSON, report, coverage reasons and evidence details are searched for the
  raw names, not only the `SERVICE_ACCOUNT` field.
