wg-portal v2.3.1 with two ETTI fixes for Active Directory:

- the LDAP user synchronization pages its search (SearchWithPaging, 500), so Active Directory's 1000-entry limit no longer makes it fail with "Size Limit Exceeded";
- new LDAP `field_map` key `user_identifier_fallback` (e.g. `userPrincipalName`): used, lowercased, as the user identifier when `user_identifier` (e.g. `mail`) is empty, so accounts without an e-mail address can log in.

Static linux/amd64 binary built by the etti-release workflow (CGO_ENABLED=0, netgo), as the upstream Dockerfile does; its sha256 is in wg-portal_linux_amd64.sha256.
