## Test Scenarios for Client Updates

### Update Root Role

- Refer to [the corresponding TUF specification section](https://theupdateframework.github.io/specification/v1.0.33/index.html#update-root).
- [ ] *"[T]he client MUST download intermediate root metadata files, until the latest available one is reached"*
- [x] *"Check for arbitrary Software Attack"*
    - [x] *"Version N+1 of the root metadata file MUST have been signed by:*"
        - [x] *"a THRESHOLD of keys specified in the trusted root metadata file (version N)"*
        - [x] *"a THRESHOLD of keys specified in the new root metadata file being validated (version N+1)."*
    - [x] *"When computing the THRESHOLD each KEY MUST only contribute one SIGNATURE."*
        - [x] *"each SIGNATURE which is counted towards the THRESHOLD MUST have a unique KEYID"*
        - [x] *"Even if a KEYID is listed more than once in the "signatures" list a client MUST NOT count more than one verified SIGNATURE from that KEYID towards the THRESHOLD."*
- [x] *"Check for a rollback attack. The version number of the new root metadata (version N+1) MUST be exactly the version in the trusted root metadata (version N) incremented by one, that is precisely N+1."*
- [x] *"Check for a freeze attack. The expiration timestamp in the trusted root metadata file MUST be higher than the fixed update start time. If the trusted root metadata file has expired, abort the update cycle, report the potential freeze attack."*
- [x] *"If the timestamp and / or snapshot keys have been rotated, then delete the trusted timestamp and snapshot metadata files."*
- [ ] *"Set whether consistent snapshots are used as per the trusted root metadata file"*

### Update Timestamp Role

- Refer to [the corresponding TUF specification section](https://theupdateframework.github.io/specification/v1.0.33/index.html#update-timestamp).
- [x] *"Check for arbitrary Software Attack"*
    - [x] *"The new timestamp metadata file MUST have been signed by:*"
        - [x] *"a THRESHOLD of keys specified in the trusted root metadata file (version N)"*
    - [x] *"When computing the THRESHOLD each KEY MUST only contribute one SIGNATURE."*
        - [x] *"each SIGNATURE which is counted towards the THRESHOLD MUST have a unique KEYID"*
        - [x] *"Even if a KEYID is listed more than once in the "signatures" list a client MUST NOT count more than one verified SIGNATURE from that KEYID towards the THRESHOLD."*
- [x] *"Check for a rollback attack."*
    - [x] *"The version number of the trusted timestamp metadata file, if any, MUST be less than the version number of the new timestamp metadata file."*
    - [x] *"In case they are equal, discard the new timestamp metadata and abort the update cycle. This is normal and it shouldn’t raise any error."*
    - [x] *"The version number of the snapshot metadata file in the trusted timestamp metadata file, if any, MUST be less than or equal to its version number in the new timestamp metadata file. If not, discard the new timestamp metadata file, abort the update cycle, and report the failure."*
- [x] *"Check for a freeze attack. The expiration timestamp in the new timestamp metadata file MUST be higher than the fixed update start time. If so, the new timestamp metadata file becomes the trusted timestamp metadata file. If the new timestamp metadata file has expired, discard it, abort the update cycle, and report the potential freeze attack."*


### Update Snapshot Role


- Refer to [the corresponding TUF specification section](https://theupdateframework.github.io/specification/v1.0.33/index.html#update-snapshot).
- [x] *"Check against timestamp role’s snapshot hash. The hashes of the new snapshot metadata file MUST match the hashes, if any, listed in the trusted timestamp metadata."*
- [x] *"Check for arbitrary Software Attack"*
    - [x] *"The new snapshot metadata file MUST have been signed by:*"
        - [x] *"a THRESHOLD of keys specified in the trusted root metadata file (version N)"*
    - [x] *"When computing the THRESHOLD each KEY MUST only contribute one SIGNATURE."*
        - [x] *"each SIGNATURE which is counted towards the THRESHOLD MUST have a unique KEYID"*
        - [x] *"Even if a KEYID is listed more than once in the "signatures" list a client MUST NOT count more than one verified SIGNATURE from that KEYID towards the THRESHOLD."*
- [x] *"The version number of the new snapshot metadata file MUST match the version number listed in the trusted timestamp metadata."*
- [x] *"Check for a rollback attack."*
    - [x] *"The version number of the targets metadata file, and all delegated targets metadata files, if any, in the trusted snapshot metadata file, if any, MUST be less than or equal to its version number in the new snapshot metadata file."*
    - [x] *"[A]ny targets metadata filename that was listed in the trusted snapshot metadata file, if any, MUST continue to be listed in the new snapshot metadata file."*
- [x] *"Check for a freeze attack. The expiration timestamp in the new snapshot metadata file MUST be higher than the fixed update start time. If so, the new snapshot metadata file becomes the trusted snapshot metadata file."*
    
### Update Targets Role

- Refer to [the corresponding TUF specification section](https://theupdateframework.github.io/specification/v1.0.33/index.html#update-targets).

- [x] *"Check against snapshot role’s targets hash. The hashes of the new targets metadata file MUST match the hashes, if any, listed in the trusted snapshot metadata."*
- [x] *"Check for arbitrary Software Attack"*
    - [x] *"The new targets metadata file MUST have been signed by[:]*"
        - [x] *"a THRESHOLD of keys specified in the trusted root metadata file (version N)"*
    - [x] *"When computing the THRESHOLD each KEY MUST only contribute one SIGNATURE."*
        - [x] *"each SIGNATURE which is counted towards the THRESHOLD MUST have a unique KEYID"*
        - [x] *"Even if a KEYID is listed more than once in the "signatures" list a client MUST NOT count more than one verified SIGNATURE from that KEYID towards the THRESHOLD."*
- [x] *"Check against snapshot role’s targets version. The version number of the new targets metadata file MUST match the version number listed in the trusted snapshot metadata."*
- [x] *"Check for a freeze attack. The expiration timestamp in the new targets metadata file MUST be higher than the fixed update start time."*
- [ ] *"Perform a pre-order depth-first search for metadata about the desired target, beginning with the top-level targets role."*
    - [ ] *"If this role has been visited before, then skip this role (so that cycles in the delegation graph are avoided). Otherwise, if an application-specific maximum number of roles have been visited, then go to step § 5.7 Fetch target (so that attackers cannot cause the client to waste excessive bandwidth or time). Otherwise, if this role contains metadata about the desired target, then go to step § 5.7 Fetch target."*
    - [ ] *"Otherwise, recursively search the list of delegations in order of appearance."*
        - [x] *"If the current delegation is a terminating delegation, then jump to step § 5.7 Fetch target."*
        - [] *"Otherwise, if the current delegation is a non-terminating delegation, continue processing the next delegation, if any. Stop the search, and jump to step § 5.7 Fetch target as soon as a delegation returns a result."*

### Fetch Target

- Refer to [the corresponding TUF specification section](https://theupdateframework.github.io/specification/v1.0.33/index.html#fetch-target).
- [x] *"Verify the desired target against its targets metadata."*
- [x] *"download the target (up to the number of bytes specified in the targets metadata)"*
- [x] *"verify that its hashes match the targets metadata"*

