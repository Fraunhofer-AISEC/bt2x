#ifndef BT4OT
#define BT4OT

typedef struct SubjectIdentity {
  const char *identifier;
  const char *issuer;
} SubjectIdentity;

bool verify_bt(const uint8_t *rekor_pub_key,
               uintptr_t rekor_pub_key_len,
               const uint8_t *root_cert,
               uintptr_t root_cert_len,
               const uint8_t *bundle,
               uintptr_t bundle_len,
               const uint8_t *blob,
               uintptr_t blob_len,
               const struct SubjectIdentity *subject_identities,
               uintptr_t subject_identities_len);

#endif /* BT4OT */
