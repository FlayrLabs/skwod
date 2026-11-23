`engine-state-v1.bin` is a genuine protocol-v1 engine snapshot (the postcard blob builds 29–40
kept under the `engine-state` key of the SQLCipher cache). It was produced by the pre-libsignal
`skwod-crypto` (git history, before ADR-011) with throwaway random keys: a v1 identity, prekeys,
two Double Ratchet sessions with skipped message keys, a pending PQXDH initial message, a sender
key and a sender-key receiver, two space keys, pinned identities, an expected provisioner and the
trailing `group_dist` map. It exists so the upgrade path is tested against real v1 bytes rather
than against a mirror of our own reader. The keys in it belong to nobody.
