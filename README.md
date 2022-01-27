# Nostr CLI client built with Rust
APIs:
- [x] `clust post <content>`
- [ ] `clust set-private <key>`
- [x] `clust generate-key`
- [ ] `clust subscribe <id>`
- [ ] `clust get <filter> --with-flags`
- [ ] `clust home`

Backend to-do:
- [ ] use `serde` and struct instead of throwing strings around
- [ ] use config file to store keys and subscriptions
- [x] replace `schnorr_fun` with `secp256k1`
