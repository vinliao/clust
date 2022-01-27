# Nostr CLI client built with Rust
APIs:
- [x] `clust post <content>`
- [ ] `clust set-private <key>`
- [ ] `clust generate-key`
- [ ] `clust get`
- [ ] `clust subscribe <id>`

Backend to-do:
- [ ] use `serde` and struct instead of throwing strings around
- [ ] use config file to store keys and subscriptions
- [ ] replace `schnorr_fun` with `secp256k1`
