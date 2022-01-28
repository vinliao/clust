# Nostr CLI client built with Rust
APIs:
- [x] `clust post <content>`
- [x] `clust set-private <key>`
- [x] `clust generate-key`
- [x] `clust init`
- [x] `clust get-event <id>`
- [x] `clust get-profile <pubkey>`
- [x] `clust subscribe-to <pubkey>`
- [x] `clust unsubscribe-from <pubkey>`
- [ ] `clust add-relay <url>`
- [ ] `clust remove-relay <url>`
- [ ] `clust home`

Backend to-do:
- [ ] use `serde` and struct instead of throwing json around
- [x] use config file to store keys and subscriptions
- [x] replace `schnorr_fun` with `secp256k1`

Questions (please DM if you know the answer):
- What's the safest way to store private keys used in this CLI?
- Where should the config file be stored?
- Should `clust generate-key` be exposed to user, or should it be a private function? 
