# Nostr CLI client built with Rust
APIs:
- [x] `clust init`
- [x] `clust generate-key`
- [x] `clust set-private <key>`
- [x] `clust publish-raw <event>`
- [ ] `clust message-from <pubkey>`
- [ ] `clust message-send <pubkey> <message>`
- [x] `clust get-event <id>`

Backend to-do:
- [x] replace `schnorr_fun` with `secp256k1`
- [x] use config file to store keys and subscriptions
- [ ] use `serde` and struct instead of throwing json around
- [ ] store config file in `~/.config/clust/config.json`
- [ ] pick relay from config file

Questions (please DM if you know the answer):
- What's the safest way to store private keys used in this CLI?
- Where should the config file be stored?
- Should `clust generate-key` be exposed to user, or should it be a private function? 
