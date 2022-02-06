# Nostr CLI client built with Rust
APIs:
- [x] `clust init`
- [x] `clust generate-keypair`
- [x] `clust set-private <key>`
- [ ] `clust add-contact <key>`
- [ ] `clust message-from <pubkey>`
- [ ] `clust message-send <pubkey> <message>`

Low-level APIs:
- [ ] `clust create-raw-message <pubkey> <message>`
- [x] `clust publish-raw <event>`
- [x] `clust get-event <id>`

Backend to-do:
- [x] replace `schnorr_fun` with `secp256k1`
- [x] use config file to store keys and subscriptions
- [ ] use `serde` and struct instead of throwing json around
- [ ] store config file in `~/.config/clust/config.json`
- [ ] pick relay from config file
- [ ] only use strings to pretty-print, deal directly with bytes and structs
- [ ] write tests (duh)