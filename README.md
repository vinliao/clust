# Nostr CLI client built with Rust
This is very unstable and experimental. It's best to not use your "real identity."

APIs:
- [ ] `clust chat <name>`
- [ ] `clust inbox`

Low-level APIs:
- [x] `clust init`
- [x] `clust generate-keypair`
- [x] `clust set-private <key>`
- [x] `clust publish-raw <event>`
- [x] `clust get-event <id>`
- [x] `clust add-contact <name> <pubkey>`
- [ ] `clust delete-contact <name>`
- [x] `clust change-contact-pubkey <name> <pubkey>`

Backend to-do:
- [x] replace `schnorr_fun` with `secp256k1`
- [x] use config file to store keys and subscriptions
- [ ] use `serde` and struct instead of throwing json around
- [ ] store config file in `~/.config/clust/config.json`
- [ ] pick relay from config file
- [ ] only use strings to pretty-print, deal directly with bytes and structs
- [ ] write tests (duh)