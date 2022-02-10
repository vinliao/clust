# Nostr CLI client built with Rust
This is very unstable and experimental. It's best to not use your "real identity."

APIs:
- [x] `clust init`
- [x] `clust chat <name>` (launches a new ui, just like `ranger`, or something)
- [ ] `clust send <name> <message>`

Low-level APIs:
- [x] `clust generate-keypair`
- [x] `clust set-private <key>`
- [x] `clust publish-raw <event>`
- [x] `clust get-event <id>`
- [x] `clust get-dm <pubkey>`
- [x] `clust create-dm-throwaway-key <pubkey> <message>`
- [x] `clust send-alias` (return two raw events, currently kind 1, but in the future new kind)
- [ ] `clust add-contact <name> <contact pubkey> <alias privkey>`
- [ ] `clust change-contact-pubkey <name> <pubkey>` (used after having received alias)
- [ ] `clust send-new-alias <pubkey>` (send alias with NIP-04, and save alias to config)

Backend to-do:
- [x] replace `schnorr_fun` with `secp256k1`
- [x] use config file to store keys and subscriptions
- [ ] use `serde` and struct instead of throwing json around
- [ ] store config file in `~/.config/clust/config.json`
- [ ] pick relay from config file
- [ ] only use strings to pretty-print, deal directly with bytes and structs
- [ ] write tests (duh)