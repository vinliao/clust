# Nostr CLI client built with Rust
Encrypted chat inside Nostr leaks metadata of who talks to who. This small CLI app implements a "public inbox," which obfuscates that metadata. It's private chat, but more private.

The basic idea is this:
1. Alice announces her pubkey to Bob
2. Both have each other's pubkey, both can derive shared key from it 
3. They both post message to "public inbox" with sha256(shared_key) on its tag
4. With the shared key, only both can create the private event, only both can decrypt
5. Nobody knows who is messaging who since there's no pubkey on the event
6. If attacker tries to tamper with the event, either the event's signature becomes invalid or the content can't be decrypted by Alice or Bob

Let me illustrate with an analogy: Public inbox is to PO box what public key is to home address. Instead of sending mails to each other's home address, Alice and Bob send mails to a PO box. In the PO box, only they know how to find each other's mails, only they can write to each other through that PO box.

Example private message event:
```
{"content":"B+teWrgJ4ljieX3Fbr8H3NWA7KbIl4ImRLSqDhbRgavMKGqtmCfsMdwRIp0FjYWEn9B0Kiv4TfhUls0zEkq/9N7EmDlgcX+iinna/brdXc9qy2O5PqO/kap2skbKLZ5gCHOw3oSdP5DyNuSRpxuUOFMuI9xMUxL/zipsVJQDlhbCg2qLzw5Yq2mK0RJSXnDe515lKS6Eb9XlBCa6nYWxq1QzhuvRxDgN5o1ZuIirJDsylMzcDt5/niFW9daav4/WjY1XbbjeUc2XbSFB10J5FpMoz+TgG/NVxNKpmm4VSHBhs+v/A+jF/j/HJQlsbHrsavy2aRKHkRFVYqL7Phyd4O3hKRFcZrS4tnh2nesXif5QoZgxIEqD8eCDQOorO6UUXo8SHOFKdlSXfuYCgFecIVeM+QKTaST4eizJJbx0X8+qnYuuYxAqQt0+0MUMDGPbErlCw1nDhprLY3C3th6y5dDWfGs/cGuhDZBJWpbWvXs69xury9qGfo0p9GDDwprtb363d6/cTxHgMSaji5p7hfXTHzdiyuqfH90TuW8TIuQyfpV7F/BCoUq45wdv9nqpzlV+x/HLXIlOCGu23cNriJcIDFf7SfNk8WmiQpa69nCTYvManculqE2+eIn4k/jj1lWEA7YdSWjVAqJtmhBgnQ==?iv=SbNrOyZOtL7ymyvUxK9xWw==","created_at":1644948134,"id":"3bee25d04aeb632c4babe4a978b838a08882c42874df64858cfd66b41284a87c","kind":4,"pubkey":"9073f08fa71396e45d89adf34024e5c1dccaa369bab3c0d285994fdb8e150e07","sig":"185702115bdf3e5b79219e440ff56efe53924d95ab27325b2fe835c98512dcccecc733d34c807869efb19afd6a9519f42234afe798a61f0e2492669753c20cce","tags":[["shared","781caa9f1d2ab6052a3b84d8b3e80cee9ac22cf41e016cc8f13a18cc5064ca4b"]]}
```

Notice the `pubkey` value? That's the public inbox. Public inbox is an agreed-upon keypair to sign things with. Yes, you read it right, it's keypair, which means anyone has access to the public inbox's private key. Don't worry, the messages are still safe; public inbox is just a central point for inbox to land on, so everyone can post and search on the same place - messages are still secured and encrypted by the shared key only both recipient and sender have.

Here's my dummy pubkey: `xyz`. Wanna chat?

## How to use
This is very unstable and experimental. It's best to not use your "real identity."

1. Clone repository
2. `cargo run init` to initialize config file
3. `cargo run add-contact vincent xyz`
4. `cargo run chat vincent`

(You can try requesting `["REQ", "foobar", {"#p", your_pubkey}]` or `["REQ", "foobar", {"#p", xyz}]` to relays. You won't see much.)

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