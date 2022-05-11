# d4ft3

This project is my third start on a text and file transfer program, after
[d4ft](https://github.com/dacid44/d4ft) and [d4ft2](https://github.com/dacid44/d4ft2). I'm starting
over with the knowledge and hindsight I've gained since starting work on `d4ft2`, and more prior
planning.

[Docs](https://dacid44.github.io/d4ft3)

## Overall changes from d4ft2
- No (or minimal) `extra-options`
- Files described in a list, rather than a tree. Not a ton of reason to do a tree
- Replace plaintext socket with encrypted socket object rather than modifying it
- Maybe internal mutability/`RefCell` for the socket objects? (holding the encryption object)
- Better project structure (two separate crates for cli and library)

## Milestones
- [x] Two unencrypted sockets talking to each other (print to console)
- [x] Proper text transfer
  - [x] encryption setup
  - [x] transfer mode setup
- [x] Above steps/features, using CLI
- [x] Two encrypted sockets talking to each other
  - [x] with fixed key
  - [x] with password-generated key
  - [x] with `Poly1305`
- [ ] Sending file list
- [ ] Sending one file
  - [ ] no checks
  - [ ] checks
- [ ] Sending multiple files

## Future goals
- GUI app
- Android app
