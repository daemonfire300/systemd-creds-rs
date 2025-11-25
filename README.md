# Motivation

Minimalistic library as drop-in to easily discover/load secrets defined via systemd.

Idea is to also/maybe integrate this into [https://github.com/cachix/secretspec](https://github.com/cachix/secretspec) as provider.

# TODO

 1. Add oxalica overlay for devShell or checkout how to build crane devShell ✅
 2. ~~Fix incorrect use statements in the linux specific random mod.~~ (Excercise for another day, I caved in and am just using `tempfile` for now) ✅
 3. Add documentation
 4. Add tiny bit more tests
 5. Add sample systemd example
 6. Publish
 7. Try to integrate as provider for `secretspec` and submit PR
