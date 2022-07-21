- `generate_address.html` and `generate_address.py` are two implementations of a key derivation process, using a username as seed & a password to derive a private key.  
- Both use libsodium, with the `generate_address.py` interfacing via PyNaCl (https://pypi.org/project/PyNaCl/) and `generate_address.html` using libsodium.js (https://github.com/jedisct1/libsodium.js/)
    - `sodium.js` in this repo is directly copied from https://github.com/jedisct1/libsodium.js/blob/master/dist/browsers-sumo/sodium.js