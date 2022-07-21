import sys
import nacl.encoding
import nacl.pwhash
import nacl.signing
import nacl.hash


def derive_keys(username, password, sensitive=False):
    """
    derives private & public keys given username & password
    """
    if sensitive:
        opslimit = nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE
        memlimit = nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE
    else:
        opslimit = nacl.pwhash.argon2id.OPSLIMIT_MIN
        memlimit = nacl.pwhash.argon2id.MEMLIMIT_MIN

    username_ascii = username.encode('ascii')
    password_ascii = password.encode('ascii')
    # username is hashed and the first 16 bytes used as salt
    salt = nacl.hash.blake2b(
        username_ascii, digest_size=16, encoder=nacl.encoding.RawEncoder
    )
    print("salt:", salt)
    # derive private key directly from the password and salt
    seed = nacl.pwhash.argon2id.kdf(
        size=32,
        password=password_ascii,
        salt=salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )
    print()
    private_key = nacl.signing.SigningKey(seed)
    address = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    print("username:", username)
    print("password:", password)
    print("salt:", [x for x in salt])
    print("seed:", [x for x in seed])
    print("private key:", private_key.encode(encoder=nacl.encoding.HexEncoder))
    print("address:", address)
    return address

if __name__ == "__main__":
    func_args = sys.argv[1:]
    derive_keys(*func_args)
