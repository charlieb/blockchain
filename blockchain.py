from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_public_key
from cryptography.hazmat.primitives.hashes import Hash, SHA224
from cryptography.exceptions import InvalidSignature
from base64 import b64encode, b64decode

def new_key():
    return ec.generate_private_key(ec.SECP256K1, default_backend())

def prv_txt(key):
    txt = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return b''.join(txt.split(b'\n')[1:-2])

def pub_txt(key):
    txt = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return b''.join(txt.split(b'\n')[1:-2])[:-2]

def txt_pub(txt):
    txt = b'-----BEGIN PUBLIC KEY-----\n' + txt[:64] + b'\n' + txt[64:64+56] + b'==\n-----END PUBLIC KEY-----\n'
    return load_pem_public_key(txt, default_backend())

def address(key):
    hasher = Hash(SHA224(), openssl_backend)
    hasher.update(pub_txt(key.public_key()))
    return b64encode(hasher.finalize())[:-2]

def sign(prvkey, message):
    return b64encode(prvkey.sign(message, ec.ECDSA(SHA224())))
def verify(pubkey, signature, message):
    try:
        pubkey.verify(b64decode(signature), message, ec.ECDSA(SHA224()))
    except InvalidSignature:
        return False
    return True

#---------------------------------------

def add_tx(bc, inputs, outputs):
    txid = len(bc)
    bc.append({'txid': txid, 'inputs': inputs, 'outputs': outputs})
    return txid

def mk_input(txid, output):
    return {'txid': txid, 'output': output}

def mk_output(address, amount):
    return {'address': address, 'amount': amount}

def verify_chain(bc):
    utxos = set()
    for tx in bc:
        print(tx)
        # Validate and sum inputs
        in_amt = 0
        for inp in tx['inputs']:
            if (inp['txid'], inp['output']) not in utxos:
                print('Invalid Tx - double spend of %s:%s:\n%s'%(inp['txid'], inp['output'], tx))
                return False
            in_amt += bc[inp['txid']]['outputs'][inp['output']]['amount']

        # Sum outputs
        out_amt = sum(out['amount'] for out in tx['outputs'])

        # must be enough in inputs or no inputs at all for a special tx
        if in_amt < out_amt and tx['inputs'] != []:
            print('Invalid Tx - output > input:\n%s'%tx)
            return False
        
        # Finally update utxo database
        utxos -= set((inp['txid'], inp['output']) for inp in tx['inputs'])
        utxos |= set((tx['txid'], i) for i,_ in enumerate(tx['outputs']))
    return True

def test():
    bc = []
    add_tx(bc, [], [mk_output('one', 100)])
    add_tx(bc, [mk_input(0, 0)], [mk_output('two', 75), mk_output('three', 25)])
    add_tx(bc, [mk_input(1, 0)], [mk_output('three', 30), mk_output('four', 45)])
    add_tx(bc, [mk_input(2, 0)], [mk_output('four', 15)])
    print(bc)
    print(verify_chain(bc))

    print('---------------------------')

    key = new_key()
    print(prv_txt(key))
    print(pub_txt(key.public_key()))
    print(address(key))
    print(pub_txt(key.public_key()) == pub_txt(txt_pub(pub_txt(key.public_key()))))

    message = b'This is a test'
    sig = sign(key, message)
    print(sig)
    print(verify(key.public_key(), sig, message))


    print('---------------------------')

if __name__ == '__main__':
    test()
