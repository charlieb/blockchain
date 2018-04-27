from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_public_key
from cryptography.hazmat.primitives.hashes import Hash, SHA224, SHA256
from cryptography.exceptions import InvalidSignature
from base64 import b64encode, b64decode
import random

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

def address(pubkey):
    hasher = Hash(SHA224(), openssl_backend)
    hasher.update(pub_txt(pubkey))
    return b64encode(hasher.finalize())[:-2]

def sha256(data):
    hasher = Hash(SHA256(), openssl_backend)
    hasher.update(data)
    return hasher.finalize()

def sign(prvkey, message):
    return b64encode(prvkey.sign(message, ec.ECDSA(SHA224())))

def verify(pubkey, signature, message):
    try:
        pubkey.verify(b64decode(signature), message, ec.ECDSA(SHA224()))
    except InvalidSignature:
        return False
    return True

#---------------------------------------

def get_tx(bc, txid):
    return bc['txes'][txid]

def add_tx(bc, tx):
    if not verify_tx(bc, tx):
        return None
    tx['txid'] = len(bc['blocks'])
    bc['blocks'].append(tx)

    bc['txes'][tx['txid']] = tx
    bc['utxos'] -= set((inp['txid'], inp['output']) for inp in tx['inputs'])
    bc['utxos'] |= set((tx['txid'], i) for i,_ in enumerate(tx['outputs']))

    return tx['txid']

def mk_tx(inputs, pubkeys, outputs):
    return {'txid': None, 'inputs': inputs, 'pubkeys': pubkeys, 'outputs': outputs, 'signatures': []}

def to_sign(tx):
    return b''.join(str(x).encode() for x in tx['inputs'] + tx['pubkeys'] + tx['outputs'])

def to_hash(tx):
    return b''.join(str(x).encode() for x in tx['inputs'] + tx['pubkeys'] + tx['outputs'] + tx['signatures'])

def sign_tx(tx, prvkeys):
    message = to_sign(tx)
    tx['signatures'] = [sign(key, message) for key in prvkeys]

def mk_input(txid, output):
    return {'txid': txid, 'output': output}

def mk_output(address, amount):
    return {'address': address, 'amount': amount}

def verify_sig(bc, tx):
    # Verify address of each input is derived from the corresponding public key
    for inp, pubkey in zip(tx['inputs'], tx['pubkeys']):
        if address(txt_pub(pubkey)) != get_tx(bc, inp['txid'])['outputs'][inp['output']]['address']:
            print('Invalid Tx - pubkey to address mismatch\n%s'%tx)
            return False

    # Verify that each signature is correct for the tx body and the public key
    for sig, pubkey in zip(tx['signatures'], tx['pubkeys']):
        message = to_sign(tx)
        if not verify(txt_pub(pubkey), sig, message):
            print('Invalid Tx - bad signature\n%s'%tx)
            return False
    return True

def verify_tx(bc, tx):
    # Validate and sum inputs
    in_amt = 0
    spent = []
    for inp in tx['inputs']:
        utxo = (inp['txid'], inp['output'])
        if utxo not in bc['utxos'] or utxo in spent:
            print('Invalid Tx - double spend of %s:%s:\n%s'%(inp['txid'], inp['output'], tx))
            return False
        in_amt += bc['txes'][inp['txid']]['outputs'][inp['output']]['amount']
        spent.append(utxo)

    # Sum outputs
    out_amt = sum(out['amount'] for out in tx['outputs'])

    # must be enough in inputs or no inputs at all for a special tx
    if in_amt < out_amt and tx['inputs'] != []:
        print('Invalid Tx - output > input:\n%s'%tx)
        return False

    if not verify_sig(bc, tx):
        return False

    return True

# --------------------------------------

def try_add_tx(bc, tx):
    txid = add_tx(bc, tx)
    if txid is None:
        print('Add tx failed')
        return False
    else:
        print('Added tx %s'%txid)
        return True

def gen_tx(bc, addr_keys):
    keys = [new_key() for _ in range(random.randint(1,5))]
    utxos = random.sample(tuple(bc['utxos']), random.randint(1,min(len(bc['utxos']), 5)))

    outputs = [get_tx(bc, utxo[0])['outputs'][utxo[1]] for utxo in utxos]
    utxo_keys = [addr_keys[out['address']] for out in outputs]

    total = sum(out['amount'] for out in outputs)
    dividers = sorted(random.sample(range(1, total), len(keys) - 1))
    amts = [a - b for a, b in zip(dividers + [total], [0] + dividers)]
    
    tx = mk_tx([mk_input(tx, out) for tx,out in utxos],
               [pub_txt(key.public_key()) for key in utxo_keys],
               [mk_output(address(k.public_key()), amt) for k, amt in zip(keys, amts)])
    sign_tx(tx, utxo_keys)
    
    if not try_add_tx(bc, tx):
        print('gen_tx Failed')
        return False

    for k in keys: addr_keys[address(k.public_key())] = k

def sum_utxos(bc):
    return sum(get_tx(bc, utxo[0])['outputs'][utxo[1]]['amount'] for utxo in bc['utxos'])

# ---------------------------------------

def mk_block(bc, txes):
    return {
            'header': {
                'number': len(bc['blocks']),
                'prev_block_hash': 0,
                'merkle_root': 0,
                'difficulty': 1,
                'nonce': 0
                },
            'txes': [],
            'merkle_tree': []
            }

def coinbase_tx(bc, address):
    return mk_tx([], [], mk_output(address, 100000))

def mk_merkle_tree(txes):
    def mk_merkle_r(tree):
        print('mk_merkel_r: %s'%len(tree))
        if len(tree) == 1: return tree
        new_tree = []
        first = None
        for tx in tree:
            if first is None:
                first = tx
            else:
                new_tree.append([first, tx, sha256(first[-1] + tx[-1])])
                first = None
        if first is not None:
            new_tree.append([first, first, sha256(first[-1]*2)])

        return mk_merkle_r(new_tree)

    return mk_merkle_r([(tx, sha256(to_hash(tx))) for tx in txes])[0]

def hash_header(block):
    h = block['header']
    return sha256(b''.join([
        str(h['number']).encode(),
        h['prev_block_hash'],
        h['merkle_root'],
        str(h['difficulty']).encode(),
        str(h['nonce']).encode()
        ]))


def solve_block(block):
    mask = int('1'*block['header']['difficulty'], 2)
    block['header']['nonce'] = 0
    while int.from_bytes(hash_header(block), byteorder='big') & mask:
        #print('nonce: %s -> %s'%(block['header']['nonce'], int.from_bytes(hash_header(block), byteorder='big') & mask))
        block['header']['nonce'] += 1
    #print('nonce: %s -> %s'%(block['header']['nonce'], int.from_bytes(hash_header(block), byteorder='big') & mask))
    print(block['header'])

def verify_block_header(block):
    mask = int('1'*block['header']['difficulty'], 2)
    if int.from_bytes(hash_header(block), byteorder='big') & mask:
        print('Invalid Block: header hash does not meet diffulty \n%s'%block['header'])
        return False

    mroot = mk_merkle_tree(block['txes'])[-1]
    if mroot != block['header']['merkle_root']:
        print('Invalid Block: bad merkle root calculated %s, block has %s\n%s'%(mroot,
            block['header']['merkle_root'], block['header']))
        return False

    return True


# ---------------------------------------

def test():
    bc = {'blocks': [], 'txes': {}, 'utxos': set()}

    a,b,c = new_key(), new_key(), new_key()
    addr_keys = { 
            address(a.public_key()): a,
            address(b.public_key()): b,
            address(c.public_key()): c,
            }


    tx = mk_tx([], [], [mk_output(address(a.public_key()), 1000000)])
    try_add_tx(bc, tx)
    print(sum_utxos(bc))

    for _ in range(50):
        gen_tx(bc, addr_keys)
        print(sum_utxos(bc))

    mtree = mk_merkle_tree(bc['blocks'])
    print(mtree[-1])

    block = {'header': {
                'number': 0,
                'prev_block_hash': b'',
                'merkle_root': mtree[-1],
                'difficulty': 10,
                'nonce': 0
                },
                'txes': bc['blocks']
            }

    block['header']['prev_block_hash'] = b'\xda\xa2\xca\xbb\x14\x01\xf5\xbei\xb3u\xf3\xba\x0e\x81\x86\xac\x8c\xdc\xbbW\xce\xed\x8bcv6u\xd4\xc4\x90t'
    solve_block(block)
    
    block['header']['prev_block_hash'] = b'\xda\xa2\xca\xbb\x14\x01\xf5\xbej\xb3u\xf3\xba\x0e\x81\x86\xac\x8c\xdc\xbbW\xce\xed\x8bcv6u\xd4\xc4\x90t'
    solve_block(block)

    print(verify_block_header(block))




if __name__ == '__main__':
    test()
