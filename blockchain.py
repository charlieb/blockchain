from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.hashes import Hash, SHA224, SHA256
from cryptography.exceptions import InvalidSignature
from base64 import b64encode, b64decode
import random
from copy import deepcopy
import json

def new_key():
    return ec.generate_private_key(ec.SECP256K1, default_backend())

def prv_txt(key):
    txt = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return b''.join(txt.split(b'\n')[1:-2])

def txt_prv(txt):
    txt = b'-----BEGIN PRIVATE KEY-----\n' + txt[:64] + b'\n' + txt[64:] + b'\n-----END PRIVATE KEY-----\n'
    return load_pem_private_key(txt, None, default_backend())

def pub_txt(key):
    txt = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return b''.join(txt.split(b'\n')[1:-2])

def txt_pub(txt):
    txt = b'-----BEGIN PUBLIC KEY-----\n' + txt[:64] + b'\n' + txt[64:] + b'\n-----END PUBLIC KEY-----\n'
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

def get_tx(state, txid):
    return state['txes'][txid]

def update_state_tx(state, tx):
    state['txes'][tx['txid']] = tx
    state['utxos'] -= set((inp['txid'], inp['output']) for inp in tx['inputs'])
    state['utxos'] |= set((tx['txid'], i) for i,_ in enumerate(tx['outputs']))

def add_tx(state, block, tx):
    if not verify_tx(state, tx):
        return None
    tx['txid'] = txid(tx)
    block['txes'].append(tx)

    update_state_tx(state, tx)
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

def verify_sig(state, tx):
    # Verify address of each input is derived from the corresponding public key
    for inp, pubkey in zip(tx['inputs'], tx['pubkeys']):
        if address(txt_pub(pubkey)) != get_tx(state, inp['txid'])['outputs'][inp['output']]['address']:
            print('Invalid Tx - pubkey to address mismatch\n%s'%tx)
            return False

    # Verify that each signature is correct for the tx body and the public key
    for sig, pubkey in zip(tx['signatures'], tx['pubkeys']):
        message = to_sign(tx)
        if not verify(txt_pub(pubkey), sig, message):
            print('Invalid Tx - bad signature\n%s'%tx)
            return False
    return True

def verify_tx(state, tx):
    # Validate and sum inputs
    in_amt = 0
    spent = []
    for inp in tx['inputs']:
        utxo = (inp['txid'], inp['output'])
        if utxo not in state['utxos'] or utxo in spent:
            print('Invalid Tx - double spend of %s:%s:\n%s'%(inp['txid'], inp['output'], tx))
            return False
        in_amt += state['txes'][inp['txid']]['outputs'][inp['output']]['amount']
        spent.append(utxo)

    # ensure all outputs a positive and # Sum outputs
    out_amt = 0
    for out in tx['outputs']:
        if out['amount'] < 0:
            print('Invalid Tx - output amount less than zero:\n%s'%tx)
            return False
        out_amt += out['amount']

    # must be enough in inputs or no inputs at all for a special tx
    if in_amt < out_amt and tx['inputs'] != []:
        print('Invalid Tx - output > input:\n%s'%tx)
        return False

    if not verify_sig(state, tx):
        return False

    return True

def txid(tx):
    return b64encode(
            sha256(b''.join(str(x).encode() for x in tx['inputs'] +
                                                     tx['pubkeys'] +
                                                     tx['outputs'] +
                                                     tx['signatures'])))

# --------------------------------------

def try_add_tx(state, block, tx):
    txid = add_tx(state, block, tx)
    if txid is None:
        print('Add tx failed')
        return False
    else:
        print('Added tx %s'%txid)
        return True

def gen_tx(state, block, addr_keys):
    keys = [new_key() for _ in range(random.randint(1,5))]
    utxos = random.sample(tuple(state['utxos']), random.randint(1,min(len(state['utxos']), 5)))

    outputs = [get_tx(state, utxo[0])['outputs'][utxo[1]] for utxo in utxos]
    utxo_keys = [txt_prv(addr_keys[out['address']]) for out in outputs]

    total = sum(out['amount'] for out in outputs)
    try:
        dividers = sorted(random.sample(range(1, total), len(keys) - 1))
    except ValueError:
        print('Value Error on sample: keys %s'%keys)
        raise

    amts = [a - b for a, b in zip(dividers + [total], [0] + dividers)]
    
    tx = mk_tx([mk_input(tx, out) for tx,out in utxos],
               [pub_txt(key.public_key()) for key in utxo_keys],
               [mk_output(address(k.public_key()), amt) for k, amt in zip(keys, amts)])
    sign_tx(tx, utxo_keys)
    
    if not try_add_tx(state, block, tx):
        print('gen_tx Failed')
        return False

    for k in keys: addr_keys[address(k.public_key())] = prv_txt(k)

def sum_utxos(bc):
    return sum(get_tx(bc, utxo[0])['outputs'][utxo[1]]['amount'] for utxo in bc['utxos'])

# ---------------------------------------

def mk_block(bc):
    return {
            'header': {
                'number': len(bc),
                'prev_block_hash': 0,
                'merkle_root': 0,
                'difficulty': 1,
                'nonce': 0
                },
            'txes': [],
            }

def coinbase_tx(state, block, address):
    if block['txes'] != []: return None
    return add_tx(state, block, mk_tx([], [], [mk_output(address, 100000)]))

def mk_merkle_tree(txes):
    def mk_merkle_r(tree):
        #print('mk_merkel_r: %s'%len(tree))
        if len(tree) == 1: return tree
        new_tree = []
        first = None
        for tx in tree:
            if first is None:
                first = tx
            else:
                new_tree.append([first, tx, b64encode(sha256(first[-1] + tx[-1]))])
                first = None
        if first is not None:
            new_tree.append([first, first, b64encode(sha256(first[-1]*2))])

        return mk_merkle_r(new_tree)

    return mk_merkle_r([(tx, b64encode(sha256(to_hash(tx)))) for tx in txes])[0]

def hash_header_raw_bytes(block):
    h = block['header']
    return sha256(b''.join([
        str(h['number']).encode(),
        h['prev_block_hash'],
        h['merkle_root'],
        str(h['difficulty']).encode(),
        str(h['nonce']).encode()
        ]))

def hash_header(block):
    return b64encode(hash_header_raw_bytes(block))


def solve_block(block):
    mask = int('1'*block['header']['difficulty'], 2)
    block['header']['nonce'] = 0
    while int.from_bytes(hash_header_raw_bytes(block), byteorder='big') & mask:
        #print('nonce: %s -> %s'%(block['header']['nonce'], int.from_bytes(hash_header(block), byteorder='big') & mask))
        block['header']['nonce'] += 1
    #print('nonce: %s -> %s'%(block['header']['nonce'], int.from_bytes(hash_header(block), byteorder='big') & mask))
    print(block['header'])

def verify_block_header(block):
    mask = int('1'*block['header']['difficulty'], 2)
    if int.from_bytes(hash_header_raw_bytes(block), byteorder='big') & mask:
        print('Invalid Block: header hash does not meet diffulty \n%s'%block['header'])
        return False

    mroot = mk_merkle_tree(block['txes'])[-1]
    if mroot != block['header']['merkle_root']:
        print('Invalid Block: bad merkle root calculated %s, block has %s\n%s'%(mroot,
            block['header']['merkle_root'], block['header']))
        return False

    return True

def verify_block(state, bc, block):
    new_state = deepcopy(state)

    if not verify_block_header(block): return False
    if block['header']['number'] > 0 and block['header']['prev_block_hash'] != hash_header(bc[block['header']['number']-1]):
        print('Invalid Block: prev_block_hash incorrect\n%s'%block['header'])
        return False

    for tx in block['txes']:
        if not verify_tx(new_state, tx):
            print('Invalid Block: bad tx\n%s'%block['header'])
            return False
        if txid(tx) != tx['txid']:
            print('Invalid Block: bad txid %s\n%s'%(tx['txid'], block['header']))
            return False
        update_state_tx(new_state, tx)

    return True, new_state

# ---------------------------------------

def default(obj):
    if isinstance(obj, bytes):
        return obj.decode('utf-8') #{'__bytes__': str(obj)}

def write_from_bytes(f, data):
    json.dump(data, f, default=default, indent=4)

def object_hook(obj):
    # the only base data type we care about
    if isinstance(obj, str): return obj.encode('utf-8')

    if isinstance(obj, dict):
        for k,v in obj.items():
            obj[k] = object_hook(obj[k])
    elif isinstance(obj, list):
        obj = [object_hook(o) for o in obj]

    return obj

def read_to_bytes(f):
    return json.load(f, object_hook=object_hook)

# ---------------------------------------

import filecmp
class BadBlockException(Exception): pass

def new_random_block(state, bc, addr_keys):
    new_block = mk_block(bc)
    new_state = deepcopy(state)
    new_addr_keys = deepcopy(addr_keys)

    new_block['header']['number'] = len(bc)
    new_block['header']['prev_block_hash'] = hash_header(bc[-1]) if new_block['header']['number'] > 0 else b''
    new_block['header']['difficulty'] = 10

    # use new_state to keep generated txes correct
    a = new_key()
    tx = coinbase_tx(new_state, new_block, address(a.public_key()))

    new_addr_keys[address(a.public_key())] = prv_txt(a)
    for _ in range(50):
        gen_tx(new_state, new_block, new_addr_keys)

    mtree = mk_merkle_tree(new_block['txes'])

    new_block['header']['merkle_root'] = mtree[-1]
    solve_block(new_block)

    # use state to update it for real
    ok, new_state = verify_block(state, bc, new_block)
    if not ok: raise BadBlockException
    return new_state, bc + [new_block], new_addr_keys

def read_addr_keys(f):
    return {addr.encode('utf-8'): key for addr, key in read_to_bytes(f).items()}
def write_addr_keys(f, keys):
    write_from_bytes(f, {addr.decode('utf-8'): key for addr, key in keys.items()})

def test():
    state = {'txes': {}, 'utxos': set()}
    bc = []
    addr_keys = {}

    try:
        with open('test_block.json', 'r') as f: bc = read_to_bytes(f)
        with open('addr_keys', 'r') as f: addr_keys = read_addr_keys(f)
    except FileNotFoundError:
        pass
    
    state, bc, addr_keys = new_random_block(state, bc, addr_keys)

    with open('test_block.json', 'w') as f: write_from_bytes(f, bc)
    with open('test_block.json', 'r') as f: new_bc = read_to_bytes(f)
    print(new_bc[0]['header'])
    with open('test_block2.json', 'w') as f: write_from_bytes(f, new_bc)

    print(filecmp.cmp('test_block.json', 'test_block2.json'))

    with open('addr_keys', 'w') as f: write_addr_keys(f, addr_keys)

if __name__ == '__main__':
    test()
