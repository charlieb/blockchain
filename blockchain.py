
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

if __name__ == '__main__':
    test()
