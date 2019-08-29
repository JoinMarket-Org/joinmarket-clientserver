'''
python-psbt

Implementation of BIP 174 - Partially Signed Bitcoin Transaction format as defined 
here: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

Usage:

Instantiate either a Creator, Updater, Signer, Combiner, Input Finalizer or Transaction Extractor 
object depending on the responsibility of the entity

Different psbt roles have different requirements and scopes and should stick only to those. 

At this time, most functions expect data arguments to be raw bytes. Any PSBT role that has a constructor
that expects a PSBT as an argument, expects it to be in bytes

You can parse a base64 encoded PSBT and get the base64 representation of one as well.

Index arguments are expected to be ints and at this time getting/adding sighash types is expected 
to be of type int

Author: Jason Les
@heyitscheet
'''
from io import BytesIO
from base64 import b64encode, b64decode
from hashlib import sha256
from .bitcoin_lib import (
    hash160,
    read_varint, 
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    double_sha256,
    Tx,
    TxIn,
    TxOut,
    Script,
    OP_CODES
) 

# Magic bytes and separator constants for serialization
MAGIC_BYTES = b'psbt' 
HEAD_SEPARATOR = b'\xff'
DATA_SEPARATOR = b'\x00'

# Global key types
PSBT_GLOBAL_UNSIGNED_TX = b'\x00'

# Per-input key types
PSBT_IN_NON_WITNESS_UTXO = b'\x00'
PSBT_IN_WITNESS_UTXO = b'\x01'
PSBT_IN_PARTIAL_SIG = b'\x02'
PSBT_IN_SIGHASH_TYPE = b'\x03'
PSBT_IN_REDEEM_SCRIPT = b'\x04'
PSBT_IN_WITNESS_SCRIPT = b'\x05'
PSBT_IN_BIP32_DERIVATION = b'\x06'
PSBT_IN_FINAL_SCRIPTSIG = b'\x07'
PSBT_IN_FINAL_SCRIPTWITNESS = b'\x08'

# Per-output key types
PSBT_OUT_REDEEM_SCRIPT = b'\x00'
PSBT_OUT_WITNESS_SCRIPT = b'\x01'
PSBT_OUT_BIP32_DERIVATION = b'\x02'

         
class psbt:
    '''A partially signed bitcoin transaction as described in BIP 174'''
    
    def __init__(self, dict_of_maps=None):
        ''' A Partially Signed Bitcoin Transaction (psbt) object
        
        Argument dict_of_maps is a dictionary of all maps (global, inputs, outputs). 
         '''
        # Dict of map is organized by having three base keys: 'global', 'inputs', and 'outputs'
        # The value for key 'global' is a dictionary of all key-value pairs of global data
        # The value for key 'inputs' is an array of input maps. 
        # An input map is a dictionary of key-value pairs for that input map
        # The value for key 'outputs' is an array of input maps. 
        # An output map is a dictionary of key-value pairs for that input map
        self.maps = dict_of_maps
        # Ensure PSBT is valid
        self._validity_checking()
        
        
    def __repr__(self):
        # Representation of psbt (in hex):
        result = ''
        for g in sorted(self.maps['global'].keys()):
            result += '{}:{} '.format(g.hex(), self.maps['global'][g].hex())
        result += DATA_SEPARATOR.hex() + ' '
        for i in self.maps['inputs']:
            for k in sorted(i):
                result += ('{}:{} '.format(k.hex(), i[k].hex()))
            result += DATA_SEPARATOR.hex() + ' '
        for o in self.maps['outputs']:
            for k in sorted(o):
                result += '{}:{} '.format(k.hex(), o[k].hex())
            result += DATA_SEPARATOR.hex() + ' '
        return result
        
        
    def __str__(self):
        # String version of psbt (in hex) for debugging
        result = ('Globals\n===========\n')
        for g in sorted(self.maps['global'].keys()):
            result += '\t{} : {}\n'.format(g.hex(), self.maps['global'][g].hex())
        result += 'Inputs\n===========\n'  
        for i in self.maps['inputs']:
            for k in sorted(i):
                result += ('\t{} : {}\n'.format(k.hex(), i[k].hex()))
        result += 'Outputs\n===========\n'         
        for o in self.maps['outputs']:
            for k in sorted(o):
                result += '\t{} : {}\n'.format(k.hex(), o[k].hex())   
        return result
    
    
    def _validity_checking(self):
        '''A variety of tests to ensure this PSBT is valid'''
        # Check to make sure unsigned transaction is present
        if PSBT_GLOBAL_UNSIGNED_TX not in self.maps['global']:
            raise ValueError('Invalid PSBT, missing unsigned transaction')
        else:
            # Parse global unsigned tx for future checks
            tx_obj = Tx.parse(BytesIO(self.maps['global'][PSBT_GLOBAL_UNSIGNED_TX]))
        # If a scriptSig or scriptWitness is present, this is an signed transaction and is invalid
        for i in tx_obj.tx_ins:
            if len(i.script_sig.elements) >  0 or len(i.witness_program) > 1:
                raise ValueError('Invalid PSBT, transaction in global map has scriptSig or scriptWitness present, not unsigned')
        # Get number of inputs in unsigned tx and psbt maps
        global_ins_cnt = len(tx_obj.tx_ins)
        psbt_ins_cnt = len(self.maps['inputs'])
        # If unsigned tx has no inputs, invalid
        if global_ins_cnt == 0:
            raise ValueError('Invalid PSBT, unsigned transaction missing inputs')
        # If the psbt has no inputs, invalid
        elif psbt_ins_cnt == 0:
            raise ValueError('Invalid PSBT, no inputs')
        # If the counts do not match, invalid
        elif global_ins_cnt != psbt_ins_cnt:
            raise ValueError('Invalid PSBT, number of inputs in unsigned transaction and PSBT do not match')
        # Repeat for outputs
        global_outs_cnt = len(tx_obj.tx_outs)
        psbt_outs_cnt = len(self.maps['outputs'])
        if global_outs_cnt == 0:
            raise ValueError('Invalid PSBT, unsigned transaction missing outputs')
        elif psbt_outs_cnt == 0:
            raise ValueError('Invalid PSBT, no outputs')
        elif global_outs_cnt != psbt_outs_cnt:
            raise ValueError('Invalid PSBT, number of outputs in unsigned transaction and PSBT do not match')
    
    
    @staticmethod
    def serialize_map(key, value):
        '''Serializes a key+value map. Expects arguments to be of type bytes'''
        # In psbt serialization, each key and value is preceded by its length.
        return encode_varint(len(key)) + key + encode_varint(len(value)) + value  


    @staticmethod
    def parse_key(s):
        '''Reads byte stream and returns a key-value pair. 
        
        Returns None for both if key length is 0 (data separator)'''
        key_length = read_varint(s)
        if key_length == 0:
            return None, None
        key = s.read(key_length)
        val_length = read_varint(s)
        val = s.read(val_length)
        return key, val


    def serialize(self):
        '''Returns a serialization representation of the PSBT'''
        # First add magic bytes and separator
        result = MAGIC_BYTES + HEAD_SEPARATOR
        # Begin with global types. Iterate through and add all key+value pairs
        for g in sorted(self.maps['global'].keys()):
            result += self.serialize_map(key=g, value=self.maps['global'][g])
        # Add separator to mark end of globals
        result += DATA_SEPARATOR 
        # Next is input types. Iterate through list of inputs, each of which is its own dict 
        for i in self.maps['inputs']:
            for k in sorted(i):
                result += self.serialize_map(key=k, value=i[k])
            # Insert a separator to mark the end of each input
            result += DATA_SEPARATOR     
        # Finally, do output types. Iterate through list of outputs, each of which is its own dict 
        for o in self.maps['outputs']:
            for k in sorted(o):
                result += self.serialize_map(key=k, value=o[k])
            # Insert a separator to mark the end of each output
            result += DATA_SEPARATOR     
        return result
    
    
    @classmethod
    def parse(cls, s):
        '''Takes byte stream of a serialized psbt and returns a psbt object.'''
        # Check that serialization begins with the magic bytes
        if s.read(4) != MAGIC_BYTES:
            raise RuntimeError('Missing magic bytes')
        # Check that that magic bytes are followed by the separator
        if s.read(1) != HEAD_SEPARATOR :
            raise RuntimeError('Missing head separator')
        # Begin parsing global types, which is required to start with an unsigned transaction
        new_map = {
            'global' : {},
            'inputs' : [],
            'outputs' : []
            }
        expect_globals = True
        num_inputs = 0
        num_outputs = 0
        while expect_globals or num_inputs > 0 or num_outputs > 0:
            try:
                new_key, new_value = psbt.parse_key(s)
            except IndexError:
                raise RuntimeError('Unexpected serialization encountered, possible missing input/output maps')
            if expect_globals:
                # If a separator has been reached, the new_key will be None 
                # So it's time to continue on
                if new_key == None:
                    expect_globals = False
                    continue
                # Add new key-value pair to global maps
                new_map['global'][new_key] = new_value
                # If adding the unsigned_tx, parse it as a Tx object from bitcoin_lib 
                # and count the number of inputs and outputs
                if new_key == PSBT_GLOBAL_UNSIGNED_TX:
                    unsigned_tx_obj = Tx.parse(BytesIO(new_value))
                    num_inputs = len(unsigned_tx_obj.tx_ins)
                    num_outputs = len(unsigned_tx_obj.tx_outs)
                    # Set the amount of input and output maps that are expected
                    [new_map['inputs'].append({}) for _ in range(num_inputs)]
                    [new_map['outputs'].append({}) for _ in range(num_outputs)]
            # Parse each input key-value map
            elif num_inputs > 0:
                # If a separator has been reached, the new_key will be None 
                # thus marking the end of that input
                if new_key == None:
                    num_inputs -= 1
                    continue
                # curr_index is the position of the current input being parsed in the 
                # list of inputs in new_map['inputs']
                # Determined by the absolute value of the total number of inputs left 
                # to parse - the total number of inputs
                curr_index = abs(num_inputs - len(new_map['inputs']))
                new_map['inputs'][curr_index][new_key] = new_value       
            # Parse each output key-value map
            elif num_outputs > 0:
                # If a separator has been reached, the new_key will be None marking 
                # the end of that output
                if new_key == None:
                    num_outputs -= 1
                    continue
                # curr_index is the position of the current output being parsed 
                # in the list of inputs in new_map['outputs']
                # Determined by the absolute value of the total number of inputs left 
                # to parse - the total number of inputs
                curr_index = abs(num_outputs - len(new_map['outputs']))
                new_map['outputs'][curr_index][new_key] = new_value     
        return cls(dict_of_maps=new_map)
    
    
    @classmethod
    def parse_b64(cls, b64_psbt):
        return psbt.parse(BytesIO(b64decode(b64_psbt)))
            
            
    def get_as_b64(self):
        '''Returns a string Base64 encoding of the PSBT'''
        return b64encode(self.serialize()).decode("utf-8") 
    
    
class PSBT_Role:
    
    
    def __init__(self, serialized_psbt):
        self.psbt=psbt.parse(BytesIO(serialized_psbt))
        
        
    def serialized(self):
        return self.psbt.serialize()
    
    
    def make_file(self, filename=None):
        '''Returns a binary representation of psbt in the form of a 
        file with .psbt extension.
        
        Optional argument of the desired file name (without extension)
        '''
        extension = 'psbt'
        # Current idea: hex of double-sha256 of unsigned tx, first 8 characters + role name + 
        # hex of double-sha256 of entire psbt, last 8 characters 
        # Ex: 7b61d191-Signer-93d87e3c
        if filename == None:
            filename = double_sha256(self.psbt.maps['global'][PSBT_GLOBAL_UNSIGNED_TX]).hex()[:8] + \
            '-{}-'.format(self.role) + double_sha256(self.serialized()).hex()[-8:]
        with open('{}.{}'.format(filename, extension), 'wb') as f:
            f.write(self.serialized())
        return


    def _get_input_index(self, pubkey):
        '''Returns the input index (integer) of the input that can be signed by 
        the private key corresponding to the provided public key (in bytes)
        
        Note that this requires the public key be added to the PSBT with key 
        PSBT_IN_BIP32_DERIVATION
        '''
        # Iterate through all inputs and check to see if there is an index 
        # containing this public key
        for i in self.psbt.maps['inputs']:
            if (PSBT_IN_BIP32_DERIVATION+pubkey) in i:
                # Returns int
                return self.psbt.maps['inputs'].index(i)
        return None
    
    
    def _is_witness_input(self, an_input):
        '''Iterate through an input's key-value pairs and determine if it has a witness or
        non-witness UTXO'''
        for k in an_input.keys():
                if k[:1] == PSBT_IN_WITNESS_UTXO: 
                    return True
        return False
    
    
    def get_unsigned_tx(self):
        '''Returns the unsigned transaction for this psbt (in bytes)'''
        return self.psbt.maps['global'][PSBT_GLOBAL_UNSIGNED_TX]
    
    
    def get_utxo(self, input_index):
        '''Returns the UTXO at the provided input index in the PSBT'''
        return self.psbt.maps['inputs'][input_index].get(PSBT_IN_NON_WITNESS_UTXO, 
            self.psbt.maps['inputs'][input_index].get(PSBT_IN_WITNESS_UTXO))
    
    
    def b64_psbt(self):
        '''Returns a string Base64 encoding of the PSBT'''
        return b64encode(self.serialized_psbt()).decode("utf-8") 
        
        
    def get_output_redeem_script(self, output_index):
        try:
            return self.psbt.maps['outputs'][output_index][PSBT_OUT_REDEEM_SCRIPT]
        except KeyError:
            raise RuntimeError('Either this output index is out of bounds or there is no redeemScript for it')
        
        
    def get_output_witness_script(self, output_index):
        try:
            return self.psbt.maps['outputs'][output_index][PSBT_OUT_WITNESS_SCRIPT]
        except KeyError:
            raise RuntimeError('Either this output index is out of bounds or there is no witnessScript for it')
        

class Creator(PSBT_Role):
    '''The Creator creates a new psbt. It must create an unsigned transaction 
        and place it in the psbt. The Creator must create empty input fields.'''
    
    def __init__(self, inputs, outputs, tx_version=2, input_sequence=0xffffffff, locktime=0):
        '''Inputs should be a list of tuples in the form of (prev tx, prev index)
        Outputs should be a list of tuples in the form of (amount, scriptPubKey)'''
        # Specify current role as string for default file name in make_file()
        self.role = 'Creator'
        self.tx_inputs = []
        # outputs should be a list of tuples in the form of (amount, scriptPubKey), amount in satoshi
        self.tx_outputs = []
        # Initialize list of TxIn objects (Inputs)
        for i in inputs:
            self.tx_inputs.append(TxIn(prev_tx=i[0], prev_index=i[1], script_sig=b'', sequence=input_sequence))
        # Initialize list of TxOut objects (Outputs)
        for i in outputs:
            self.tx_outputs.append(TxOut(amount=i[0], script_pubkey=i[1]))
        self.tx_obj = Tx(version=tx_version, tx_ins=self.tx_inputs, tx_outs=self.tx_outputs, locktime=locktime)
        # Get a serialized version of the unsigned tx for the psbt
        serialized_tx = self.tx_obj.serialize()
        # Construct a serialized psbt manually
        new_psbt_serialized = MAGIC_BYTES + HEAD_SEPARATOR + psbt.serialize_map(key=PSBT_GLOBAL_UNSIGNED_TX, \
        value=serialized_tx)  + DATA_SEPARATOR + (DATA_SEPARATOR*len(self.tx_inputs)) + \
        (DATA_SEPARATOR*len(self.tx_outputs))
        # Create the psbt object using the serialized psbt
        self.psbt = psbt.parse(BytesIO(new_psbt_serialized))

    
    def get_utxo(self, input_index):
        raise RuntimeError('Function out of scope for this role')
    
    
    def _get_input_index(self, pubkey):
        raise RuntimeError('Function out of scope for this role')
    
    
    def _is_witness_input(self, an_input):
        raise RuntimeError('Function out of scope for this role')
    
    
    def get_output_redeem_script(self, output_index):
        raise RuntimeError('Function out of scope for this role')
        
        
    def get_output_witness_script(self, output_index):
        raise RuntimeError('Function out of scope for this role')


class Updater(PSBT_Role):
    '''The Updater must only accept a PSBT. The Updater adds information to the PSBT that it has access to.'''
    
    def __init__(self, serialized_psbt):
        super().__init__(serialized_psbt)
        # Specify current role as string for default file name in make_file()
        self.role = 'Updater'
           
           
    def add_nonwitness_utxo(self, input_index, utxo):
        '''Add a non-witness UTXO to it's corresponding input
        
        input_index - (int) index of the input being updated
        utxo - raw bytes of utxo being added
        '''
        self.psbt.maps['inputs'][input_index][PSBT_IN_NON_WITNESS_UTXO] = utxo
    
    
    def add_witness_utxo(self, input_index, utxo, utxo_index):
        '''Add a non-witness UTXO to it's corresponding input
        
        input_index - (int) index of the input being updated
        utxo - raw bytes of utxo being added
        '''
        tx_obj = Tx.parse(BytesIO(utxo))
        value = tx_obj.tx_outs[utxo_index].serialize()
        self.psbt.maps['inputs'][input_index][PSBT_IN_WITNESS_UTXO] = value
        
    def add_witness_utxo_from_txout(self, input_index, amount, scriptPubKey):
        value = TxOut(amount, scriptPubKey).serialize()
        self.psbt.maps['inputs'][input_index][PSBT_IN_WITNESS_UTXO] = value

    def add_sighash_type(self, input_index, sighash):
        '''Adds a sighash type to an input
        
        Signatures for this input must use the sighash type
        
        input_index - (int) index of the input being updated
        sighash - int of the sighash type
        '''
        # Converts into to 32-bit unsigned LE integer of the sighash type
        self.psbt.maps['inputs'][input_index][PSBT_IN_SIGHASH_TYPE] = \
        int_to_little_endian(n=sighash, length=4)
    
    
    def add_input_redeem_script(self, input_index, script):
        '''Adds a redeem script to an input
        
        input_index - (int) index of the input being updated
        script 0 raw bytes of witness script being added
        '''
        self.psbt.maps['inputs'][input_index][PSBT_IN_REDEEM_SCRIPT] = script

        
    def add_input_witness_script(self, input_index, script):
        '''Adds a witness script to an input
        
        input_index - (int) index of the input being updated
        script 0 raw bytes of witness script being added
        '''
        self.psbt.maps['inputs'][input_index][PSBT_IN_WITNESS_SCRIPT] = script  
        
        
    def add_input_pubkey(self, input_index, pubkey, masterkey_fingerprint, bip32_path):
        '''Adds a public key and the master key fingerprint + bip32 path it maps to 
        an input. 
        
        The bip32 derivation path is represented as 32-bit unsigned integer indexes 
        concatenated with each other.
        
        input_index - (int) index of the input being updated
        All other arguments should be raw bytes'''
        self.psbt.maps['inputs'][input_index][PSBT_IN_BIP32_DERIVATION+pubkey] = masterkey_fingerprint + bip32_path  
    
    
    def add_output_redeem_script(self, output_index, script):
        '''Adds a redeem script to an output
        
        output_index - (int) index of the output being updated
        script 0 raw bytes of witness script being added
        '''
        self.psbt.maps['outputs'][output_index][PSBT_OUT_REDEEM_SCRIPT] = script

        
    def add_output_witness_script(self, output_index, script):
        '''Adds a witness script to an output
        
        output_index - (int) index of the output being updated
        script = raw bytes of witness script being added
        '''
        self.psbt.maps['outputs'][output_index][PSBT_OUT_WITNESS_SCRIPT] = script  
        
        
    def add_output_pubkey(self, output_index, pubkey, masterkey_fingerprint, bip32_path):
        '''Adds a public key and the master key fingerprint + bip32 path it maps to to 
        an output. 
        
        The bip32 derivation path is represented as 32-bit unsigned integer indexes 
        concatenated with each other.
        
        input_index - (int) index of the output being updated
        All other arguments should be raw bytes'''
        self.psbt.maps['outputs'][output_index][PSBT_OUT_BIP32_DERIVATION+pubkey] \
        = masterkey_fingerprint + bip32_path   
    

class Signer(PSBT_Role):
    '''The Signer must only accept a PSBT. The Signer must only use the UTXOs provided in 
    the PSBT to produce signatures for inputs. '''
    def __init__(self, serialized_psbt):
        # Specify current role as string for default file name in make_file()
        self.role = 'Signer'
        self.psbt=psbt.parse(BytesIO(serialized_psbt))
        # Iterate through all of the inputs for this PSBT and check to make sure a 
        # UTXO has been filled in
        for i in range(len(self.psbt.maps['inputs'])):
            if self.get_utxo(i) is None:
                raise ValueError('Not all the UTXOs have been filled in for this PSBTs inputs')
            
            
    def get_path(self, pubkey):
        '''Returns the masterkey fingerprint concatenated with the bip32 path of the 
        provided public key (in bytes)'''
        return self.psbt.maps['inputs'][PSBT_IN_BIP32_DERIVATION+pubkey]
    
    
    def get_sighash_type(self, input_index):
        '''Returns the int of the sighash type for the input at input_index'''
        found = self.psbt.maps['inputs'][input_index].get(PSBT_IN_SIGHASH_TYPE)
        if found is None:
            raise RuntimeWarning('No sighash key for input at index {}'.format(input_index))
            return None
        else:
            return little_endian_to_int(found)
        
        
    def check_sighash(self, input_index, sighash):
        '''Takes the bytes representation of a sighash type and checks if it matches the
        sighash for the input at int input_index
        '''
        return sighash == self.get_sighash_type(input_index)
    
    
    def add_partial_signature(self, new_sig, compressed_sec, input_index=None):
        '''Adds signature to input of PSBT. Signature and public key should be of type bytes
        
        If the public key has been added to an input in the PSBT, the input index will be found
        '''
        # TODO: Add more ways to find an input that matches the provided public key
        # If an input index is not specified in arguments, find it based on matching public key
        if input_index == None:
            input_index = self._get_input_index(compressed_sec)
        # Note that the below assumes that the sighash type is only the last byte of sig. 
        # This may be problematic
        # Note: Assumes inputs in psbt and indexed the same as in unsigned tx
        # TODO: Check on this
        this_sighash = little_endian_to_int(new_sig[-1:])
        if input_index is not None:
            # Check to make sure signature's sighash type correctly matches the type specified 
            # for this input
            if not self.check_sighash(input_index=input_index, sighash=this_sighash):
                raise ValueError('Sighash type {} on this signature does not match specified \
                sighash type {} for this input'.format(little_endian_to_int(this_sighash), 
                                                       self.get_sighash_type(input_index)))     
            curr_input = self.psbt.maps['inputs'][input_index]
            # Verify that if UTXO for witness or non-witness is present, it matches TXID of global unsigned tx
            if PSBT_IN_NON_WITNESS_UTXO in curr_input:
                global_txid = Tx.parse(BytesIO(self.psbt.maps['global'][PSBT_GLOBAL_UNSIGNED_TX])).tx_ins[input_index].prev_tx 
                utxo_txid = double_sha256(curr_input[PSBT_IN_NON_WITNESS_UTXO])[::-1]
                # Verify that txids match
                if utxo_txid != global_txid:
                    raise RuntimeError('UTXO of this input does not match with that in global unsigned tx') 
            # If witness UTXO, verify that hashes match there
            elif PSBT_IN_WITNESS_UTXO in curr_input:
                # TODO: Do more testing for native segwit utxos
                # Get the hash of witness program in scriptPubKey of the witness UTXO
                scriptPubKey = Script.parse(curr_input[PSBT_IN_WITNESS_UTXO][9:]) 
                # Determine script type of scriptPubKey
                if scriptPubKey.type() == 'p2wpkh':
                    # If scriptPubKey is p2wpkh, keyhash is last element
                    keyhash = scriptPubKey.elements[-1]
                    # Check to make sure hash160 of compressed pubkey of signature matches that in UTXO scriptPubKey
                    if hash160(compressed_sec) != keyhash:
                        raise RuntimeError('Hash of compressed pubkey in partial signature does not match \
                        that of hash in witness UTXOs scriptPubKey')     
                elif scriptPubKey.type() == 'p2wsh':
                    # If scriptPubKey is p2wsh, scripthash is last element
                    scripthash = scriptPubKey.elements[-1]
                    # Check to make sure single SHA256 of witnessScript (if provided) matches that in UTXO scriptPubKey
                    if PSBT_IN_WITNESS_SCRIPT in curr_input:
                        if sha256(curr_input[PSBT_IN_WITNESS_SCRIPT]).digest != scripthash:
                                raise RuntimeError('Hash of witnessScript does not match that of hash in witness UTXOs \
                                scriptPubKey')            
                # Otherwise check if P2SH (including P2SH wrapped segwit)   
                elif scriptPubKey.type() == 'p2sh':
                    # If scriptPubKey is p2sh, scripthash is 2nd to last element
                    scripthash = scriptPubKey.elements[-2]
                    # If redeemScript is present for this input, its hash160 should match scripthash in scriptPubKey
                    if PSBT_IN_REDEEM_SCRIPT in curr_input:
                        if hash160(curr_input[PSBT_IN_REDEEM_SCRIPT]) != scripthash:
                            raise RuntimeError('Hash of redeemScript does not match that of hash in witness UTXOs \
                            scriptPubKey')
                        # If witness script is also present, verify the hash of this input's witnessScript matches the hash
                        # inside the redeemScript
                        if PSBT_IN_WITNESS_SCRIPT in curr_input:
                            # Parse redeemScript to get hash of witnessScript inside it
                            redeemScript = Script.parse(curr_input[PSBT_IN_REDEEM_SCRIPT])
                            # The last item in a P2SH-segwit redeemScript is the hash of the witness program
                            redeem_wit_hash = redeemScript.elements[-1]
                            if redeemScript.type() == 'p2wsh':
                                if sha256(curr_input[PSBT_IN_WITNESS_SCRIPT]).digest() != redeem_wit_hash:
                                    raise RuntimeError('Hash of witnessScript does not match that of hash in redeemScript')                
            # If this point has been reached without any errors, add partial signature
            self.psbt.maps['inputs'][input_index][PSBT_IN_PARTIAL_SIG+compressed_sec] = new_sig      
        # If input_index is still None, partial signature cannot be added
        else:
            raise RuntimeError('If the public key for this signature has not been added to the PSBT \
            and an input_index has not been provided then partial signature cannot be added')
        return
        
    
class Combiner(PSBT_Role):
    '''Takes any number of serialized PSBTs and combines them. All additional PSBTs 
    will be checked against the initializing (first) PSBT's 0x00 global unsigned transaction 
    key-value'''
    
    def __init__(self, *args):
        # Specify current role as string for default file name in make_file()
        self.role = 'Combiner'
        # Initialize the new PSBT using the first one passed as an argument as the base
        self.psbt=psbt.parse(BytesIO(args[0]))
        # Count number of inputs in the base PSBT. All future PSBTs will be checked 
        # to make sure the count matches
        self.base_num_inputs = len(self.psbt.maps['inputs'])
        # Same for outputs
        self.base_num_outputs = len(self.psbt.maps['outputs'])
        # Run combine function on the rest of the PSBTs passed as arguments
        [self.combine_serialized(a) for a in args]
    
    
    def matching_psbt(self, check_psbt):
        return self.psbt.maps['global'][PSBT_GLOBAL_UNSIGNED_TX] == \
        check_psbt.maps['global'][PSBT_GLOBAL_UNSIGNED_TX]

                  
    def combine_serialized(self, *args):
        '''Takes one or more PSBTs in bytes and combines them into one PSBT which contains 
        all of the key-value pairs from each of the PSBTs and removes any duplicate key-value pairs.'''
        for p in args:
            curr = psbt.parse(BytesIO(p))
            # First check to make sure all PSBTs being passed are the same PSBT, 
            # identified by the global transaction value
            if self.matching_psbt(curr) is True:    
                # Combine the global keys 
                self.psbt.maps['global'].update(curr.maps['global'])
                # Go through each input for this PSBT and combine it with its matching input 
                # in the base PSBT
                # Note this assumes that every PSBT has inputs indexed in the same order they 
                # appear in the unsigned tx
                # TODO: Review and revise this process if necessary
                curr_num_inputs = len(curr.maps['inputs'])
                # Check to make sure the number of inputs on the current PSBT matches up with 
                # the base PSBT
                if curr_num_inputs != self.base_num_inputs:
                    raise ValueError('Number of input maps in the following PSBT does not match that of base: \
                    {}'.format(curr.get_as_b64))
                for i in range(curr_num_inputs):
                    self.psbt.maps['inputs'][i].update(curr.maps['inputs'][i]) 
                # Go through each output for this current PSBT and combine it with its matching 
                # output in the base PSBT
                curr_num_outputs = len(curr.maps['outputs'])
                # Check to make sure the number of inputs on the current PSBT matches up with 
                # the base PSBT
                if curr_num_outputs != self.base_num_outputs:
                    raise ValueError('Number of output maps in the following PSBT does not match that \
                    of base: {}'.format(curr.get_as_b64))
                for o in range(len(curr.maps['outputs'])):
                    self.psbt.maps['outputs'][o].update(curr.maps['outputs'][o])        
            else:
                # If the current PSBT being passed does not match global tx of base PSBT, skip it 
                # and raise warning
                raise RuntimeWarning('A PSBT being combined does not have matching a unsigned \
                transaction value and was not added')
        # Return that combination was successful
        return True
        
        
        
class Input_Finalizer(PSBT_Role):
    '''Input_Finalizer accepts a single PSBT, validates and finalizes the inputs'''
    
    def __init__(self, serialized_psbt):
        # Specify current role as string for default file name in make_file()
        self.role = 'Input_Finalizer'
        self.psbt=psbt.parse(BytesIO(serialized_psbt))
        # For each input, check to see if it has enough data to pass validation
        # If it does, construct the scriptSig and scriptWitness and place them in map
        # All other data except the UTXO and unknown fields in the input key-value map
        # should be cleared
        # Iterate through each input
        for i in self.psbt.maps['inputs']:
            # Step 1: check to make sure at least 1 signature is present
            if not self._check_for_sig(i):
                continue
            # Step 2: check to make sure a sighash type is specified
            if PSBT_IN_SIGHASH_TYPE not in i.keys():
                continue
            # Step 3: check if witness or non-witness utxo
            if self._is_witness_input(i):
                # Currently assumes a multisig witness input,
                # or a p2sh-p2wpkh input. TODO: handle all cases
                if PSBT_IN_REDEEM_SCRIPT in i.keys() and PSBT_IN_WITNESS_SCRIPT not in i.keys():
                    i[PSBT_IN_FINAL_SCRIPTSIG] = encode_varint(len(i[PSBT_IN_REDEEM_SCRIPT])) + i[PSBT_IN_REDEEM_SCRIPT]
                    # insert the added signature; since we are assuming p2sh-p2wpkh, there
                    # must be only 1.
                    found = 0
                    for k in i.keys():
                        if k[:1] == PSBT_IN_PARTIAL_SIG:
                            found += 1
                            pub = k[1:]
                            sig = i[k]
                    if found != 1:
                        print("FAILED to find 1 signature in input, cannot be finalized.")
                        continue
                    i[PSBT_IN_FINAL_SCRIPTWITNESS] = Script([sig, pub]).serialize()
                    continue
                # Step 3a: If witness, check to make sure witnessScript is present
                if PSBT_IN_WITNESS_SCRIPT not in i.keys():
                    continue
                # Step 3b: Then create scriptWitness
                new_scriptWitness = self._make_multisig_script(inp=i, witness=True)
                # Complete scriptWitness by adding the number of witness items to the beginning 
                new_scriptWitness.insert(0, len(new_scriptWitness))
                # Add key-type PSBT_IN_FINAL_SCRIPTWITNESS to PSBT with the finalized scriptWitness as its value     
                i[PSBT_IN_FINAL_SCRIPTWITNESS] = Script(new_scriptWitness).serialize()
                # Add key-type PSBT_IN_FINAL_SCRIPTSIG to PSBT with the finalized scriptSig as its value
                # For witness inputs, this is the redeemScript preceded by its length
                i[PSBT_IN_FINAL_SCRIPTSIG] = encode_varint(len(i[PSBT_IN_REDEEM_SCRIPT])) + i[PSBT_IN_REDEEM_SCRIPT]
            # Step 4: If not witness, check for a lone redeemScript
            elif PSBT_IN_REDEEM_SCRIPT in i.keys():
                # Step 4a: since redeem script is present, create the scriptSig for this input
                # Add key-type PSBT_IN_FINAL_SCRIPTSIG to PSBT with the finalized scriptSig as its value       
                i[PSBT_IN_FINAL_SCRIPTSIG] = Script(self._make_multisig_script(i)).serialize()
            # Final case is this input is P2PKH, so create its scriptSig
            # TODO: Test case for this
            else: 
                found_sec = False
                for k in i.keys():
                    if k[:1] == PSBT_IN_PARTIAL_SIG:
                        if found_sec:
                            # More than one partial sig should not be found without a redeemScript or
                            # witnessScript. Must be missing a script
                            continue
                            sec = k[1:]
                            sig = i[k]
                            found_sec = True
                # Take the SEC and sig and construct the scriptSig
                # Add key-type PSBT_IN_FINAL_SCRIPTSIG to PSBT with the finalized scriptSig as its value 
                i[PSBT_IN_FINAL_SCRIPTSIG] = Script([sig, sec]).serialize()
            # If this point is reached, all neccessary data must be present
            # Clear all data except UTXO and unknown fields
            self._clear_keyvalues(i)
    
    
    def _clear_keyvalues(self, inp):
        '''Clears all of an input's key-value fields besides the UTXO, finalized scriptSig, 
        scriptWitness and any unknown fields'''
        to_delete = []
        for k in inp.keys():
            if k[:1] in [PSBT_IN_PARTIAL_SIG, PSBT_IN_SIGHASH_TYPE, PSBT_IN_REDEEM_SCRIPT, 
                         PSBT_IN_WITNESS_SCRIPT, PSBT_IN_BIP32_DERIVATION]:
                to_delete.append(k)
        for k in to_delete:
            del inp[k]
        return 
                
                
    def _make_multisig_script(self, inp, witness=False):
        '''Takes a PSBT input and constructs a finalized scriptSig or scriptWitness for that input'''
        new_script = []
        # Start with OP_0
        new_script.append(0)
        # Create redeemScript object and get number of sigs required for the redeemScript
        if witness:
            redeemScript = Script.parse(inp[PSBT_IN_WITNESS_SCRIPT])
        else:
            redeemScript = Script.parse(inp[PSBT_IN_REDEEM_SCRIPT])
        # Make sure this is a multisig redeemScript by checking for OP_CODE 174, OP_CHECKMULTISIG
        if redeemScript.elements[-1] != 174 :
            raise ValueError('Present redeemScript is not multisig and not understood')
        # Assumes this is multisig redeemScript which has m and n # of sigs in usual position
        sigs_required = int(OP_CODES[redeemScript.elements[0]][3:])
        total_sigs = int(OP_CODES[redeemScript.elements[-2]][3:])
        found_sigs = 0
        # Iterate through redeemScript. Go through its public keys and check if there is a
        # partial sig present matching that public key.
        for pk_i in range(total_sigs):
            if found_sigs >= sigs_required :
                # If the required number of sigs have been found, stop searching
                break
            # Look for partial signature matching a redeemScript public key in our
            # current input's partial signatures
            try_key = PSBT_IN_PARTIAL_SIG + redeemScript.sec_pubkey(pk_i)
            if try_key in inp:
                # If key is found, add its signature to scriptSig and increment counter
                new_script.append(inp[try_key])
                found_sigs += 1
        # Check if a sufficient number of signatures are present to satisfy redeemScript
        if found_sigs < sigs_required:
            raise ValueError("Insufficient sigs present to satisfy this PSBT input's redeemScript")
        # Complete the scriptSig by adding the redeemScript to the end
        new_script.append(redeemScript.serialize())
        return new_script
    
    
    def _check_for_sig(self, an_input):
        '''Iterate through an input's key-value pairs and determine if it has a parial sig present'''
        for k in an_input.keys():
                if k[:1] == PSBT_IN_PARTIAL_SIG: 
                    return True
        return False
    
                 
class Transaction_Extractor(PSBT_Role):
    '''Transaction Extractor accepts a single PSBT and determines if the necessary finalized
    scriptSig and scriptWitness are present and constructors a network serialized transaction'''
    
    def __init__(self, serialized_psbt):
        # Specify current role as string for default file name in make_file()
        self.role = 'Transaction_Extractor'
        self.psbt=psbt.parse(BytesIO(serialized_psbt))
        # Take the finalized scriptSig and scriptWitness data and complete the unsigned tx
        self.tx_obj = Tx.parse(BytesIO(self.psbt.maps['global'][PSBT_GLOBAL_UNSIGNED_TX]))
        # Iterate through psbt input key-value fields and input their finalized data into 
        # the transaction. Note this assumes PSBT inputs are ordered the same as they are
        # in the unsigned TX
        # TODO: Reconsider that assumption
        for i in range(len(self.psbt.maps['inputs'])):
            curr_input = self.psbt.maps['inputs'][i]
            if self._is_witness_input(curr_input):
                try:
                    # Insert final scriptWitness as witness program for this input
                    self.tx_obj.tx_ins[i].witness_program = curr_input[PSBT_IN_FINAL_SCRIPTWITNESS]
                except KeyError:
                    print("No scriptWitness was present, this is correct for *p2wpkh inputs")
                # If a final scriptSig is present, must be P2SH-wrapped segwit so scriptSig is required
                if PSBT_IN_FINAL_SCRIPTSIG in curr_input:
                    self.tx_obj.tx_ins[i].script_sig = Script.parse(curr_input[PSBT_IN_FINAL_SCRIPTSIG])
                    self.tx_obj.tx_ins[i].witness_program = curr_input[PSBT_IN_FINAL_SCRIPTWITNESS]
            # Else, this is a non-witness input
            else:
                try:
                    # Insert final scriptSig into input
                    self.tx_obj.tx_ins[i].script_sig = Script.parse(curr_input[PSBT_IN_FINAL_SCRIPTSIG])
                except KeyError:
                    # If not a witness input, final scriptSig should be present
                    raise ValueError('PSBT input is missing finalized scriptSig')  
            # TODO: Verify each input                        
        
        
    def serialized(self):
        return self.tx_obj.serialize()
    

    def input_index_in_ustx(self, inp):
        '''Take a PSBT input and determine its index in the unsigned tx'''
        raise NotImplementedError
        
    
