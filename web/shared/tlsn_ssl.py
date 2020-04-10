from __future__ import print_function
import math, os, binascii, hmac, time, re
from hashlib import md5, sha1
from shared.tlsn_common import bigint_to_list as bigint_to_list
from shared.tlsn_common import ba2int as ba2int, bi2ba as bi2ba
from shared.tlsn_common import xor as xor, recv_socket as recv_socket
from base64 import b64encode,b64decode
from pyasn1.type import univ
from pyasn1.codec.der import decoder
from slowaes import AESModeOfOperation
from slowaes import AES
import tlsn_common
from Crypto.Cipher import AES
import OpenSSL
import cryptography

#*********** TLS CODE ***************************************
#This is a *heavily* restricted, and modified
#implementation of client-side TLS 1.0.
#Restrictions:
#-only for RSA key exchange
#-only for AES-CBC and RC4 ciphers
#-only implements one client request and one server response
# after the handshake is complete.
#-certificate is extracted but not checked using any PKI; the
# certificate check must be implemented by the calling code.
#-does not support record level compression.
#Modifications:
#The master secret and key generation is based on the
#tlsnotary algorithm as explained in TLSNotary.pdf as found
#in the documentation folder of the repo.
#This is achieved by creating a separate TLSNClientSession
#object for each of auditor and auditee, containing separate
#subsets of the required information(in particular, secrets.)
#************************************************************
#constants
md5_hash_len = 16
sha1_hash_len = 20
aes_block_size = 16
tls_ver_1_0 = '\x03\x01'
tls_ver_1_1 = '\x03\x02'
tls_versions = [tls_ver_1_0,tls_ver_1_1]
#record types
appd = '\x17' #Application Data
hs = '\x16' #Handshake
chcis = '\x14' #Change Cipher Spec
alrt = '\x15' #Al                         ert
tls_record_types = [appd,hs,chcis,alrt]
#handshake types
h_ch = '\x01' #Client Hello
h_sh = '\x02' #Server Hello
h_cert = '\x0b' #Certificate
h_shd = '\x0e' #Server Hello Done
h_cke = '\x10' #Client Key Exchange
h_fin = '\x14' #Finished
tls_handshake_types = [h_ch,h_sh,h_cert,h_shd,h_cke,h_fin]

"""The amount of key material for each ciphersuite:
AES256-CBC-SHA: mac key 20*2, encryption key 32*2, IV 16*2 == 136bytes
AES128-CBC-SHA: mac key 20*2, encryption key 16*2, IV 16*2 == 104bytes
RC4128_SHA: mac key 20*2, encryption key 16*2 == 72bytes
RC4128_MD5: mac key 16*2, encryption key 16*2 == 64 bytes"""
#tlsn_cipher_suites =  {47:['AES128',20,20,16,16,16,16],\
#                    53:['AES256',20,20,32,32,16,16],\
#                    5:['RC4SHA',20,20,16,16,0,0],\
#                    4:['RC4MD5',16,16,16,16,0,0]}
tlsn_cipher_suites =  {47:['AES128-SHA',20,20,16,16,16,16],\
                       53:['AES256-SHA',20,20,32,32,16,16],\
                       5:['RC4-SHA',20,20,16,16,0,0],\
                       4:['RC4-MD5',16,16,16,16,0,0]}

#preprocessing: add the total number of bytes in the expanded keys format
#for each cipher suite, for ease of reference
for v in tlsn_cipher_suites.values():
    v.append(sum(v[1:]))

class TLSNSSLError(Exception):
    def __init__(self, msg, data=None):
        self.msg = msg
        if data:
            self.data = binascii.hexlify(data)
        else:
            self.data = ''
            
    def __str__(self):
            return self.msg + ': ' + self.data    

def ssl_dump(session, fn=None):
    #Note that this dump write could be encapsulated
    #in the TLSNSSLError class, but the session object
    #is not always available in context.
    filename = 'ssldump' if not fn else fn
    with open(filename,'wb') as f:
        f.write(session.dump())    
    
def tls_record_decoder(d):
    '''Given a binary data stream d,
    separate it into TLS records and return
    as a list of TLSRecord objects. If no
    TLS record is found at the start of the stream,
    return False. If any additional data is found
    at the end of the final record, it is returned
    as the second part of the returned tuple.
    Note that record length is only validated here
    in the decoder.'''
    records = []
    remaining = None
    if d[0] not in tls_record_types: return False
    if d[0] == alrt:
        raise TLSNSSLError("handshake alert")
    while d:    
        rt = d[0]
        if rt not in tls_record_types:
            remaining = d
            break
        ver = d[1:3]
        if ver not in tls_versions: 
            raise TLSNSSLError("Incompatible TLS version",ver)
        l = ba2int(d[3:5])
        if len(d) < l+5:
            #can vandalise console, but not stored anywhere else, so needed.
            raise TLSNSSLError("incomplete TLS record",d)
        fragment = d[5:5+l]
        d = d[5+l:]
        records.append(TLSRecord(rt, tlsver=ver, f=fragment))        
    return (records,remaining)

def tls_record_fragment_decoder(t,d, conn=None, ignore_mac = False):
    '''Given the record type t and the data fragment d,
    we construct as many objects of that type as we can find
    in the fragment and return them as a list of Python objects.
    If conn is not None, the record fragment is assumed to be 
    encrypted and is decrypted before processing. '''
    hlpos = []
    if conn:
        if ignore_mac: #means we won't check it now, but store to be checked later
            validity, plaintext, mac = conn.dtvm(d,t,return_mac=True)
        else:
            validity,plaintext = conn.dtvm(d,t)
            if not validity:
                raise TLSNSSLError("Mac failure", plaintext[:10])
    else:
        plaintext = d

    while len(plaintext):
#        print("type:")
#        print(ord(t))
        print(ord(plaintext[0]))
        if t == hs:
            if not plaintext[0] in hs_type_map.keys():
                raise TLSNSSLError("Invalid handshake type",plaintext[0])
            constructed_obj = hs_type_map[plaintext[0]](serialized=plaintext)
        elif t == appd:
            constructed_obj = TLSAppData(serialized=plaintext)
        elif t == alrt:
            print("alert")
            constructed_obj = TLSAlert(serialized=plaintext)
        elif t == chcis:
            constructed_obj   = TLSChangeCipherSpec(serialized=plaintext)
        else:
            raise TLSNSSLError("Invalid record type",t)
        hlpos.append(constructed_obj)
        plaintext = constructed_obj.discarded
        
    if conn: 
        #Note this assumes that only ONE encrypted message
        hlpos[0].encrypted = d 
        if ignore_mac:
            hlpos[0].recorded_mac = mac
            
    return hlpos 

class TLSRecord(object):
    def __init__(self, ct, f=None, tlsver=None):
        self.content_type = ct
        self.content_version = tlsver 
        if f:
            self.fragment = f
            self.length = len(self.fragment)
            self.serialize()
    
    def serialize(self):
        check_contents = self.content_type and self.content_version and self.length and self.fragment
        if not check_contents:
            raise TLSNSSLError("Cannot serialize record, data incomplete", self.fragment)
        if not len(self.fragment) == self.length:
            raise TLSNSSLError("Incorrect record length",self.fragment)
        self.serialized =  self.content_type + self. content_version + bi2ba(self.length,fixed=2) \
            + self.fragment      

class TLSHandshake(object):
    def __init__(self,serialized=None,handshake_type=None):
        self.handshake_type = handshake_type

        if serialized:

            self.serialized = serialized
            print("handshake type:")
            print(ord(self.serialized[0]))
            if not self.handshake_type == self.serialized[0]:
                raise TLSNSSLError("Mismatched handshake type",self.handshake_type+self.serialized[0])
            if not self.handshake_type in [h_ch,h_sh,h_shd,h_cert,h_cke,h_fin]:
                raise TLSNSSLError('Unrecognized or unimplemented handshake type',self.handshake_type)
            self.handshake_record_length = ba2int(self.serialized[1:4])
            if len(self.serialized[4:]) < self.handshake_record_length:
                raise TLSNSSLError('Invalid handshake message length',self.serialized[1:4])
            self.discarded = self.serialized[4+self.handshake_record_length:]
            if self.discarded:
                print ('Info: got a discarded data when constructing',
                       'a handshake message of type: ', binascii.hexlify(self.handshake_type),
                       ' and discarded length was: ', len(self.discarded))
            #Note that we do *not* strip handshake headers for the serialized form;
            #this is a complete, valid handshake message.
            self.serialized = self.serialized[:4+self.handshake_record_length]
            
    def serialize(self):
        self.serialized = self.handshake_type+\
            bi2ba(len(self.serialized),fixed=3)+self.serialized
        

class TLSClientHello(TLSHandshake):
    def __init__(self,serialized = None,client_random = None, cipher_suites=tlsn_cipher_suites.keys(), tlsver=None):
        assert not serialized, """Not implemented instantiation of client hello 
                                   with serialization; this is a client-only
                                   TLS implementation"""
        if client_random:
            self.client_random = client_random
        else: 
            cr_time = bi2ba(int(time.time()))
            self.client_random = cr_time + os.urandom(28)
        #last byte is session id length
        self.tlsver = tlsver
        self.serialized = self.tlsver + self.client_random + '\x00' 
        self.cipher_suites = cipher_suites
        self.serialized += '\x00'+chr(2*len(self.cipher_suites))
        for a in self.cipher_suites:
            self.serialized += '\x00'+chr(a)                        
        self.serialized += '\x01\x00' #compression methods - null only 
        super(TLSClientHello,self).__init__(None, h_ch)
        super(TLSClientHello,self).serialize()
        
        
class TLSServerHello(TLSHandshake):
    def __init__(self,serialized = None,server_random = None, cipher_suite=None):
        assert serialized, """Not implemented instantiation of server hello
                             without serialization; this is a client-only
                              TLS implementation"""

        super(TLSServerHello,self).__init__(serialized,h_sh)
        self.tlsver = self.serialized[4:6]
        self.server_random = self.serialized[6:38]
        self.session_id_length = ba2int(self.serialized[38])
        if self.session_id_length != 0:
            if not self.session_id_length == 32:
                raise TLSNSSLError('Server hello contains unrecognized session id format',
                                   self.serialized[38])
            self.session_id = self.serialized[39:71]
            remainder = self.serialized[71:]
        else: 
            remainder = self.serialized[39:]
            self.session_id = None
        
        self.cipher_suite = ba2int(remainder[0:2])
        if not self.cipher_suite in tlsn_cipher_suites.keys():
            raise TLSNSSLError('Server chosen cipher suite not in TLS Notary allowed list: ',
                               str(self.cipher_suite))
        if not remainder[2:] == '\x00':
            raise TLSNSSLError('Received invalid server hello compression method',remainder[2:])
        #At end of serialized instantiation, we have defined server
        #random and cipher suite


class TLSCertificate(TLSHandshake):
    def __init__(self, serialized = None):
        assert serialized, """'Not implemented instantiation of certificate
                   without serialization; this is a client-only
                   TLS implementation"""

        super(TLSCertificate,self).__init__(serialized,h_cert)
        #TODO we are currently reading *only* the first certificate
        #in the list (tlsnotary code compares this with the browser
        #as a re-use of browser PKI). It may be necessary to do a 
        #more detailed parsing.
        #This handshake message has format: hs_cert(1), hs_msg_len(3),
        #certs_list_msg_len(3), [cert1_msg_len(3), cert1, cert_msg_len(3), cert2...]
        #so the first cert data starts at byte position 10 
        self.cert_len = ba2int(self.serialized[7:10])
        self.asn1cert = self.serialized[10:10+self.cert_len]
        #used for pagesigner: just store all the certs and certlengths
        #after the initial certs_list_msg_len field
        self.certs = self.serialized[7:]
            
            
class TLSServerHelloDone(TLSHandshake):
    def __init__(self, serialized = None):
        assert serialized, """Not implemented instantiation of server hello done
                       without serialization; this is a client-only 
                       TLS implementation"""
        super(TLSServerHelloDone,self).__init__(serialized,h_shd)
        
class TLSClientKeyExchange(TLSHandshake):
    def __init__(self, serialized = None, encryptedPMS=None):
        assert not serialized, """Not implemented instantiation of client key exchange
                        with serialization; this is a client-only
                        TLS implementation"""

        if type(encryptedPMS) == type(long()):
            self.encryptedPMS = bi2ba(encryptedPMS) #TODO zero byte bug?
        #Note that the encpms is preceded by its 2-byte length
        self.serialized = bi2ba(len(self.encryptedPMS),fixed=2) +self.encryptedPMS
        super(TLSClientKeyExchange,self).__init__(None,h_cke)
        super(TLSClientKeyExchange,self).serialize()


class TLSChangeCipherSpec(object):
    def __init__(self,serialized=None):
        if serialized:
            self.serialized = serialized
            if not self.serialized[0] == '\x01':
                raise TLSNSSLError('Invalid change cipher spec received',self.serialized[0])
            self.discarded = self.serialized[1:]
            self.serialized = self.serialized[0]
        else:
            self.serialized = '\x01'
        
class TLSFinished(TLSHandshake):
    def __init__(self,serialized=None, verify_data=None):
        if serialized: 
            super(TLSFinished,self).__init__(serialized,h_fin)
            self.validity = None
            self.verify_data = self.serialized[4:]
            
        else: 
            self.serialized = verify_data
            super(TLSFinished,self).__init__(None,h_fin)
            super(TLSFinished,self).serialize()
            
    def decrypt_verify_data(self,conn):
        self.encrypted = self.verify_data #the encrypted form is kept for later processing
        self.validity,self.verify_data = conn.dtvm(self.verify_data,hs)
            
class TLSAppData(object):
    def __init__(self, serialized, encrypted=False):
        #App Data is 'transparent' to the Record protocol layer
        #(I borrow this slighly, ahem, opaque language from the 
        #RFC Section 10). This means that there is no notion of 
        #'length of an app data message'. Nor is there any meaning
        #to the concept of 'serialization' in this context, since 
        #there is no structure. However the terminology is kept
        #the same as other record types, for consistency.
        self.serialized = serialized
        self.discarded=''
    def decrypt_app_data(self,conn):
        self.serialized = conn.dtvm(self.serialized,rec_type=appd)

class TLSAlert(object):
    def __init__(self,serialized=None):
        if serialized:
            self.serialized = serialized
            self.discarded=''
        else:
            #TODO - do we need to issue alerts?
            print ("Alert creation not implemented")
              

class TLSConnectionState(object):
    '''Note that this implementation of connection
    state uses the pre-computed expanded keys rather
    than generating the secrets within it. A corollary
    of this is that there is no need for this encapsulation
    for the unencrypted portion of the TLS connection, and
    so this object is only initiated once TLSNotary key
    expansion is performed (after negotiation with auditor).
    Mac failures should be treated as fatal in TLS, but
    for specific cases in TLSNotary, the mac check is delayed,
    hence mac failure is returned as False rather than raising
    an exception.'''
    def __init__(self, cipher_suite, expanded_keys,is_client, no_enc=False, tlsver=None):
        '''Provide the cipher suite as defined in the global
        cipher suite list.
        Currently only AES-CBC and RC4 cipher suites are
        supported.
        The format of expanded_keys must be as required
        by the specified cipher suite.
        If mac failures occur they will be flagged but
        decrypted result is still made available.'''
        
        self.tlsver = tlsver #either TLS1.0 or 1.1
        if not self.tlsver in tls_versions:
            raise TLSNSSLError("Unrecognised or invalid TLS version", self.tlsver)
        self.cipher_suite = cipher_suite
        self.end = 'client' if is_client else 'server'
        self.mac_algo = md5 if cipher_suite == 4 else sha1
        self.hash_len = md5_hash_len if self.mac_algo == md5 else sha1_hash_len
        if no_enc:
            #special case - mac only processing, we don't need IV or
            #enc keys, so 'expanded_keys' is just the mac_key
            self.mac_key = expanded_keys
        else:
            #set appropriate secrets for state
            self.client_mac_key,self.server_mac_key,self.client_enc_key,\
                self.server_enc_key,self.clientIV,self.serverIV = expanded_keys            
            self.mac_key,self.enc_key,self.IV = \
                (self.client_mac_key, self.client_enc_key, self.clientIV) \
                if self.end=='client' else \
                (self.server_mac_key,self.server_enc_key,self.serverIV)
        self.seq_no = 0
    
    def build_record_mac(self, cleartext, record_type):
        seq_no_bytes = bi2ba(self.seq_no,fixed=8)
        if not self.mac_key:
            raise TLSNSSLError("Failed to build mac; mac key is missing")
        fragment_len = bi2ba(len(cleartext),fixed=2)

        if  isinstance(cleartext, unicode):
            cleartext = bytearray(cleartext.encode('utf-8'))

        param = bytearray(seq_no_bytes) + bytearray(record_type) + bytearray(self.tlsver)+ bytearray(fragment_len) + bytearray(cleartext)
        record_mac = hmac.new(self.mac_key, param, self.mac_algo).digest()

        return record_mac
    
    def mte(self,cleartext,rec_type):
        return self.rc4_me(cleartext,rec_type) if self.cipher_suite in [4,5] \
               else self.aes_cbc_mpe(cleartext,rec_type)
    
    def dtvm(self,ciphertext,rec_type,return_mac=False):
        '''Decrypt then verify mac'''
        return self.rc4_dm(ciphertext,rec_type,return_mac) if self.cipher_suite in [4,5] \
               else self.aes_cbc_dum(ciphertext, rec_type,return_mac)
    
    def verify_mac(self, cleartext, rec_type, return_mac=False):
        received_mac = cleartext[-self.hash_len:]
        check_mac = self.build_record_mac(cleartext[:-self.hash_len], rec_type)
        self.seq_no += 1
        if return_mac:
            return (received_mac==check_mac, cleartext[:-self.hash_len],received_mac)
        else:
            return (received_mac==check_mac,cleartext[:-self.hash_len])
        
    def rc4_me(self,cleartext,rec_type):
        #mac
        if  isinstance(cleartext, unicode):
            cleartext = bytearray(cleartext.encode('utf-8'))
        cleartext = cleartext + self.build_record_mac(cleartext,rec_type)
        #encrypt
        #note: for RC4, the 'IV' is None at the start, 
        #which tells the RC4 to initialize state
        ciphertext, self.IV = rc4_crypt(bytearray(cleartext),self.enc_key,self.IV)
        self.seq_no += 1
 #       print("seq_no", seq_no,"rc4_me donw")
        return ciphertext 
    
    def rc4_dm(self,ciphertext, rec_type, return_mac=False):
        #decrypt
        plaintext, self.IV = rc4_crypt(bytearray(ciphertext),self.enc_key,self.IV)
        if return_mac:
            print ('IV inside rc4dm: ', self.IV)
        #mac check
        return self.verify_mac(plaintext, rec_type,return_mac)
        
    def aes_cbc_mpe(self,cleartext,rec_type):
        #mac
        if  isinstance(cleartext, unicode):
            cleartext = bytearray(cleartext.encode('utf-8'))
        cleartext = cleartext + self.build_record_mac(cleartext,rec_type)
        #pad
        cleartext_list,enc_list,iv_list = \
                    [map(ord,str(x)) for x in [cleartext,self.enc_key,self.IV]]        
        padded_cleartext = cleartext + get_cbc_padding(len(cleartext))
        #encrypt
        moo = AESModeOfOperation()
        mode, orig_len, ciphertext = \
        moo.encrypt( str(padded_cleartext), moo.modeOfOperation['CBC'], \
                     enc_list, len(self.enc_key), iv_list)
        if self.tlsver == tls_ver_1_0:
            self.IV = bytearray('').join(map(chr,ciphertext[-aes_block_size:])) 
        elif self.tlsver == tls_ver_1_1:
            #the per-record IV is now sent as the start of the fragment
            ciphertext = self.IV + bytearray(ciphertext)
            self.IV = os.urandom(aes_block_size) #use a new, random IV for each record
        self.seq_no += 1 
        return bytearray(ciphertext)
    
    def aes_cbc_dum(self,ciphertext,rec_type, return_mac=False):
        #decrypt

        if self.tlsver == tls_ver_1_1:
            self.IV = ciphertext[:aes_block_size]
            ciphertext = ciphertext[aes_block_size:]
        #else self.IV already stores the correct IV    
#        ciphertext_list,enc_list,iv_list = \
#            [map(ord,x) for x in [ciphertext,str(self.enc_key),str(self.IV)]]
#        moo = AESModeOfOperation()
#        key_size = tlsn_cipher_suites[self.cipher_suite][4]
#        print("aes_cbc_dum decrypt begin")
#        print("ciphertext length:", len(ciphertext))
#        time_begin = time.time()
#        decrypted = moo.decrypt(ciphertext_list,len(ciphertext),\
#            moo.modeOfOperation['CBC'],enc_list,key_size,iv_list)
        cipher = AES.new(buffer(self.enc_key), AES.MODE_CBC, buffer(self.IV))
        decrypted = cipher.decrypt(ciphertext)
#        time_done = time.time()
#        print("aes_cbc_dum decrypt done, time used:", str(time_done-time_begin))
        if self.tlsver== tls_ver_1_0:
            self.IV = ciphertext[-aes_block_size:]
        #unpad
        plaintext = cbc_unpad(decrypted)

        #mac check
        return self.verify_mac(plaintext, rec_type, return_mac)    

#dictionary to allow dynamic decoding of a handshake message in a record fragment   
hs_type_map = {h_ch:TLSClientHello,h_sh:TLSServerHello,h_cert:TLSCertificate,\
            h_cke:TLSClientKeyExchange,h_fin:TLSFinished,h_shd:TLSServerHelloDone}  

def tls_sender(sckt,msg,rec_type,conn=None, tlsver=None):
    '''Wrap a message in a TLS Record before sending
    If conn argument provided, encrypt the payload
    before sending'''
    if conn:
        msg = conn.mte(msg,rec_type)
    rec = TLSRecord(rec_type, f=msg, tlsver=tlsver)
    sckt.send(rec.serialized)
    
class TLSNClientSession(object):
    def __init__(self,server=None,port=443,ccs=None, tlsver=None):
        self.server_name = server
        self.ssl_port = port
        self.initial_tlsver = tlsver
        #current TLS version may be downgraded
        self.tlsver = tlsver
        self.n_auditee_entropy = 12
        self.n_auditor_entropy = 9
        self.auditor_secret = None
        self.auditee_secret = None
        self.auditor_padding_secret = None
        self.auditee_padding_secret = None
        self.pms1 = None #auditee's
        self.pms2 = None #auditor's
        self.enc_first_half_pms = None
        self.enc_second_half_pms = None
        self.enc_pms = None
        #client hello, server hello, certificate, server hello done,
        #client key exchange, change cipher spec, finished
        self.handshake_messages = [None] * 7
        self.handshake_hash_sha = None
        self.handshake_hash_md5 = None
        self.p_auditor = None
        self.p_auditee = None
        self.master_secret_half_auditor = None
        self.master_secret_half_auditee = None
        self.p_master_secret_auditor = None
        self.p_master_secret_auditee = None
        self.server_mac_key = None
        self.client_mac_key = None
        self.server_enc_key = None
        self.client_enc_key = None
        self.serverIV = None
        self.clientIV = None
        self.server_certificate = None
        self.server_modulus = None
        self.server_exponent = 65537
        self.server_mod_length = None

        #array of ciphertexts from each SSL record
        self.server_response_app_data=[]
        #unexpected app data is defined as that received after 
        #server finished, but before client request. This will
        #be decrypted, but not included in plaintext result.
        self.unexpected_server_app_data_count = 0
        self.unexpected_server_app_data_raw = ''
        
        #the HMAC required to construct the verify data
        #for the server Finished record
        self.verify_hmac_for_server_finished = None
        
        #for certain testing cases we want to limit the
        #choice of cipher suite to 1, otherwise we use
        #the globally defined standard 4:
        self.offered_cipher_suites = \
            {k: v for k,v in tlsn_cipher_suites.items() if k==ccs} \
            if ccs else tlsn_cipher_suites
        
        self.chosen_cipher_suite = ccs

        
    def dump(self):
        return_str='Session state dump: \n'
        for k,v in self.__dict__.iteritems():
            return_str += k + '\n'
            if type(v) == type(str()):
                return_str += 'string: len:'+str(len(v)) + '\n'
                return_str += v + '\n'
            elif type(v) == type(bytearray()):
                return_str += 'bytearray: len:'+str(len(v)) + '\n'
                return_str += binascii.hexlify(v) + '\n'
            else:
                return_str += str(v) + '\n'
        return return_str
          
    def start_handshake(self,sckt):  
        #replace tlsnotary-auditee start_tls()
        self.client_hello = TLSClientHello(cipher_suites=self.offered_cipher_suites.keys(), tlsver=self.tlsver) 
        self.handshake_messages[0]= self.client_hello.serialized
        tls_sender(sckt,self.handshake_messages[0],hs, tlsver=self.tlsver)
        #the handshake messages: server hello, certificate, server hello done
        #may be packed in arbitrary groupings into the TLS records, since
        #they are all the same record type (Handshake)            
        handshake_objects=[]
        while len(handshake_objects) < 3:
            rspns = recv_socket(sckt,True)
            records, remaining = tls_record_decoder(rspns)
            if remaining:
                raise TLSNSSLError("Server sent spurious non-TLS response", remaining[:20])
            for rec in records:
                handshake_objects.extend(tls_record_fragment_decoder(hs,rec.fragment))
        if not [h_sh,h_cert,h_shd] == [x.handshake_type for x in handshake_objects]:
               raise TLSNSSLError("Server failed to send server hello, certificate, server hello done",
                                  ''.join([x.handshake_type for x in handshake_objects]))
        self.server_hello, self.server_certificate, self.server_hello_done = handshake_objects
        
        self.handshake_messages[1:4] = [x.serialized for x in handshake_objects]

        self.client_random = self.client_hello.client_random
        self.server_random = self.server_hello.server_random
        self.chosen_cipher_suite = self.server_hello.cipher_suite

        if self.server_hello.tlsver != self.tlsver:
            if self.server_hello.tlsver =='\x03\x01' and self.tlsver == '\x03\x02':
                #server requested downgrade
                #note that this can only happen *before* a TLSConnectionState object is
                #initialised, so the tlsversion used in that object will be synchronised.
                #TODO: error checking to make sure this is the case.
                self.tlsver = bytearray('\x03\x01')
            else:
                raise TLSNSSLError("Failed to negotiate valid TLS version with server",self.server_hello.tlsver)
        
        #for 'full' sessions, we can immediately precompute everything except
        #for finished, including the handshake hashes used to calc the Finished
        if self.enc_pms:
            self.client_key_exchange = TLSClientKeyExchange(serialized=None,encryptedPMS=self.enc_pms)
            self.change_cipher_spec = TLSChangeCipherSpec()
            self.handshake_messages[4] = self.client_key_exchange.serialized
            self.handshake_messages[5] = self.change_cipher_spec.serialized
            self.set_handshake_hashes()
            
    def get_verify_data_for_finished(self,sha_verify=None,md5_verify=None,\
                                     half=1,provided_p_value=None,is_for_client=True):
        if not (sha_verify and md5_verify):
            sha_verify, md5_verify = self.handshake_hash_sha, self.handshake_hash_md5

        if not provided_p_value:
            #we calculate the verify data from the raw handshake messages
            if self.handshake_messages[:6] != filter(None,self.handshake_messages[:6]):
                #whole handshake is too big to print here; will be seen in debug dump.
                raise TLSNSSLError('Handshake data was not complete, could not calculate verify data')
            label = 'client finished' if is_for_client else 'server finished'
            seed = md5_verify + sha_verify
            ms = self.master_secret_half_auditor+self.master_secret_half_auditee
            #we don't store the verify data locally, just return it
            return tls_10_prf(label+seed,req_bytes=12,full_secret=ms)[2]

        #we calculate based on provided hmac by the other party
        return xor(provided_p_value[:12],\
                   self.get_verify_hmac(sha_verify=sha_verify,md5_verify=md5_verify,\
                                        half=half,is_for_client=is_for_client)) 
    
    def set_handshake_hashes(self,server=False):
        '''An obscure but important detail: the hashes used
        for the server Finished use the *unencrypted* client finished;
        in the current model this is automatic since the TLSFinished objects
        store the verify data unencrypted.'''
        handshake_data = bytearray('').join(self.handshake_messages[:5])
        if server:
            handshake_data += self.handshake_messages[6] #client finished
        handshake_hash_sha = sha1(handshake_data).digest()
        handshake_hash_md5 = md5(handshake_data).digest()
        if not server:
            self.handshake_hash_sha,self.handshake_hash_md5 = handshake_hash_sha,handshake_hash_md5 
        return (handshake_hash_sha,handshake_hash_md5)
    
    def send_client_finished(self, sckt, provided_p_value):
        '''Creates the client finished handshake message without
        access to the master secret, but on the P-hash data provided
        by the auditor. Then receives the server ccs and finished.'''
        verify_data = self.get_verify_data_for_finished(provided_p_value=provided_p_value,half=2)
        self.client_finished = TLSFinished(serialized=None, verify_data=verify_data)
        self.handshake_messages[6] = self.client_finished.serialized
        #Note that the three messages cannot be packed into one record; 
        #change cipher spec is *not* a handshake message
        tls_sender(sckt,self.handshake_messages[4],hs, tlsver=self.tlsver)
        tls_sender(sckt,self.handshake_messages[5],chcis, tlsver=self.tlsver) 
        #client finished must be sent encrypted       
        tls_sender(sckt,self.handshake_messages[6],hs, conn=self.client_connection_state, tlsver=self.tlsver)
        records=[]
        while len(records) < 2: #conceivably, might want an extra timeout for naughty servers!?
            rspns = recv_socket(sckt,True)
            x, remaining = tls_record_decoder(rspns)
            if remaining:
                raise TLSNSSLError("Server sent spurious non-TLS response", remaining[:20])
            records.extend(x)
        
        #this strange-looking 'filtering' approach is based on observation
        #in practice of CCS being repeated (and possible also Finished, although I don't remember)
        sccs = [x for x in records if x.content_type == chcis][0]
        self.server_ccs = tls_record_fragment_decoder(chcis,sccs.fragment)[0]
        sf = [x for x in records if x.content_type == hs][0]
        self.server_finished = tls_record_fragment_decoder(hs,sf.fragment, \
                                                    conn=self.server_connection_state, \
                                                    ignore_mac=True)[0]
        if not self.server_finished.handshake_type == h_fin:
            raise TLSNSSLError("Server failed to send Finished" , self.server_finished.handshake_type)
        #store the IV immediately after decrypting Finished; this will be needed
        #by auditor in order to replay the decryption
        self.IV_after_finished = self.server_connection_state.IV 
        
        if len(records) > 2:
            #we received extra records; are they app data? if not we have bigger problems..
            for x in records:
                if x.content_type in [chcis,hs]: continue
                if x.content_type != appd:
                    #this is too much; if it's an Alert or something, we give up.
                    raise TLSNSSLError("Received unexpected TLS record before client request.", x.content_type)
                #store any app data records, in sequence, prior to processing all app data.
                self.server_response_app_data.extend(tls_record_fragment_decoder(appd,x.fragment))
                #We have to store the raw form of these unexpected app data records, since they will
                #be needed by auditor.
                self.unexpected_server_app_data_raw += x.serialized #the full record serialization (otw bytes)
                self.unexpected_server_app_data_count += 1 #note: each appd record contains ONE appd message
        
              
    def complete_handshake(self,sckt,rsapms2):
        '''Called from prepare_pms(). For auditee only,
        who passes the second half of the encrypted
        PMS product (see TLSNotary.pdf under documentation).'''
        self.extract_mod_and_exp()
        self.set_auditee_secret()
        self.set_master_secret_half() #default values means full MS created
        self.do_key_expansion()
        self.enc_second_half_pms = ba2int(rsapms2)
        self.set_enc_first_half_pms()
        self.set_encrypted_pms()
        self.client_key_exchange = TLSClientKeyExchange(encryptedPMS=self.enc_pms)
        self.handshake_messages[4] = self.client_key_exchange.serialized
        self.change_cipher_spec = TLSChangeCipherSpec()
        self.handshake_messages[5] = self.change_cipher_spec.serialized
        self.set_handshake_hashes()
        
        client_verify_data = self.get_verify_data_for_finished(\
            sha_verify=self.handshake_hash_sha,
            md5_verify=self.handshake_hash_md5,half=1)
        
        self.client_finished = TLSFinished(verify_data=client_verify_data)
        self.handshake_messages[6] = self.client_finished.serialized
        #Note that the three messages cannot be packed into one record; 
        #change cipher spec is *not* a handshake message
        tls_sender(sckt,self.handshake_messages[4],hs, tlsver=self.tlsver)
        tls_sender(sckt,self.handshake_messages[5],chcis, tlsver=self.tlsver) 
        #client finished must be sent encrypted
        tls_sender(sckt,self.handshake_messages[6],hs, conn=self.client_connection_state, tlsver=self.tlsver)
        return recv_socket(sckt,True)
            
    def extract_mod_and_exp(self, certDER=None, sn=False):
        DER_cert_data = certDER if certDER else self.server_certificate.asn1cert
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, DER_cert_data)
#        print("cert pubkey type:", cert.get_pubkey().type())
        print("is rsapublickey:",isinstance(cert.get_pubkey().to_cryptography_key(), cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey))
        if isinstance(cert.get_pubkey().to_cryptography_key(), cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
            self.server_modulus = cert.get_pubkey().to_cryptography_key().public_numbers().n
            self.server_exponent = cert.get_pubkey().to_cryptography_key().public_numbers().e
#            print("server_mod:")
#            print(server_mod)
            n = bi2ba(self.server_modulus)
            modulus_len_int = len(n)
            self.server_mod_length = bi2ba(modulus_len_int,fixed=2)
            print("old server_mod:")
            print(self.server_modulus)
            return (self.server_modulus,self.server_exponent)  
        else:
            raise TLSNSSLError("The public key used by this server is not rsa public key")
        # rv  = decoder.decode(DER_cert_data, asn1Spec=univ.Sequence())
        # if sn:
        #     self.server_name = str(rv[0].getComponentByPosition(0).getComponentByPosition(5).getComponentByPosition(4).getComponentByPosition(0).getComponentByPosition(1))
        # bit_string = rv[0].getComponentByPosition(0).getComponentByPosition(6).getComponentByPosition(1)
        # #bit_string is a list of ints, like [01110001010101000...]
        # #convert it into into a string   '01110001010101000...'
        # string_of_bits = ''
        # for bit in bit_string:
        #     bit_as_str = str(bit)
        #     string_of_bits += bit_as_str
        # #treat every 8 chars as an int and pack the ints into a bytearray
        # ba = bytearray()
        # for i in range(0, len(string_of_bits)/8):
        #     onebyte = string_of_bits[i*8 : (i+1)*8]
        #     oneint = int(onebyte, base=2)
        #     ba.append(oneint)
        # #decoding the nested sequence
        # rv  = decoder.decode(str(ba), asn1Spec=univ.Sequence())
        # exponent = rv[0].getComponentByPosition(1)
        # modulus = rv[0].getComponentByPosition(0)
        # self.server_modulus = int(modulus)
        # self.server_exponent = int(exponent)
        # n = bi2ba(self.server_modulus)
        # modulus_len_int = len(n)
        # self.server_mod_length = bi2ba(modulus_len_int,fixed=2)
        # print("old server_mod:")
        # print(self.server_modulus)
        # return (self.server_modulus,self.server_exponent)  

    def extract_server_name(self, certDER=None, sn=False):
        DER_cert_data = certDER if certDER else self.server_certificate.asn1cert
        rv  = decoder.decode(DER_cert_data, asn1Spec=univ.Sequence())
        if sn:
            server_name = str(rv[0].getComponentByPosition(0).getComponentByPosition(5).getComponentByPosition(4).getComponentByPosition(0).getComponentByPosition(1))
        return server_name
    
    def set_encrypted_pms(self):
        if not (self.enc_first_half_pms and self.enc_second_half_pms and self.server_modulus):
            raise TLSNSSLError("Failed to set encpms")
            
        self.enc_pms =  self.enc_first_half_pms * self.enc_second_half_pms % self.server_modulus
        return self.enc_pms

    def set_enc_first_half_pms(self):
        if not (self.server_modulus and not self.enc_first_half_pms):
            raise TLSNSSLError("Failed to set enc first half pms")
        ones_length = 23            
        self.pms1 = self.initial_tlsver+self.auditee_secret + ('\x00' * (24-2-self.n_auditee_entropy))
        self.enc_first_half_pms = pow(ba2int('\x02'+('\x01'*(ones_length))+\
        self.auditee_padding_secret+'\x00'+self.pms1 +'\x00'*23 + '\x01'), self.server_exponent, self.server_modulus)
     
    def set_auditee_secret(self):
        '''Sets up the auditee's half of the preparatory
        secret material to create the master secret. Note
        that according to the RFC, the tls version prepended to the
        premaster secret must be that used in the client hello message,
        not the negotiated/downgraded version set by the server hello. 
        See variable tlsver_ch.'''
        tlsver_ch = self.initial_tlsver
        cr = self.client_random
        sr = self.server_random
        if not cr and sr:
            raise TLSNSSLError("one of client or server random not set")
        if not self.auditee_secret:
            self.auditee_secret = os.urandom(self.n_auditee_entropy)             
        if not self.auditee_padding_secret:
            self.auditee_padding_secret = os.urandom(15)
        label = 'master secret'
        seed = cr + sr
        self.pms1 = tlsver_ch+self.auditee_secret + ('\x00' * (24-2-self.n_auditee_entropy))
        self.p_auditee = tls_10_prf(label+seed,first_half = self.pms1)[0]
        #encrypted PMS has already been calculated before the audit began
        return (self.p_auditee)

    def set_enc_second_half_pms(self):
        if not self.server_modulus:
            raise TLSNSSLError("Failed to set enc second half pms")
        ones_length = 103+ba2int(self.server_mod_length)-256
        self.pms2 =  self.auditor_secret + ('\x00' * (24-self.n_auditor_entropy-1)) + '\x01'
        self.enc_second_half_pms = pow( ba2int('\x01'+('\x01'*(ones_length))+\
        self.auditor_padding_secret+ ('\x00'*25)+self.pms2), self.server_exponent, self.server_modulus )

    def set_auditor_secret(self):
        '''Sets up the auditor's half of the preparatory
        secret material to create the master secret, and
        the encrypted premaster secret.
        'secret' should be a bytearray of length n_auditor_entropy'''
        cr = self.client_random
        sr = self.server_random
        if not cr and sr:
            raise TLSNSSLError("one of client or server random not set")
        if not self.auditor_secret:
            self.auditor_secret = os.urandom(self.n_auditor_entropy)
        if not self.auditor_padding_secret:
            self.auditor_padding_secret =  os.urandom(15)
        label = 'master secret'
        seed = cr + sr
        self.pms2 =  self.auditor_secret + ('\x00' * (24-self.n_auditor_entropy-1)) + '\x01'
        self.p_auditor = tls_10_prf(label+seed,second_half = self.pms2)[1]
        return (self.p_auditor)        
    
    def set_master_secret_half(self,half=1,provided_p_value=None):
        #non provision of p value means we use the existing p
        #values to calculate the whole MS
        if not provided_p_value:
            self.master_secret_half_auditor = xor(self.p_auditee[:24],self.p_auditor[:24])
            self.master_secret_half_auditee = xor(self.p_auditee[24:],self.p_auditor[24:])
            return self.master_secret_half_auditor+self.master_secret_half_auditee
        assert half in [1,2], "Must provide half argument as 1 or 2"
        #otherwise the p value must be enough to provide one half of MS
        if not len(provided_p_value)==24:
            raise TLSNSSLError("Wrong length of P-hash value for half MS setting.", provided_p_value)
        if half == 1:
            self.master_secret_half_auditor = xor(self.p_auditor[:24],provided_p_value)
            return self.master_secret_half_auditor
        else:
            self.master_secret_half_auditee = xor(self.p_auditee[24:],provided_p_value)
            return self.master_secret_half_auditee 
    
    def get_p_value_ms(self,ctrprty,garbage=[]):
        '''Provide a list of keys that you want to 'garbageize' so as to hide
        that key from the counterparty, in the array 'garbage', each number is
        an index to that key in the cipher_suites dict        
        '''
        if not (self.server_random and self.client_random and self.chosen_cipher_suite):
            raise TLSNSSLError("server random, client random or cipher suite not set.")
        label = 'key expansion'
        seed = self.server_random + self.client_random
        expkeys_len = tlsn_cipher_suites[self.chosen_cipher_suite][-1]        
        if ctrprty == 'auditor':
            self.p_master_secret_auditor = tls_10_prf(label+seed,req_bytes=expkeys_len,first_half=self.master_secret_half_auditor)[0]
        else:
            self.p_master_secret_auditee = tls_10_prf(label+seed,req_bytes=expkeys_len,second_half=self.master_secret_half_auditee)[1]

        tmp = self.p_master_secret_auditor if ctrprty=='auditor' else self.p_master_secret_auditee
        for k in garbage:
            if k==1:
                start = 0
            else:
                start = sum(tlsn_cipher_suites[self.chosen_cipher_suite][1:k])
            end = sum(tlsn_cipher_suites[self.chosen_cipher_suite][1:k+1])
            #ugh, python strings are immutable, what's the elegant way to do this?
            tmp2 = tmp[:start]+os.urandom(end-start)+tmp[end:]
            tmp = tmp2
        return tmp    
    
    def do_key_expansion(self):
        '''A note about partial expansions:
        Often we will have sufficient information to extract particular
        keys, e.g. the client keys, but not others, e.g. the server keys.
        This should be handled by passing in garbage to fill out the relevant
        portions of the two master secret halves. TODO find a way to make this
        explicit so that querying the object will only give real keys.
        '''
        cr = self.client_random
        sr = self.server_random
        cs = self.chosen_cipher_suite
        if not cr and sr and cs:
            raise TLSNSSLError("need client and server random and cipher suite")
        label = 'key expansion'
        seed = sr + cr
        #for maximum flexibility, we will compute the sha1 or md5 hmac
        #or the full keys, based on what secrets currently exist in this object
        expkeys_len = tlsn_cipher_suites[cs][-1]
        if self.master_secret_half_auditee:
            self.p_master_secret_auditee = tls_10_prf(label+seed,req_bytes=expkeys_len,second_half=self.master_secret_half_auditee)[1]
        if self.master_secret_half_auditor:
            self.p_master_secret_auditor = tls_10_prf(label+seed,req_bytes=expkeys_len,first_half=self.master_secret_half_auditor)[0]

        if self.master_secret_half_auditee and self.master_secret_half_auditor:
            key_expansion = tls_10_prf(label+seed,req_bytes=expkeys_len,full_secret=self.master_secret_half_auditor+\
                                                                                self.master_secret_half_auditee)[2]
        elif self.p_master_secret_auditee and self.p_master_secret_auditor:
            key_expansion = xor(self.p_master_secret_auditee,self.p_master_secret_auditor)
        else:
            raise TLSNSSLError('Cannot expand keys, insufficient data')

        #we have the raw key expansion, but want the keys. Use the data
        #embedded in the cipherSuite dict to identify the boundaries.
        key_accumulator = []
        ctr=0
        for i in range(6):
            keySize = tlsn_cipher_suites[cs][i+1]
            if keySize == 0:
                key_accumulator.append(None)
            else:
                key_accumulator.append(key_expansion[ctr:ctr+keySize])
            ctr += keySize

        self.client_mac_key,self.server_mac_key,self.client_enc_key,\
            self.server_enc_key,self.clientIV,self.serverIV = key_accumulator
        #we now have sufficient information to initialise client and server
        #connection state. NOTE: Since this wipes/restarts the encryption 
        #connection state, a call to do_key_expansion automatically restarts
        #the session.
        self.client_connection_state = TLSConnectionState(cs, key_accumulator,True, False, tlsver=self.tlsver)
        self.server_connection_state = TLSConnectionState(cs, key_accumulator, False, False, tlsver=self.tlsver)
        return bytearray('').join(filter(None,key_accumulator))
    
    def get_verify_hmac(self,sha_verify=None,md5_verify=None,half=1,is_for_client=True):
        '''returns only 12 bytes of hmac'''
        label = 'client finished' if is_for_client else 'server finished'
        seed = md5_verify + sha_verify
        if half==1:
            return tls_10_prf(label+seed,req_bytes=12,first_half = self.master_secret_half_auditor)[0]
        else:
            return tls_10_prf(label+seed,req_bytes=12,second_half = self.master_secret_half_auditee)[1]              
    
    def check_server_ccs_finished(self, provided_p_value):
        #verify the verify data:     
        sha_verify,md5_verify = self.set_handshake_hashes(server=True)
        verify_data_check =  self.get_verify_data_for_finished(sha_verify=sha_verify, 
                                                md5_verify=md5_verify,
                                                provided_p_value=provided_p_value,
                                                half=2,
                                                is_for_client=False)
        if not self.server_finished.verify_data == verify_data_check:
            raise TLSNSSLError("Server Finished record verify data is not valid.", 
                               self.server_finished.verify_data+verify_data_check)
        
        return True        

    def build_request(self, sckt, cleartext):
        '''Constructs the raw bytes to send over TCP
        for a given client request. Implicitly the request
        will be less than 16kB and therefore only 1 SSL record.
        This can in principle be used more than once.'''
        self.tls_request = TLSAppData(cleartext)
        tls_sender(sckt, self.tls_request.serialized, appd, conn=self.client_connection_state, tlsver=self.tlsver)

    def store_server_app_data_records(self, response):
        #extract the ciphertext from the raw records as a list
        #for maximum flexibility in decryption
        recs, remaining = tls_record_decoder(response)
        if remaining:
            raise TLSNSSLError("Server sent spurious non-TLS data", remaining[:20])
        for rec in recs:
            self.server_response_app_data.extend(tls_record_fragment_decoder(rec.content_type,
                                                                             rec.fragment))    
                
        #what has been stored is a list of TLSAppData objects in which
        #the .serialized property is still encrypted.
    
    def get_ciphertexts(self):
        '''for use with aes-js'''   
        assert len(self.server_response_app_data),"Could not process the server response, no ciphertext found."
        if not self.chosen_cipher_suite in [47,53]: #AES-CBC
            raise TLSNSSLError("non-AES cipher suite.", bi2ba(self.chosen_cipher_suite))                    
        ciphertexts = [] #each item contains a tuple (ciphertext, encryption_key, iv)
        last_ciphertext_block = self.IV_after_finished
        for appdata in self.server_response_app_data:
            if self.tlsver == tls_ver_1_0:
                ciphertexts.append( (appdata.serialized, 
                                 self.server_connection_state.enc_key, 
                                 last_ciphertext_block) )
                last_ciphertext_block = appdata.serialized[-aes_block_size:]
            elif self.tlsver == tls_ver_1_1:
                ciphertexts.append((appdata.serialized[aes_block_size:],
                                    self.server_connection_state.enc_key,
                                    appdata.serialized[:aes_block_size]))
        return ciphertexts    
    
    def mac_check_plaintexts(self, plaintexts):
        '''for use with aes-js; given the plaintext
        output from decryption, we check the macs of the plaintext
        records. To do this a special non-encryption form of the
        ConnectionState is built which only checks macs.''' 
        mac_stripped_plaintext = ''
        #build a dummy connection state with null encryption
        #and run each plaintext through, checking the mac each time
        dummy_connection_state = TLSConnectionState(self.chosen_cipher_suite, 
                                                   self.server_mac_key, 
                                                   is_client=False, no_enc=True, tlsver=self.tlsver)
        validity, fintext = \
        dummy_connection_state.verify_mac(self.server_finished.serialized+\
                                          self.server_finished.recorded_mac,hs)
        if not validity:
            raise TLSNSSLError("Server finished mac check failed", self.server_finished.recorded_mac)
        #NB Note the verify data was verified earlier, no need to do it again here
        for i,pt in enumerate(plaintexts):
            if type(self.server_response_app_data[i]) is TLSAppData:
                rt = appd
            elif type(self.server_response_app_data[i]) is TLSAlert:
                rt = alrt
            else:
                print ("Info: Got an unexpected record type in the server response: ", 
                       type(self.server_response_app_data[i]))
               
            validity, stripped_pt = dummy_connection_state.verify_mac(pt,rt)
            if not validity:
                raise TLSNSSLError("Fatal error - invalid mac, data not authenticated!",pt[:20])
            
            #plaintext is only included if it's appdata not alerts, and if it's 
            #not part of the ignored set (the set that was delivered pre-client-request)            
            if rt==appd and i > self.unexpected_server_app_data_count-1:
                mac_stripped_plaintext += stripped_pt
            elif rt==alrt:
                print ("Info: alert received, decrypted: ", binascii.hexlify(stripped_pt))

        return mac_stripped_plaintext
    
    def mac_check_server_finished(self):
        '''For non-AES-JS processing.
        #Note server connection state has been reset after do_key_expansion
        #(which was done to correct server mac key), so state is initialised
        #correctly).'''
        validity, plaintext = \
            self.server_connection_state.dtvm(self.server_finished.encrypted,hs)
        #now sequence number and IV are correctly initialised for the app data
        return validity
        
    def process_server_app_data_records(self,is_for_auditor=False):
        '''Using the encrypted records in self.server_response_ciphertexts, 
        containing the response from
        the server to a GET or POST request (the *first* request after
        the handshake), this function will process the response one record
        at a time. Each of these records is decrypted and reassembled
        into the plaintext form of the response. The plaintext is returned
        along with the number of record mac failures (more than zero means
        the response is unauthenticated/corrupted).
        '''
        bad_record_mac = 0
        if not is_for_auditor:
            #decrypt and verify mac of server finished as normal
            if not self.mac_check_server_finished() == True:
                bad_record_mac += 1
        else:
            #auditor needs to reset the state of the server_connection_state
            #without actually processing the server finished (he doesn't have it)
            self.server_connection_state.seq_no += 1
            self.server_connection_state.IV = self.IV_after_finished
            
        if not len(self.server_response_app_data):
            raise TLSNSSLError("Could not process the server response, no ciphertext found.")
        plaintexts = ''
        for i,ciphertext in enumerate(self.server_response_app_data):
            if type(ciphertext) is TLSAppData:
                rt = appd
            elif type(ciphertext) is TLSAlert:
                rt = alrt
            else:
                raise TLSNSSLError("Server response contained unexpected record type ")
            validity, plaintext = self.server_connection_state.dtvm(ciphertext.serialized,rt)
            if not validity==True: 
                bad_record_mac += 1
            #plaintext is only included if it's appdata not alerts, and if it's 
            #not part of the ignored set (the set that was delivered pre-client-request)
            if rt== appd and i>self.unexpected_server_app_data_count-1: 
                plaintexts += plaintext
    
        return (plaintexts, bad_record_mac)    

def get_cbc_padding(data_length):
    req_padding = aes_block_size - data_length % aes_block_size
    return chr(req_padding-1) * req_padding

def cbc_unpad(pt):
    '''Given binary string pt, return
    unpadded string, raise fatal exception
    if padding format is not valid'''
    pad_len = ba2int(pt[-1])
    #verify the padding
    if not all(pad_len == x for x in map(ord,pt[-pad_len-1:-1])):
        raise TLSNSSLError("Invalid CBC padding.", pt)
    return pt[:-(pad_len+1)]    
                    
def rc4_crypt(data, key, state=None):
    """RC4 algorithm.
    Symmetric, so performs encryption and decryption
    'state', if passed, is a tuple of three values,
    box (a bytearray), x and y (integers), allowing
    restart of the algorithm from an intermediate point.
    This is necessary since stream ciphers
    in TLS use the final state of the cipher at the end
    of one record to initialise the next record (see RFC 2246)."""
    if not state:
        x = 0
        box = range(256)
        for i in range(256):
            x = (x + box[i] + key[i % len(key)]) % 256
            box[i], box[x] = box[x], box[i]
        x = y = 0
    else:
        box,x,y = state
        
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(char ^ box[(box[x] + box[y]) % 256]))
    out_state = (box, x, y)
    return (''.join(out), out_state )

def rc4_state_to_bytearray(state):
    box = state[0][:]
    x,y = state[1:3]
    box.extend([x,y])
    return bytearray('').join(map(chr,box))
    
def tls_10_prf(seed, req_bytes = 48, first_half=None,second_half=None,full_secret=None):
    '''
    Calculates all or part of the pseudo random function PRF
    as defined in the TLS 1.0 RFC 2246 Section 5. If only first_half or
    second_half are provided, then the appropriate HMAC is returned
    as the first or second element of the returned tuple respectively.
    If both are provided, the full result of PRF is provided also in
    the third element of the returned tuple.
    For maximum clarity, variable names correspond to those used in the RFC.
    Notes:
    The caller should provide one or other but not both of first_half and
    second_half - the alternative is to provide full_secret. This is because
    the algorithm for splitting into two halves as described in the RFC,
    which varies depending on whether the secret length is odd or even,
    cannot be correctly deduced from two halves.
    '''
    #sanity checks, (see choices of how to provide secrets under 'Notes' above)
    if not first_half and not second_half and not full_secret:
        raise TLSNSSLError("Error in TLSPRF: at least one half of the secret is required.")
    if (full_secret and first_half) or (full_secret and second_half):
        raise TLSNSSLError("Error in TLSPRF: both full and half secrets should not be provided.")
    if first_half and second_half:
        raise TLSNSSLError("Error in TLSPRF: please provide the secret in the parameter full_secret.")

    P_MD5 = P_SHA_1 = PRF = None

    #split the secret into two halves if necessary
    if full_secret:
        L_S = len(full_secret)
        L_S1 = L_S2 = int(math.ceil(L_S/2))
        first_half = full_secret[:L_S1]
        second_half = full_secret[L_S2:]

    #To calculate P_MD5, we need at most floor(req_bytes/md5_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of md5_hash_len(16), we will use
    #0 bytes of the final iteration, otherwise we will use 1-15 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.
    if first_half:
        A=[hmac.new(first_half,seed,md5).digest()]
        for i in range(1,int(req_bytes/md5_hash_len)+1):
            A.append(hmac.new(first_half,A[len(A)-1],md5).digest())

        md5_P_hash = ''
        for x in A:
            md5_P_hash += hmac.new(first_half,x+seed,md5).digest()

        P_MD5 = md5_P_hash[:req_bytes]

    #To calculate P_SHA_1, we need at most floor(req_bytes/sha1_hash_len) iterations
    #of 'A'. If req_bytes is a multiple of sha1_hash_len(20), we will use
    #0 bytes of the final iteration, otherwise we will use 1-19 bytes of it.
    #Note that A[0] is actually A(1) in the RFC, since A(0) in the RFC is the seed.
    if second_half:
        A=[hmac.new(second_half,seed,sha1).digest()]
        for i in range(1,int(req_bytes/sha1_hash_len)+1):
            A.append(hmac.new(second_half,A[len(A)-1],sha1).digest())

        sha1_P_hash = ''
        for x in A:
            sha1_P_hash += hmac.new(second_half,x+seed,sha1).digest()

        P_SHA_1 = sha1_P_hash[:req_bytes]

    if full_secret:
        PRF = xor(P_MD5,P_SHA_1)

    return (P_MD5, P_SHA_1, PRF)

#*********************END TLS CODE***************************************************

