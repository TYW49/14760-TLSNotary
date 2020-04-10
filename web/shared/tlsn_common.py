from __future__ import print_function
from ConfigParser import SafeConfigParser
from SocketServer import ThreadingMixIn
from struct import pack
import os, binascii, itertools, re, random
import threading, BaseHTTPServer
import select, time, socket
from subprocess import check_output
#General utility objects used by both auditor and auditee.

config = SafeConfigParser()
config_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),'tlsnotary.ini')

#required_options = {'Notary':['notary_server','notary_port']}
required_options = {}
reliable_sites = {}        


def verify_signature(msg, signature, modulus):
    '''RSA verification is sig^e mod n, drop the padding and get the last 32 bytes
    Args: msg as sha256 digest, signature as bytearray, modulus as (big) int
    '''
    sig = ba2int(signature)
    exponent = 65537
    result = pow(sig,exponent,modulus)
    padded_hash = bi2ba(result,fixed=512) #4096 bit key
    unpadded_hash = padded_hash[512-32:]
    if msg==unpadded_hash:
	return True
    else:
	return False

def load_program_config():    

    loadedFiles = config.read([config_location])
    #detailed sanity checking :
    #did the file exist?
    if len(loadedFiles) != 1:
        raise Exception("Could not find config file: "+config_location)
    #check for sections
    for s in required_options:
        if s not in config.sections():
            raise Exception("Config file does not contain the required section: "+s)
    #then check for specific options
    for k,v in required_options.iteritems():
        for o in v:
            if o not in config.options(k):
                raise Exception("Config file does not contain the required option: "+o)


def import_reliable_sites(d):
    '''Read in the site names and ssl ports from the config file,
    and then read in the corresponding pubkeys in browser hex format from
    the file pubkeys.txt in directory d. Then combine this data into the reliable_sites global dict'''
    sites = [x.strip() for x in config.get('SSL','reliable_sites').split(',')]
    ports = [int(x.strip()) for x in config.get('SSL','reliable_sites_ssl_ports').split(',')]
    assert len(sites) == len(ports), "Error, tlsnotary.ini file contains a mismatch between reliable sites and ports"    
    #import hardcoded pubkeys
    with open(os.path.join(d,'pubkeys.txt'),'rb') as f: plines = f.readlines()
    raw_pubkeys= []
    pubkeys = []
    while len(plines):
        next_raw_pubkey = list(itertools.takewhile(lambda x: x.startswith('#') != True,plines))
        k = len(next_raw_pubkey)
        plines = plines[k+1:]
        if k > 0 : raw_pubkeys.append(''.join(next_raw_pubkey))
    for rp in raw_pubkeys: 
        pubkeys.append(re.sub(r'\s+','',rp))
    for i,site in enumerate(sites):
        reliable_sites[site] = [ports[i]]
        reliable_sites[site].append(pubkeys[i])

def check_complete_records(d):
    '''Given a response d from a server,
    we want to know if its contents represents
    a complete set of records, however many.'''
    l = ba2int(d[3:5])
    if len(d)< l+5: return False
    elif len(d)==l+5: return True
    else: return check_complete_records(d[l+5:])

def create_sock(server,prt):
    returned_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    returned_sock.settimeout(int(config.get("General","tcp_socket_timeout")))
    returned_sock.connect((server, prt))
    return returned_sock
    
def recv_socket(sckt,is_handshake=False):
    last_time_data_was_seen_from_server = 0
    data_from_server_seen = False
    databuffer=''
    while True:
        rlist, wlist, xlist = select.select((sckt,), (), (sckt,), 1)
        if len(rlist) == len(xlist) == 0: #timeout
            #TODO dont rely on a fixed timeout 
            delta = int(time.time()) - last_time_data_was_seen_from_server
            if not data_from_server_seen: continue
            if  delta < int(config.get("General","server_response_timeout")): continue
            return databuffer #we timed out on the socket read 
        if len(xlist) > 0:
            print ('Socket exceptional condition. Terminating connection')
            return ''
        if len(rlist) == 0:
            print ('Python internal socket error: rlist should not be empty. Please investigate. Terminating connection')
            return ''
        for rsckt in rlist:
            data = rsckt.recv(1024*32)
            if not data:
                if not databuffer:
                    raise Exception ("Server closed the socket and sent no data")
                else:
                    return databuffer
            data_from_server_seen = True  
            databuffer += data
            if is_handshake: 
                if check_complete_records(databuffer): return databuffer #else, just continue loop
            last_time_data_was_seen_from_server = int(time.time())
    
def bi2ba(bigint,fixed=None):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    if fixed:
        padding = fixed - len(m_bytes)
        if padding > 0: m_bytes = [0]*padding + m_bytes
    return bytearray(m_bytes)


def xor(a,b):
    return bytearray([ord(a) ^ ord(b) for a,b in zip(a,b)])

def bigint_to_list(bigint):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    return m_bytes

#convert bytearray into int
def ba2int(byte_array):
    return int(str(byte_array).encode('hex'), 16)
    
    
def gunzip_http(http_data):
    import gzip
    import StringIO
    http_header = http_data[:http_data.find('\r\n\r\n')+len('\r\n\r\n')]
    #\s* below means any amount of whitespaces
    if re.search(r'content-encoding:\s*deflate', http_header, re.IGNORECASE):
        #TODO manually resend the request with compression disabled
        raise Exception('Please set gzip_disabled = 1 in tlsnotary.ini and rerun the audit')
    if not re.search(r'content-encoding:\s*gzip', http_header, re.IGNORECASE):
        return http_data #nothing to gunzip
    http_body = http_data[len(http_header):]
    ungzipped = http_header
    gzipped = StringIO.StringIO(http_body)
    f = gzip.GzipFile(fileobj=gzipped, mode="rb")
    ungzipped += f.read()    
    return ungzipped
    
       
def dechunk_http(http_data):
    '''Dechunk only if http_data is chunked otherwise return http_data unmodified'''
    http_header = http_data[:http_data.find('\r\n\r\n')+len('\r\n\r\n')]
    #\s* below means any amount of whitespaces
    if not re.search(r'transfer-encoding:\s*chunked', http_header, re.IGNORECASE):
        return http_data #nothing to dechunk
    http_body = http_data[len(http_header):]

    dechunked = http_header
    cur_offset = 0
    chunk_len = -1 #initialize with a non-zero value
    while True:  
        new_offset = http_body[cur_offset:].find('\r\n')
        if new_offset==-1:  #pre-caution against endless looping
            #pinterest.com is known to not send the last 0 chunk when HTTP gzip is disabled
            return dechunked
        chunk_len_hex  = http_body[cur_offset:cur_offset+new_offset]
        chunk_len = int(chunk_len_hex, 16)
        if chunk_len ==0: break #for properly-formed html we should break here
        cur_offset += new_offset+len('\r\n')   
        dechunked += http_body[cur_offset:cur_offset+chunk_len]
        cur_offset += chunk_len+len('\r\n')    
    return dechunked


if __name__ == "__main__":
    hex_modulus = "D7D0CB0EB013153009D9D9279B1EC14E67C4FFB4ABAA36A06C35CAFF85A0C1997C03D60FEB5FC98DC48EBB004FC77221CB1F076211EF9DA80D2FAFE0111ECFD1F93AB63BBF60529DA273C1EAB827DEC95D1D4CB9692A9491FB8202305DC85D03060A16761D3F3720EC923201C1966A5C93B9491DB40F830CC366892C5C0DF8CAE5558E06B7B8469D2723E89BA52B0A174943A107E3E52AFF2DBB9F681701EEB6318C7D076268D4B0E7A992CB6564C4DF630DCB7455D7D806108A206153D64040CDB547EF871DE8250CA47D1170B4D7FAD9DF664F2A0EF3C4E7AF74346B1E9CCEF1F1A63D691F4F4D1EC0C9AF88C17180B24ED279E2AE0D9B6D6EC201F58AC7E37EA1B0D047A22ED62C6639805480C80E7E95D74D1549245F15A28E1C4E766D4C83CBB734415679D05A04E7F9FF2604A410B398E8D7568A17964A6DB6BCADB47CE6D1280CBEFCFF54ED0C46C9A2754E149BC347B6C13E7F883C1037BB90F32429B76CD9F388089E98E5CD05A7114696E640F540C6D77D20E0811724AAC1288745C78E2A61CDE1BC9ABB7F7F2AE4BAFB96680BC5231973E47F88C185F62F3E13C8A2E152BB9C1EC4E5564CCB56CE4AC0BC1E91A5587FCDE260AB55E58141D61093E715EFBDECFCBA0EF657C78E152337AD81760E0BFBDFC988C3E2F423440C2A58361AA4020FD17DE4027AB23A34742232AF618F30C516A32C2746F5ECB17FEC2B"
    ba_modulus = binascii.unhexlify(hex_modulus)
    int_modulus = ba2int(ba_modulus)
    bigint = int_modulus
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, int(b) )
        bigint //= 256
    print("int array: ",m_bytes)

    ba2 = bi2ba(int_modulus)
    ba4 = binascii.hexlify(ba2)
    print("ba4:", ba4)
    print("ba4 equal hex_modulus?", ba4 == ba_modulus)

    ba3 = bytearray('').join(map(chr, m_bytes))
    print("bytes equal? ", ba_modulus == ba3)
