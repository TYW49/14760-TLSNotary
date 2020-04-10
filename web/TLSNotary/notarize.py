#!/usr/bin/env python
from __future__ import print_function

from base64 import b64decode, b64encode
from hashlib import md5, sha1, sha256
from os.path import join
import binascii, hmac, os, platform,  tarfile
import Queue, random, re, shutil, signal, sys, time
import SimpleHTTPServer, socket, threading, zipfile
import string, json
from optparse import OptionParser
import sys
from os import path
import exceptions
import OpenSSL




#Globals

global_tlsver = bytearray('\x03\x02')
global_use_gzip = True
global_use_slowaes = False
global_use_paillier = False

#file system setup.
PROOF_DIR = "proofs"
data_dir = os.path.dirname(os.path.realpath(__file__))
install_dir = os.path.dirname(data_dir)
PROOF_DIR = join(data_dir, PROOF_DIR)
if not os.path.exists(PROOF_DIR):
    os.makedirs(PROOF_DIR)
# change "oracle" to "auditor"
from oracles import check_oracle, oracle, oracle_modulus
try: import wingdbstub
except: pass

global_proof_index = 0


#unpack and check validity of Python modules
def first_run_check(modname,modhash):
    if not modhash: return
    mod_dir = join(data_dir, 'python', modname)
    if not os.path.exists(mod_dir):
        print ('Extracting '+modname + '.tar.gz...')
        with open(join(data_dir, 'python', modname+'.tar.gz'), 'rb') as f: tarfile_data = f.read()
        if md5(tarfile_data).hexdigest() !=  modhash:
            raise Exception ('Wrong hash')
        os.chdir(join(data_dir, 'python'))
        tar = tarfile.open(join(data_dir, 'python', modname+'.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()

        
modules_to_load = {'rsa-3.1.4':'b6b1c80e1931d4eba8538fd5d4de1355',\
                   'pyasn1-0.1.7':'2cbd80fcd4c7b1c82180d3d76fee18c8',\
                   'slowaes':'','requests-2.3.0':'7449ffdc8ec9ac37bbcd286003c80f00'}
for x,h in modules_to_load.iteritems():
    first_run_check(x,h)
    sys.path.append(join(data_dir, 'python', x))
import rsa
import pyasn1
import requests
from pyasn1.type import univ
from pyasn1.codec.der import encoder, decoder
from slowaes import AESModeOfOperation
sys.path.append( path.dirname( path.dirname( path.abspath(__file__) ) ) )
import shared
shared.load_program_config()
shared.import_reliable_sites(join(install_dir, 'shared'))


    #override default config values
if int(shared.config.get("General","tls_11")) == 0: 		
        global_tlsver = bytearray('\x03\x01')
if int(shared.config.get("General","decrypt_with_slowaes")) == 1:
        global_use_slowaes = True
if int(shared.config.get("General","gzip_disabled")) == 1:
        global_use_gzip = False
if int(shared.config.get("General","use_paillier_scheme")) == 1:
        global_use_paillier = True




def probe_server_modulus(server):
    probe_session = shared.TLSNClientSession(server, tlsver=global_tlsver)
    print ('ssl port is: ', probe_session.ssl_port)
    tls_sock = shared.create_sock(probe_session.server_name,probe_session.ssl_port)
    try:
        probe_session.start_handshake(tls_sock)
    except Exception as e:
        print("tls 1.1 not support")
        old_tlsver = bytearray('\x03\x01')
        probe_session = shared.TLSNClientSession(server, tlsver= old_tlsver)
        tls_sock = shared.create_sock(probe_session.server_name,probe_session.ssl_port)
        probe_session.start_handshake(tls_sock)

    server_mod, server_exp = probe_session.extract_mod_and_exp()
    tls_sock.close()
    return shared.bi2ba(server_mod)


def start_generate(server_name, headers, server_modulus):
    global global_tlsver
    global global_use_gzip
    global global_use_slowaes

    print("server_name:",server_name)
    session_id = ''.join(random.choice(string.ascii_lowercase+string.digits) for x in range(10))
    tlsn_session = shared.TLSNClientSession(server_name, tlsver=global_tlsver)
    tlsn_session.server_modulus = shared.ba2int(server_modulus)
    tlsn_session.server_mod_length = shared.bi2ba(len(server_modulus))

    print ('Preparing encrypted pre-master secret')
    prepare_pms(tlsn_session, session_id)

    for i in range(10):
        try:
            print ('Performing handshake with server')
            tls_sock = shared.create_sock(tlsn_session.server_name,tlsn_session.ssl_port)
            tlsn_session.start_handshake(tls_sock)
            retval = negotiate_crippled_secrets(tlsn_session, tls_sock, session_id)
            if not retval == 'success': 
                raise shared.TLSNSSLError('Failed to negotiate secrets: '+retval)                         
            #TODO: cert checking; how to do it for browserless mode?
            #========================================================
            #before sending any data to server compare this connection's cert to the
            #one which FF already validated earlier
            #if sha256(tlsn_session.server_certificate.asn1cert).hexdigest() != certhash:
            #    raise Exception('Certificate mismatch')   
            #========================================================
            # no need: checking certs is not a Mandatory for auditee.
            # it's better to check certs!
            print ('Getting data from server')
            #
            response = make_tlsn_request(headers,tlsn_session,tls_sock)
            #prefix response with number of to-be-ignored records, 
            #note: more than 256 unexpected records will cause a failure of audit. Just as well!
            response = shared.bi2ba(tlsn_session.unexpected_server_app_data_count,fixed=1) + response
            break
        except shared.TLSNSSLError:
            shared.ssl_dump(tlsn_session)
            raise 
        except Exception as e:
            print ('Exception caught while getting data from server, retrying...', e)
            if i == 9:
                raise Exception('Notarization failed')
            continue

    # commit its own hash, get auditor's secrets
    ok, commit_hash, pms2, signature, audit_time = commit_session(tlsn_session, response, session_id)
    if not ok:
        return ok, "commit hash to auditor failed"
# no need to verify signatures
    msg = sha256(commit_hash+pms2+shared.bi2ba(tlsn_session.server_modulus)+audit_time).digest()
    oracle_ba_modulus = binascii.unhexlify(oracle_modulus)
    oracle_int_modulus = shared.ba2int(oracle_ba_modulus)
    if not shared.verify_signature(msg, signature, oracle_int_modulus):
        raise Exception("Notarization FAILED, notary signature invalid.")
    
    ok, result = decrypt_html(pms2, tlsn_session)
    if not ok:
        return ok, result
    html = result

    print ('Verified OK')

#    cert_bi = tlsn_session.server_certificate.asn1cert
#    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bi)
#    server_name = cert.get_subject().CN
#    print("tlsn_session.server_name:", server_name)

    host_line = "host: "+ server_name +"\r\n"
    readable = host_line
    b = """"""""

    b = """<meta[ ]+http-equiv=["']?content-type["']?[ ]+content=["']?text/html;[ ]*charset=([0-9-a-zA-Z]+)["']?"""
    B = re.compile(b, re.IGNORECASE)
    encodings = B.search(html)
#    print("encoding:")
#    print(encodings.group(1),len(encodings.group(1)))
    if encodings != None:
        encoding = encodings.group(1)
        if encoding.lower() == 'gb231' or encoding.lower() == 'gb2312':
            html = html.decode('gb18030')
            #        print(html)
        else:
            html = html.decode(encoding)
    else:
        html.decode('utf-8')

    print("html len:", len(html))
    html = "response:\r\n" + html + '\r\n-----PROOF BINARY DATA-----\r\n';
#    print(html)
#    readable += html.decode().encode('utf-8')
    readable += html
#    print("readable:",readable)
#    audit_data = bytearray('notarization binary data\n')
    # version of tlsnotary?
#    audit_data += '\x00\x02' #2 version bytes
    # url length
#    server_name = bytearray(server_name.encode('utf-8'))
#    audit_data += shared.bi2ba(len(server_name),fixed=2)
    # url
#    audit_data += server_name
    # chosen_cipher_suite
    audit_data = shared.bi2ba(tlsn_session.chosen_cipher_suite,fixed=2) # 2 bytes
    # client_random, server_random
    audit_data += tlsn_session.client_random + tlsn_session.server_random # 64 bytes
    # pre_master_key, two parts, each generated by auditee or auditor
    audit_data += tlsn_session.pms1 + pms2 #48 bytes
    # length of server_cert, sent by TLS Server, why fix 3 ?
    audit_data += shared.bi2ba(len(tlsn_session.server_certificate.certs),fixed=3)
    # server_certs, it's very hard to verify these babies on-chain.
    audit_data += tlsn_session.server_certificate.certs
    # tls version
    audit_data += tlsn_session.tlsver #2 bytes
    # proposed tls version in ClientHello?
#    audit_data += tlsn_session.initial_tlsver #2 bytes
    # length of response 
    audit_data += shared.bi2ba(len(response),fixed=8) #8 bytes
    # response data
    audit_data += response #note that it includes unexpected pre-request app data, 10s of kB
    # IV_after_finished used by RC4, necessory to authenticate response
    IV = tlsn_session.IV_after_finished if tlsn_session.chosen_cipher_suite in [47,53] \
                else shared.rc4_state_to_bytearray(tlsn_session.IV_after_finished)
    # length of IV, should be before IV ?
    audit_data += shared.bi2ba(len(IV),fixed=2) #2 bytes
    # IV
    audit_data += IV #16 bytes or 258 bytes for RC4.
    # length of auditor's public key, in modulus formate
    audit_data += shared.bi2ba(len(oracle_ba_modulus),fixed=2)
    # auditor's signature
    audit_data += signature #512 bytes RSA PKCS 1 v1.5 padding
    # hash that auditee commits to auditor
    audit_data += commit_hash #32 bytes sha256 hash
    # auditor's public key
    audit_data += oracle_ba_modulus
    # timestamp used to make signature unique
    audit_data += audit_time
#    audit_data = bytearray(readable.encode('utf-8')) + audit_data

    date = time_str = time.strftime('%d-%b-%Y-%H-%M-%S-', time.gmtime())
    filename = date + session_id +".pgsg"
#    print("proof file name:",filename)
    proofpath = join(PROOF_DIR,filename)
    with open(proofpath,"w") as f:
        f.write(readable)
        f.write(audit_data)

    return True, filename

#Because there is a 1 in ? chance that the encrypted PMS will contain zero bytes in its
#padding, we first try the encrypted PMS with a reliable site and see if it gets rejected.
def prepare_pms(tlsn_session, session_id):
    n = shared.bi2ba(tlsn_session.server_modulus)
    rs_choice = random.choice(shared.reliable_sites.keys())
    print("ramdom choice:", rs_choice);
    for i in range(10): #keep trying until reliable site check succeeds
        try:
            pms_session = shared.TLSNClientSession(rs_choice,shared.reliable_sites[rs_choice][0], ccs=53, tlsver=global_tlsver)
            if not pms_session: 
                raise Exception("Client session construction failed in prepare_pms")
            tls_sock = shared.create_sock(pms_session.server_name,pms_session.ssl_port)
            pms_session.start_handshake(tls_sock)
            # 1# message exchange with auditor
            reply = send_and_recv('rcr_rsr_rsname_n',
                                  pms_session.client_random+pms_session.server_random+rs_choice[:5]+n,
                                  session_id)
            if reply[0] != 'success': 
                raise Exception ('Failed to receive a reply for rcr_rsr_rsname_n:')
            if not reply[1]=='rrsapms_rhmac_rsapms':
                raise Exception ('bad reply. Expected rrsapms_rhmac_rsapms:')
            reply_data = reply[2]
            rrsapms2 = reply_data[:256]
            pms_session.p_auditor = reply_data[256:304]
            rsapms2 = reply_data[304:]
            response = pms_session.complete_handshake(tls_sock,rrsapms2)
            tls_sock.close()
            if not response:
                print ("PMS trial failed")
                continue
            #judge success/fail based on whether a properly encoded 
            #Change Cipher Spec record is returned by the server (we could
            #also check the server finished, but it isn't necessary)
            if not response.count(shared.TLSRecord(shared.chcis,f='\x01', tlsver=global_tlsver).serialized):
                print ("PMS trial failed, retrying. (",binascii.hexlify(response),")")
                continue
            tlsn_session.auditee_secret = pms_session.auditee_secret
            tlsn_session.auditee_padding_secret = pms_session.auditee_padding_secret		
            tlsn_session.enc_second_half_pms = shared.ba2int(rsapms2)			
            tlsn_session.set_enc_first_half_pms()
            tlsn_session.set_encrypted_pms()
            return
        except shared.TLSNSSLError:
            shared.ssl_dump(pms_session,fn='preparepms_ssldump')
            shared.ssl_dump(tlsn_session)
            raise
    raise Exception ('Could not prepare PMS with ', rs_choice, ' after 10 tries. Please '+\
                     'double check that you are using a valid public key modulus for this site; '+\
                     'it may have expired.')

def send_and_recv (cmd, dat, session_id, timeout=5):
    print("send data:")
    headers = {'Request':cmd,"Data":b64encode(dat),"UID":session_id}
    url = 'http://'+shared.config.get("Notary","server_name")+":"+shared.config.get("Notary","server_port")
    r = requests.head(url,headers=headers)
    r_response_headers = r.headers #case insensitive dict
    received_cmd, received_dat = (r_response_headers['response'],r_response_headers['data'])
    return ('success', received_cmd, b64decode(received_dat))
    
#reconstruct correct http headers
#for passing to TLSNotary custom ssl session
#TODO not yet implemented in browserless mode; should
#add standard headers, esp. gzip according to prefs
def parse_headers(headers):
    header_lines = headers.split('\r\n') #no new line issues; it was constructed like that
    server = header_lines[1].split(':')[1].strip()
    if not global_use_gzip:
        modified_headers = '\r\n'.join([x for x in header_lines if 'gzip' not in x])
    else:
        modified_headers = '\r\n'.join(header_lines)
    return (server,modified_headers)


def negotiate_crippled_secrets(tlsn_session, tls_sock, session_id):
    '''Negotiate with auditor in order to create valid session keys
    (except server mac is garbage as auditor withholds it)'''
    assert tlsn_session.handshake_hash_md5
    assert tlsn_session.handshake_hash_sha
    tlsn_session.set_auditee_secret()
    cs_cr_sr_hmacms_verifymd5sha = chr(tlsn_session.chosen_cipher_suite) + tlsn_session.client_random + \
        tlsn_session.server_random + tlsn_session.p_auditee[:24] +  tlsn_session.handshake_hash_md5 + \
        tlsn_session.handshake_hash_sha
    # 2# talking with auditor
#    print("cs_cr_sr_hmacms:" + cs_cr_sr_hmacms_verifymd5sha)
    reply = send_and_recv('cs_cr_sr_hmacms_verifymd5sha',cs_cr_sr_hmacms_verifymd5sha, session_id)
    print("send_and_recv")
    if reply[0] != 'success': 
        raise Exception ('Failed to receive a reply for cs_cr_sr_hmacms_verifymd5sha:')
    if not reply[1]=='hmacms_hmacek_hmacverify':
        raise Exception ('bad reply. Expected hmacms_hmacek_hmacverify but got', reply[1])
    reply_data = reply[2]
    expanded_key_len = shared.tlsn_cipher_suites[tlsn_session.chosen_cipher_suite][-1]
    if len(reply_data) != 24+expanded_key_len+12:
        raise Exception('unexpected reply length in negotiate_crippled_secrets')
    hmacms = reply_data[:24]    
    hmacek = reply_data[24:24 + expanded_key_len]
    hmacverify = reply_data[24 + expanded_key_len:24 + expanded_key_len+12] 
    tlsn_session.set_master_secret_half(half=2,provided_p_value = hmacms)
    tlsn_session.p_master_secret_auditor = hmacek
    tlsn_session.do_key_expansion()
    tlsn_session.send_client_finished(tls_sock,provided_p_value=hmacverify)
    sha_digest2,md5_digest2 = tlsn_session.set_handshake_hashes(server=True)

    # 3# talking with auditor, finally auditee get the 3 kyes necessary to talk with tls server.
    reply = send_and_recv('verify_md5sha2',md5_digest2+sha_digest2, session_id)
    if reply[0] != 'success':
        raise Exception("Failed to receive a reply for verify_md5sha2")
    if not reply[1]=='verify_hmac2':
        raise Exception("bad reply. Expected verify_hmac2:")
    if not tlsn_session.check_server_ccs_finished(provided_p_value = reply[2]):
        raise Exception ("Could not finish handshake with server successfully. Audit aborted")
    return 'success'    

def make_tlsn_request(headers,tlsn_session,tls_sock):
    '''Send TLS request including http headers and receive server response.'''
    try:
        tlsn_session.build_request(tls_sock,headers)
        response = shared.recv_socket(tls_sock) #not handshake flag means we wait on timeout
        if not response: 
            raise Exception ("Received no response to request, cannot continue audit.")
        tlsn_session.store_server_app_data_records(response)
    except shared.TLSNSSLError:
        shared.ssl_dump(tlsn_session)
        raise
    
    tls_sock.close()
    #we return the full record set, not only the response to our request
    return tlsn_session.unexpected_server_app_data_raw + response

def commit_session(tlsn_session,response, session_id):
    '''Commit the encrypted server response and other data to auditor'''
    # elegant design! commit only hash, save all reviewing work to third party
#    commit_dir = join(current_session_dir, 'commit')
#    if not os.path.exists(commit_dir): os.makedirs(commit_dir)
    #Serialization of RC4 'IV' requires concatenating the box,x,y elements of the RC4 state tuple
#    IV = shared.rc4_state_to_bytearray(tlsn_session.IV_after_finished) \
#        if tlsn_session.chosen_cipher_suite in [4,5] else tlsn_session.IV_after_finished
#    stuff_to_be_committed  = {'response':response,'IV':IV,
#                              'cs':str(tlsn_session.chosen_cipher_suite),
#                              'pms_ee':tlsn_session.pms1,'domain':tlsn_session.server_name,
#                              'certificate.der':tlsn_session.server_certificate.asn1cert, 
#                              'origtlsver':tlsn_session.initial_tlsver, 'tlsver':tlsn_session.tlsver}
#    for k,v in stuff_to_be_committed.iteritems():
#        with open(join(commit_dir,k+sf),'wb') as f: f.write(v)    
    commit_hash = sha256(response+tlsn_session.server_certificate.certs).digest()
    # 4# talking with auditor
    reply = send_and_recv('commit_hash',commit_hash, session_id)

    if reply[0] != 'success': 
        return False, 'Failed to receive a reply'
    if not reply[1]=='pms2':
        return False, 'bad reply. Expected pms2'
    return True, commit_hash, reply[2][:24], reply[2][24:536], reply[2][536:540] 


def decrypt_html(pms2, tlsn_session):
    '''Receive correct server mac key and then decrypt server response (html),
    (includes authentication of response). Submit resulting html for browser
    for display (optionally render by stripping http headers).'''
    print ("\nStarting decryption of content, may take a few seconds...")
    try:
        tlsn_session.auditor_secret = pms2[:tlsn_session.n_auditor_entropy]
        tlsn_session.set_auditor_secret()
        tlsn_session.set_master_secret_half() #without arguments sets the whole MS
        tlsn_session.do_key_expansion() #also resets encryption connection state
    except shared.TLSNSSLError:
        shared.ssl_dump(tlsn_session)
        raise
        #either using slowAES or a RC4 ciphersuite
    try:
        plaintext,bad_mac = tlsn_session.process_server_app_data_records()
#        print(plaintext)
    except shared.TLSNSSLError:
        shared.ssl_dump(tlsn_session)
        raise
    if bad_mac:
        return False, "ERROR! Audit not valid! Plaintext is not authenticated."

    # if http data chunked, dechunk
    plaintext = shared.dechunk_http(plaintext)
    if global_use_gzip:    
        plaintext = shared.gunzip_http(plaintext)
    return True, plaintext


def decrypt_html_stage2(plaintext, tlsn_session, sf):
    plaintext = shared.dechunk_http(plaintext)
    if global_use_gzip:    
        plaintext = shared.gunzip_http(plaintext)
    #write a session dump for checking even in case of success
    with open(join(current_session_dir,'session_dump'+sf),'wb') as f: f.write(tlsn_session.dump())
    commit_dir = join(current_session_dir, 'commit')
    html_path = join(commit_dir,'html-'+sf)
    with open(html_path,'wb') as f: f.write('\xef\xbb\xbf'+plaintext) #see "Byte order mark"
    if not int(shared.config.get("General","prevent_render")):
        htm=l_path = join(commit_dir,'forbrowser-'+sf+'.html')
        with open(html_path,'wb') as f:
            f.write('\r\n\r\n'.join(plaintext.split('\r\n\r\n')[1:]))
    print ("Decryption complete.")
    return ('success',html_path)

def get_headers(hpath):
    #assumed in json format
    with open(hpath,'rb') as f:
        json_headers = json.loads(f.read())
    print (json_headers)
    headers_as_string = ''
    for h in json_headers:
        print("h:"+h)
        print("content of h:"+json.dumps(json_headers[h]))
        headers_as_string += bytearray(h, 'utf-8') +':'+bytearray(json.dumps(json_headers[h]), 'utf-8')+' \r\n'
    return headers_as_string

def generate(target, header):

    import time;
    start_time = time.time();
#    if target.startswith("www."):
#        target = target[4:]
    url_raw = target
    host = url_raw.split('/')[0]
    host = host.strip()
    url = '/'.join(url_raw.split('/')[1:])
    print ('query host:', host)
    headers = "GET" + " /" + url + " HTTP/1.1" + "\r\n" + "Host: " + host + "\r\n"
    if header:
        headers = headers + header + "\r\n"
    else:
        headers += "\r\n"
    server_mod = probe_server_modulus(host)    
    ok, prooffile =  start_generate(host, headers, server_mod)
    if ok:
        print ('tls session successfully finished!')
        end_time = time.time();
        print("time used: %.1f  s" % (end_time-start_time))
        return True, prooffile
    else:
        print ('failed to complete notarization')
        return False, 'failed to complete notarization'
        
if __name__ == "__main__":

    import time;
    start_time = time.time();
    #for md5 hash, see https://pypi.python.org/pypi/<module name>/<module version>
    modules_to_load = {'rsa-3.1.4':'b6b1c80e1931d4eba8538fd5d4de1355',\
                       'pyasn1-0.1.7':'2cbd80fcd4c7b1c82180d3d76fee18c8',\
                       'slowaes':'','requests-2.3.0':'7449ffdc8ec9ac37bbcd286003c80f00'}
    for x,h in modules_to_load.items():
        first_run_check(x,h)
        sys.path.append(join(data_dir, 'python', x))

    import rsa
    import pyasn1
    import requests
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder
    from slowaes import AESModeOfOperation
    import shared
    shared.load_program_config()
    shared.import_reliable_sites(join(install_dir,'src','shared'))
    #override default config values
    if int(shared.config.get("General","tls_11")) == 0: 		
        global_tlsver = bytearray('\x03\x01')
    if int(shared.config.get("General","decrypt_with_slowaes")) == 1:
        global_use_slowaes = True
    if int(shared.config.get("General","gzip_disabled")) == 1:
        global_use_gzip = False
    if int(shared.config.get("General","use_paillier_scheme")) == 1:
        global_use_paillier = True    
    
    parser = OptionParser(usage='usage: %prog [options] url',
            description='Automated notarization of the response to an https'
            + ' request made to the url \'url\' , with https:// omitted.'
            )
    parser.add_option('-e', '--header-file', action="store", type="string", dest='header_path',
            help='if specified, the path to the file containing the HTTP headers to'
            +' be used in the request, in json format.')
    parser.add_option('-a', '--aws-query-check', action='store_true', dest='awscheck',
             help='if set, %prog will perform a check of the PageSigner AWS oracle to verify it.' 
             + 'This takes a few seconds.')
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error('Need a url to notarize')
        exit(1)
    
    url_raw = args[0]
    if options.awscheck:
        check_oracle(oracle)
    host = url_raw.split('/')[0]
    url = '/'.join(url_raw.split('/')[1:])
    print ('using host', host)
    server_mod = probe_server_modulus(host)
    headers = "GET" + " /" + url + " HTTP/1.1" + "\r\n" + "Host: " + host + "\r\n"
    x = get_headers(options.header_path) if options.header_path else ''
    headers += x + "\r\n"
    
    if start_audit(host, headers, server_mod):
        print ('successfully finished')
        end_time = time.time();
        print("time used: %.1f  s" % (end_time-start_time))
        exit(0)
    else:
        print ('failed to complete notarization')
        exit(1)
