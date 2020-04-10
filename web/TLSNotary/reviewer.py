#!/usr/bin/env python
from __future__ import print_function

from base64 import b64decode, b64encode
from hashlib import md5, sha1, sha256
from os.path import join
from oracles import oracle_modulus
import binascii, hmac, os, platform,  tarfile
import random, re, sys, time, zipfile
import OpenSSL
import cryptography

#file system setup.
data_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(data_dir))
install_dir = os.path.dirname(os.path.dirname(data_dir))

global_tlsver = bytearray('\x03\x02')
global_use_gzip = True
global_use_slowaes = False
global_use_paillier = False
oracle_ba_modulus = None
oracle_int_modulus = None

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
import shared

oracle_ba_modulus = binascii.unhexlify(oracle_modulus)
oracle_int_modulus = shared.ba2int(oracle_ba_modulus)
shared.load_program_config()
if int(shared.config.get("General","gzip_disabled")) == 1:
    global_use_gzip = False



def extract_audit_data(audit_filename):
    audit_data = {}
    with open(audit_filename,'rb') as f:
        host_line = f.readline()
        if not host_line.startswith("host: "):
            return False, "Invalid file format host"
        print("hostline:",host_line,"end");
        audit_data['host'] = host_line[6:].strip(r'\r\n').replace("\r\n", "")
        print("host:",audit_data['host'],"end");
        html = ''
        response_prefix = f.readline()
        if response_prefix != 'response:\r\n':
            return False, "Invalid file format response"
        response_appendix = '-----PROOF BINARY DATA-----\r\n'
        line = f.readline()
        while line != response_appendix and line != '':
            html += line
            line = f.readline()
            
        if line != response_appendix:
            return False, "Invalid file format response_adppendix"

        print("html len:",len(html))
        html = html[:-2]
        print("html len:",len(html))
        audit_data['html'] = html
#        header = f.readline()
#        if header != 'notarization binary data\n':
#            return False, "Invalid file format binary data header"
#        version = f.read(2)
#        if version != '\x00\x02':
#            raise Exception("Incompatible file version")
#        audit_data['url_length']= shared.ba2int(f.read(2))
#        audit_data['url'] = f.read(audit_data['url_length'])
        audit_data['cipher_suite'] = shared.ba2int(f.read(2))
        audit_data['client_random'] = f.read(32)
        audit_data['server_random'] = f.read(32)
        audit_data['pms1'] = f.read(24)
        audit_data['pms2'] = f.read(24)
        audit_data['certs_len'] = shared.ba2int(f.read(3))
        audit_data['certs'] = f.read(audit_data['certs_len'])
        audit_data['tlsver'] = f.read(2)
        response_len = shared.ba2int(f.read(8))
        audit_data['response'] = f.read(response_len)
        IV_len = shared.ba2int(f.read(2))
        if IV_len not in [258,16]:
#            print ("IV length was: ", IV_len)
            raise False, "Wrong IV format in audit file"
        audit_data['IV'] = f.read(IV_len)
        audit_data['oracle_modulus_len'] = f.read(2) #TODO can check this
        audit_data['signature'] = f.read(len(oracle_ba_modulus))
        audit_data['commit_hash'] = f.read(32)
        audit_data['oracle_modulus'] = f.read(512)
        if audit_data['oracle_modulus'] != oracle_ba_modulus:
#            print ("file mod was: ", binascii.hexlify(audit_data['oracle_modulus']))
#            print ("actual was: ", binascii.hexlify(oracle_ba_modulus))
            raise False,"Unrecognized oracle"
        audit_data['audit_time'] = f.read(4)
    return True, audit_data

def convert(filename):
    html = "";
    response_appendix = '-----PROOF BINARY DATA-----\r\n'
    hex_mode = False;
    with open(filename,'rb') as f:
        line = f.readline()
        while line != '':
            if not hex_mode:
                if line == response_appendix:
                    hex_mode = True
                newline = line.replace("\r\n", "<br>")
                newnewline = newline.replace("\n", "<br>")
#                print("line:", newnewline)
                html += newnewline
            else:
                hex_line = binascii.b2a_hex(line)
                html += hex_line
            line = f.readline()

#    print("html:",html)
    return True, html


def review(audit_filename):
    review_result = ""
    try:
        ok, result = extract_audit_data(audit_filename)
        if not ok:
#        print(result)
            review_result += "Valid proof file format: False\n"
            return False, review_result, None
        else:
            review_result += "Valid Proof File Format: True\n"
            audit_data = result
    except Exception as e:
        review_result += "Valid proof file format: False\n"
        return False, review_result, None

    #1. Verify TLS Server's pubkey
    # to-do: verify cert signed by trusted root CA
    # to-do: extrct pubkey from ca certificate, compare with pubkey in pgsg
    try:
        audit_session = shared.TLSNClientSession(ccs=audit_data['cipher_suite'],tlsver=audit_data['tlsver'])
        first_cert_len = shared.ba2int(audit_data['certs'][:3])
        cert_bi = audit_data['certs'][3:3+first_cert_len]
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bi)
        cert_cn = cert.get_subject().CN
        print(cert.get_subject().get_components())
        print("cert CN:",cert.get_subject().commonName)
    #    server_name = cert.get_subject().CN
        print("audit_data server:", audit_data['host'])
        server_name = audit_data['host']
    #    print("is rsapublickey:",isinstance(cert.get_pubkey().to_cryptography_key(), cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey))
        server_mod = cert.get_pubkey().to_cryptography_key().public_numbers().n
    #    print("extrct public_key mod:", server_mod)


        if cert_cn.startswith("*."):
            cert_cn = cert_cn[2:]
        if cert_cn.endswith(".cn"):
            cert_cn = cert_cn[:-3]
        if cert_cn.startswith("www."):
            cert_cn = cert_cn[4:]

        print("cert CN:",cert_cn)
        if "." in cert_cn:
            cert_cn_arrays = cert_cn.split(".")
            cert_cn = cert_cn_arrays[-2]
        print("cert CN:",cert_cn)

    #    if not server_name.endswith(cert_cn):
    #    if cert_cn not in server_name:
    #        review_result += "Valid Host name: False\n"
    #        return False, review_result, None
    #    else:
    #        review_result += "Valid Host name: True\n"
        print ('Processing data for server:', server_name)
    #    if server_name.strip() != audit_data['host'].strip():
    #        return False, "host name not match"
        public_hex = binascii.hexlify(shared.bi2ba(server_mod))
    #    if  server_name.startswith("*."):
    #        short = server_name[2:]
    #        url_openssl = "free-api."+short
    #        print ('Processing data for server:', server_name)
        cipher_key = audit_data['cipher_suite']
        cipher_suites = shared.tlsn_cipher_suites
        chosen_cipher = cipher_suites[cipher_key][0]
        print("chosen cipher suite:", chosen_cipher)
        tls_ver = "-tls1_1"
        if audit_data['tlsver']==bytearray('\x03\x01'):
            tls_ver = "-tls1"

        print("tls ver:", tls_ver)
        cmd = "echo |openssl s_client " + tls_ver + " -cipher " + chosen_cipher +" -connect "+server_name+":443 2>&1 | openssl x509 -pubkey -modulus -noout 2>&1 | grep 'Modulus' | sed 's/Modulus=//g' "
        print("cmd:", cmd)
        import subprocess
        public_openssl = subprocess.check_output(cmd, shell=True).strip('\n')

        print("hex:"+public_hex.upper().lower())
        print("openssl:"+public_openssl.upper().lower())
        if public_hex.upper().lower() == public_openssl.upper().lower():
            review_result += "Valid server pub key: True\n"

        else:
            review_result += "Valid server pub key: False\n"
            return False, review_result, None

    except Exception as e:
        review_result += "Valid server pub key: False\n"
        return False, review_result, None

    try:
        check_cert = os.system("echo |openssl s_client " + tls_ver + " -cipher " + chosen_cipher +" -connect "+server_name+":443")
        print("check_cert result:", check_cert)
        if check_cert == 0:
            review_result += "Valid server certificate chain: True\n"
        else:
            review_result += "Valid server certificate chain: False\n"
            return False, review_result, None
    except Exception as e:
        review_result += "Valid server certificate chain: False\n"
        return False, review_result, None

    # to-do check if openssl cmd return 0
    #2. Verify Proof from the Auditor Side
    # the partial proof from auditor is signed by auditor
    #First, extract the cert in DER form from the notarization file
    #Then, extract from the cert the modulus and server name (common name field)
    #To do this, we need to initialise the TLSNClientSession
    try:
        audit_session = shared.TLSNClientSession(ccs=audit_data['cipher_suite'],tlsver=audit_data['tlsver'])
        first_cert_len = shared.ba2int(audit_data['certs'][:3])
    #    server_mod, server_exp = audit_session.extract_mod_and_exp(certDER=audit_data['certs'][3:3+first_cert_len], sn=True)
        data_to_be_verified = audit_data['commit_hash'] + audit_data['pms2'] + shared.bi2ba(server_mod) + audit_data['audit_time']
        data_to_be_verified = sha256(data_to_be_verified).digest()
        if not shared.verify_signature(data_to_be_verified, audit_data['signature'],oracle_int_modulus):
            review_result += "Valid Auditor Signature: False\n"
            return False, review_result, None
        else:
            review_result += "Valid Auditor Signature: True\n"
        #3. Verify commitment hash.
        if not sha256(audit_data['response']+audit_data['certs']).digest() == audit_data['commit_hash']:
            review_result += "Valid server response: False\n"
            return False, review_result, None
        else:
            review_result += "Valid encrypted server response: True\n"
    except Exception as e:
        review_result += "Valid server response: False\n"
        print(e)
        return False, review_result, None

    #4 Decrypt html and check for mac errors. Response data and MAC code from auditee will be checked by the MAC key from Auditor
    try:
        audit_session.unexpected_server_app_data_count = shared.ba2int(audit_data['response'][0])
        audit_session.tlsver = audit_data['tlsver']
        audit_session.client_random = audit_data['client_random']
        audit_session.server_random = audit_data['server_random']
        audit_session.pms1 = audit_data['pms1']
        audit_session.pms2 = audit_data['pms2']
        audit_session.p_auditee = shared.tls_10_prf('master secret'+audit_session.client_random+audit_session.server_random,
                                                    first_half=audit_session.pms1)[0]
        audit_session.p_auditor = shared.tls_10_prf('master secret'+audit_session.client_random+audit_session.server_random,
                                                    second_half=audit_session.pms2)[1]

        audit_session.set_master_secret_half()
        audit_session.do_key_expansion()
        audit_session.store_server_app_data_records(audit_data['response'][1:])
        audit_session.IV_after_finished = (map(ord,audit_data['IV'][:256]),ord(audit_data['IV'][256]), \
                ord(audit_data['IV'][257])) if audit_data['cipher_suite'] in [4,5] else audit_data['IV']

        print("start to decrypt")
        plaintext, bad_mac = audit_session.process_server_app_data_records(is_for_auditor=True)
        print("decrypt done")
        if bad_mac:
            review_result += "Valid decrypted response content: False\n"
            return False, review_result, None

        plaintext = shared.dechunk_http(plaintext)
        plaintext = shared.gunzip_http(plaintext)
        if plaintext == audit_data['html']:
            review_result += "Valid decrypted response content: True\n"
        else:
            review_result += "Valid decrypted response content: False\n"
            return False, review_result, None
    except Exception as e:
        review_result += "Valid decrypted response content: False\n"
        return False, review_result, None
    #5 Display html + success.
#    with open(join(current_session_dir,'audited.html'),'wb') as f:
#        f.write(plaintext)
    #print out the info about the domain
#    n_hexlified = binascii.hexlify(shared.bi2ba(server_mod))
#    print("pubkey string:"+n_hexlified)
#    #pubkey in the format 09 56 23 ....
#    n_write = " ".join(n_hexlified[i:i+2] for i in range(0, len(n_hexlified), 2))
#    with open(join(current_session_dir,'domain_data.txt'), 'wb') as f: 
#        f.write('Server name: '+audit_session.server_name + '\n\n'+'Server pubkey:' + '\n\n' + n_write+'\n')
    return True, review_result, plaintext

if __name__ == "__main__":
    cmd = sys.argv[1]
    audit_filename = sys.argv[2]
    #for md5 hash, see https://pypi.python.org/pypi/<module name>/<module version>

    if cmd == "review":
        ok, result, html = review(audit_filename)
    else:
        ok, html = convert(audit_filename)
        
    if ok:
        print(html)
    else:
        print("Audit failed!", html)
