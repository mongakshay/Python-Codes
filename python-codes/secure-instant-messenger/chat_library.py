
import random 
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography import exceptions
from cryptography.hazmat.primitives import padding as plain_text_padder
from cryptography.hazmat.primitives.asymmetric import padding as signature_padder
import sys
import pickle
import md5



def H(*a):
  a = ':'.join([str(a) for a in a])
  return int(hashlib.sha256(a.encode('ascii')).hexdigest(), 16)

N = '''00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3c:50:0b:88:5f:e3'''

N = int(''.join(N.split()).replace(':', ''), 16)
g = 2

def get_K():
  return H(N, g)

def get_ng():
  return N, g

def get_random_number(num=1024):
  return random.SystemRandom().getrandbits(num) % N 

def get_hash(msg):
  msg = str(msg)
  digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
  digest.update(msg.encode())
  d = digest.finalize()
  return str(d)

def get_public_ephemeral(randNum):
  return pow(g, randNum, N)

def get_random_challenge():
  return random.randint(10000, 99999)

def get_challenge():
  return os.urandom(128)

def get_client_shared_key(B, k, x, a, u):
  s_c = pow(long(B) - k * pow(g, x , N), a + u * x, N)
  k_c = H(s_c)
  return k_c

def get_server_shared_key(A, v, u, b):
  S_s = pow(long(A) * pow(v, u, N), b, N)
  K_s = H(S_s)
  return K_s

# serialize the public keys
def serialize_public_keys(key):
  backend = default_backend()
  try:
    key = serialization.load_pem_public_key(key, backend)
    return key
  except Exception as e:
    print "An error occured while serializing the public keys! %s" %e
    sys.exit()


# adding padding to the data to make it to the correct block size of 128 used by AES
def add_padding(data):
  try:
    # aes has a fixed block size of 128
    data = str(data)
    data = data.encode()
    aes_block_size = 128
    padder = plain_text_padder.PKCS7(aes_block_size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data
  except Exception as e:
    print "An error occured while padding the message to be encrypted! %s" %e
    sys.exit()

def write_data(myfile, data):
  try:
    with open (myfile, "w") as f:
      f.write(data)
  except IOError as e:
    print "An error occured while writing file",e
    raise


def fetch_iv(iv):
  try:
    with open (iv, "r") as fhandle:
      iv_file=pickle.load(fhandle)
    return iv_file 
  except IOError as e:
    print "An error occured while reading iv file %s" %e
    sys.exit()


# read the given input file
def read_file(input_file):
  try:
    fh = open(input_file, "r")
    data = fh.read()
    return data 
  except Exception as e:
    print "An error occured while reading the file - ", input_file, "  ! %s" %e
    sys.exit()

def encrypt_message_PSK(message, SERVER_KEY):
  server_public_key = read_file(SERVER_KEY)
  server_public_key = serialize_public_keys(server_public_key)
  padded_data = add_padding(message)
  iv = os.urandom(16)
  key = os.urandom(16)
  encrypted_iv = encrypt_iv(server_public_key, iv)
  encrypted_key = encrypt_iv(server_public_key, key)

  try:
    # encrypt the input message 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    response = {}
    response.update({'CIPHER': cipher_text})
    response.update({'IV': encrypted_iv})
    response.update({'SYM_KEY': encrypted_key})
    return response
  except Exception as e:
    raise

def encrypt_with_PSK(message, public_key):
  serialized_public_key = serialize_public_keys(public_key)
  padded_data = add_padding(message)
  iv = os.urandom(16)
  key = os.urandom(16)
  encrypted_iv = encrypt_iv(serialized_public_key, iv)
  encrypted_key = encrypt_iv(serialized_public_key, key)

  try:
    # encrypt the input message 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    response = {}
    response.update({'CIPHER': cipher_text})
    response.update({'IV': encrypted_iv})
    response.update({'SYM_KEY': encrypted_key})
    return response
  except Exception as e:
    raise

def MD5_HASH(data):
    return md5.new(str(data)).digest()

def encrypt_message_KAS(message, Kas, iv):
  padded_data = add_padding(message)

  try:
    # encrypt the input message 
    cipher = Cipher(algorithms.AES(str(Kas)), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return cipher_text
  except Exception as e:
    print "An error occured while encrypting the text message - %s" %e
    sys.exit()

def encrypt_iv(receiver_key, message):
  try:
    symmetric_key_encrypted = receiver_key.encrypt(
      message,
      signature_padder.OAEP(
        mgf = signature_padder.MGF1(algorithm = hashes.SHA1()),
        algorithm = hashes.SHA1(),
        label = None
      )
    )
    return symmetric_key_encrypted
  except Exception as e:
    raise 
    sys.exit()

# decrypt the input cipher 
def decrypt_iv(receiver_private_key, cipher):
  try:
    message = receiver_private_key.decrypt(
      cipher,
      signature_padder.OAEP(
        mgf = signature_padder.MGF1(hashes.SHA1()),
        algorithm = hashes.SHA1(),
        label = None
      )
    )
    return message
  except Exception as e:
    print "An error occured while decryption! %s" %e

# serialize the private keys
def serialize_private_keys(key):
  backend = default_backend()
  password = None
  try:
    key = serialization.load_pem_private_key(key, password, backend)
    return key
  except Exception as e:
    raise
    print "An error occured while serializing the private key! %s" %e
    sys.exit()

# sign the input document 
def sign_document(sender_private_key, document):
  try:
    signer = sender_private_key.signer(
      signature_padder.PSS(
        mgf = signature_padder.MGF1(hashes.SHA1()),
        salt_length = signature_padder.PSS.MAX_LENGTH
      ),
      hashes.SHA1()
    )
    signer.update(document)
    signature = signer.finalize()
    return signature
  except Exception as e:
    print "An error occured while trying to sign the encrypted symmetric key! %s" %e
    sys.exit()

# verify if the signature is valid 
def verify_signature(sender_public_key, signature, message):
  try:
    sender_public_key = read_file(sender_public_key)
    sender_public_key = serialize_public_keys(sender_public_key)
    verifier = sender_public_key.verifier(
      signature,
      signature_padder.PSS(
        mgf = signature_padder.MGF1(hashes.SHA1()),
        salt_length = signature_padder.PSS.MAX_LENGTH
      ),
      hashes.SHA1()
    )
    verifier.update(message)
    verifier.verify()
  except exceptions.InvalidSignature:
    raise
    #print "The signature is invalid!"
  except Exception as e:
    print "An error occured in verifying the signature! %s" %e

def get_private_key(key):
 private_key_file = read_file(key)
 return serialize_private_keys(private_key_file)

def get_public_key_string(key):
 return read_file(key)

def get_public_key(key):
 private_key_file = read_file(key)
 return serialize_public_keys(private_key_file)

# decrypt the data 
def decrypt_using_Kas(cipher, Kas, iv):
  try:
    decryptor = Cipher(
        algorithms.AES(Kas),
        modes.CBC(iv),
        backend=default_backend()).decryptor()
    decrypted = decryptor.update(cipher) + decryptor.finalize()
    unpadder =plain_text_padder.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted)
    decrypted_data = decrypted_data + unpadder.finalize()
    return decrypted_data
  except Exception as e:
    print "Error in decrypting the cipher text! %s" %e
    raise

def get_hmac(msg, key):
  h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
  h.update(msg)
  hashed_msg = h.finalize()
  return hashed_msg

def verify_with_hmac(msg_to_verify, hmac_msg, key):
  try:
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    # message to verify has to be bytes 
    h.update(str(msg_to_verify))
    h.verify(hmac_msg)
  except Exception as e: 
    print "An error occured in checking integrity of the message"
