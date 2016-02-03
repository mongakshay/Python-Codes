import argparse
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os 
from cryptography import exceptions
from cryptography.hazmat.primitives import padding as plain_text_padder
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as signature_padder
import pickle

# define a class that provides the structure of the object which we would 
# write into the cipher text file
class cipher_components(object):
	def __init__(self, cipher_text=None, iv=None, key=None, signature_iv=None, signature_key=None):
		self.cipher_text = cipher_text
		self.iv = iv
		self.key = key
		self.signature_iv = signature_iv
		self.signature_key = signature_key		

# serialize the public keys
def serialize_public_keys(key):
	backend = default_backend()
	try:
		key = serialization.load_pem_public_key(key, backend)
		return key
	except Exception as e:
		print "An error occured while serializing the public keys! %s" %e
		sys.exit()

# serialize the private keys
def serialize_private_keys(key):
	backend = default_backend()
	password = None
	try:
		key = serialization.load_pem_private_key(key, password, backend)
		return key
	except Exception as e:
		print "An error occured while serializing the private key! %s" %e
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

# adding padding to the data to make it to the correct block size of 128 used by AES
def add_padding(data):
	try:
		# aes has a fixed block size of 128
		aes_block_size = 128
		padder = plain_text_padder.PKCS7(aes_block_size).padder()
		padded_data = padder.update(data)
		padded_data += padder.finalize()
		return padded_data
	except Exception as e:
		print "An error occured while padding the file to be encrypted! %s" %e
		sys.exit()

# encrypt message 
def encrypt_message(receiver_key, message):
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
		print "An error occured while encrypting the symmetric key! %s" %e 
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
		print "The signature is invalid!"
	except Exception as e:
		print "An error occured in verifying the signature! %s" %e

# decrypt the input cipher 
def decrypt_cipher(receiver_private_key, cipher):
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

# encrypt the file 
def encrypt_file(receiver_public_file, sender_private_file, input_file, cipher_file):

	backend = default_backend()
	# generate randome symmetric key and the IV
	key = os.urandom(16)
	iv = os.urandom(16)

	receiver_public_key = read_file(receiver_public_file)
	sender_private_key = read_file(sender_private_file)

	receiver_public_key = serialize_public_keys(receiver_public_key)
	sender_private_key = serialize_private_keys(sender_private_key)

	input_file_data = read_file(input_file)
	print input_file_data
	padded_data = add_padding(input_file_data)

	try:
		# encrypt the input file 
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
		encryptor = cipher.encryptor()
		cipher_text = encryptor.update(padded_data) + encryptor.finalize()
	
		symmetric_key_encrypted = encrypt_message(receiver_public_key, key)
		signature_symmetric_key = sign_document(sender_private_key, symmetric_key_encrypted)
		iv_encrypted = encrypt_message(receiver_public_key, iv)
		signature_iv = sign_document(sender_private_key, iv_encrypted)
		# create the object to be written to the cipher file 
		final_cipher_output = cipher_components(cipher_text, iv_encrypted, symmetric_key_encrypted, signature_iv, signature_symmetric_key)

	
		write_to_file(final_cipher_output, cipher_file)
	except Exception as e:
		print "An error occured while encrypting the plain text file - ", input_file, "! %s" %e
		sys.exit()

# write the object created during encryption to the cipher file 
def write_to_file(data, filename):
	try:
		with open(filename, "w") as fh:
			pickle.dump(data, fh)
	except Exception as e:
		print "Could not write the data to the file - ", filename, " ! %s" %e
		sys.exit()

# read the object present in the cipher file
def read_cipher_file(filename):
	try:
		with open(filename, "r") as fh:
			output = pickle.load(fh)
		return output
	except Exception as e:
		print "Could not read the data from the file - ", filename, " ! %s" %e
		sys.exit()

# write the decrypted data to the file 
def write_plain_text(data, filename):
	try:
		fh = open(filename, "w")
		fh.write(data)
		fh.close()
	except Exception as e:
		print "Could not write the data to the plain text file - ", filename, " ! %s" %e
		sys.exit()

# decrypt the data 
def decrypt_file(receiver_private_file, sender_public_file, cipher_file, output_file):

	receiver_private_key = read_file(receiver_private_file)
	sender_public_key = read_file(sender_public_file)

	receiver_private_key = serialize_private_keys(receiver_private_key)
	sender_public_key = serialize_public_keys(sender_public_key)

	# read the objects from the cipher file 
	cipher_obj = read_cipher_file(cipher_file)
	cipher = cipher_obj.cipher_text
	iv_encrypted = cipher_obj.iv
	symmetric_key_encrypted = cipher_obj.key
	signature_iv = cipher_obj.signature_iv
	signature_symmetric_key = cipher_obj.signature_key

	# verify signature 
	verify_signature(sender_public_key, signature_iv, iv_encrypted)
	verify_signature(sender_public_key, signature_symmetric_key, symmetric_key_encrypted)

	# decrypt the symmetric key and IV
	symmetric_key = decrypt_cipher(receiver_private_key, symmetric_key_encrypted)
	iv = decrypt_cipher(receiver_private_key, iv_encrypted)

	# decrypt the cipher using the key and iv
	try:
		decryptor = Cipher(
			algorithms.AES(symmetric_key),
			modes.CBC(iv),
			backend=default_backend()).decryptor()

		decrypted = decryptor.update(cipher) + decryptor.finalize()
		unpadder =plain_text_padder.PKCS7(128).unpadder()
		plain_text = unpadder.update(decrypted)
		plain_text = plain_text + unpadder.finalize()
	except Exception as e:
		print "Error in decrypting the cipher text! %s" %e

	# write the output to the output file 
	write_plain_text(plain_text, output_file)

if __name__ == "__main__":

	# read the command line arguments 
	num_args = len(sys.argv)
	if num_args > 6:
		print "Extra arguments have been passed!"
		sys.exit()
	if num_args < 6:
		print "Insufficient number of arguments have been provided!"
		sys.exit
	type_of_operation = sys.argv[1]		

	# decrypt the cipher 
	if (type_of_operation == '-d'):
		receiver_private_key = sys.argv[2]
		sender_public_key = sys.argv[3]
		cipher_file = sys.argv[4]
		output_file = sys.argv[5]

		decrypt_file(receiver_private_key, sender_public_key, cipher_file, output_file)

	# encrypt the input file 
	if (type_of_operation == '-e'):
		receiver_public_key = sys.argv[2]
		sender_private_key = sys.argv[3]
		input_file = sys.argv[4]
		cipher_file = sys.argv[5]
		
		encrypt_file(receiver_public_key, sender_private_key, input_file, cipher_file)

	else:
		print "Only -e and -d allowed operations"
		sys.exit()




