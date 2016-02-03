

import argparse
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM, socket, error as socket_err
import logging
import sys
import traceback
import pickle
import ast
import select 
import Queue
import json
import chat_library as util
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os 
from cryptography import exceptions
from cryptography.hazmat.primitives import padding as plain_text_padder
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as signature_padder

logger = logging.getLogger('ChatServer')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)
client_store = {}
client_progress = {}
SERVER_PRIVATE_KEY = 'server_private_key.pem'
private_key = util.get_private_key(SERVER_PRIVATE_KEY)
logged_users = {}
action_progress = {}

'''
TODO:
  add key check if the key is legit - sign iv and key 
  password file to be encrypted with salt 
  add check if client wants to chat with unknown user (not registered)
  check if user online while chat 
'''

def parse_data(data):
  values = data.split(":")
  username = values[0].strip()
  A = values[1].strip()
  return (A, username)

def get_temp_data(data):
  if (not data.has_key('CIPHER_KAS')):
       raise Exception(' ERROR: get_temp_data Did not find expected stucture...')
  cipher = data['CIPHER_KAS']
  return cipher


def extract_cipher_data(data):
  if (not data.has_key('CIPHER') or 
      not data.has_key('SYM_KEY') or 
      not data.has_key('IV')):
       raise Exception(' ERROR: Did not find expected stucture...')
  cipher = data['CIPHER']
  IV = data['IV']
  sym_key = data['SYM_KEY']
  return cipher, IV, sym_key

def create_socket():
  '''
  Creates the UDP socket 
  '''
  try:
    s = socket( AF_INET, SOCK_STREAM )
    s.setblocking(0)
    logger.info( 'Establishing connection...' )
  except socket_err as err:
    logger.info( 'Error occurred while creating socket connection; %s' % traceback.format_exc() )
    sys.exit()
  except:
    print('Error occured:', sys.exc_info()[0])
    sys.exit()
  return s


def bind_socket( socket_conn, HOST='', PORT=9090 ):
  '''
  Binds the created socket to the PORT and IP specified (of the server)
  '''
  try:
    socket_conn.bind( (HOST, PORT) )  
    logger.info( 'Binding the socket to %s on port %s ' % ( HOST, PORT ) )
  except socket_err as err:
    logger.info( 'Error occurred while binding the socket; %s' % traceback.format_exc() )
    close_socket(socket_conn)
    sys.exit()
  except:
    raise
    print('Error occured:', sys.exc_info()[0])
    sys.exit()

# decrypt the data 
def decrypt(cipher, e_iv, e_sym_key):
  iv = util.decrypt_iv(private_key, e_iv)
  sym_key = util.decrypt_iv(private_key, e_sym_key)
  try:
    decryptor = Cipher(
        algorithms.AES(sym_key),
        modes.CBC(iv),
        backend=default_backend()).decryptor()
    decrypted = decryptor.update(cipher) + decryptor.finalize()
    unpadder =plain_text_padder.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted)
    decrypted_data = decrypted_data + unpadder.finalize()
    decrypted_data = ast.literal_eval(decrypted_data)
    return decrypted_data
  except Exception as e:
      print "Error in decrypting the cipher text!   %s" %e
      raise

def load_client_vault():
  try:
    with open('server_cache', 'r') as fhandle:
      for line in fhandle:
        # do decryption of pwd here
        uname_pwd = line.strip()
        uname = uname_pwd.split(' ')[0]
        pwd = uname_pwd.split(' ')[1]
        client_store.update({uname : pwd})
  except Exception:
    logger.info( 'Error occurred while fetching users from vault')
    raise

def get_params(uname, A, s):
  try:
    if uname and A:
      b = util.get_random_number()
      p = client_store[uname]
      x = util.H(s, uname, p)
      N, g = util.get_ng()
      v = pow(g, x, N)  
      k = util.get_K()
      B = (k*v + pow(g, b, N)) % N
      return B, v, b
    else:
      print(' Please enter valid username and password ')
  except Exception as e:
    print(' Invalid username password entered... ')
        
def close_socket( socket_conn ):
  try:
    socket_conn.shutdown()
    socket_conn.close()
  except socket_err as err:
    logger.info('Error while closing the socket'% traceback.format_exc() )
    sys.exit()
  except:
      print('Error occured:', sys.exc_info()[0])
      sys.exit()


def non_blocking_listen(server):
  server.listen(5)
  read_sockets = [server]
  write_sockets = []
  message_queue = {}
  timeout = 30
  load_client_vault()
  try:
    while(read_sockets):
      readable, writable, exceptional = select.select(read_sockets, write_sockets, read_sockets, timeout)

      for s in readable:
        if s is server:
          conn, client_address = s.accept()
          print("Received connection - %s from %s" %(conn, client_address))
          conn.setblocking(0)
          read_sockets.append(conn)
          message_queue[conn] = Queue.Queue()
          client_progress[conn] = (1,)
        else:
          data = s.recv(40960)
          if data:
            pickled_data = pickle.loads(data)
            status = client_progress[s]

            if(status[0] == 1):
              #A, username = parse_data(pickled_data)
              cipher, e_iv , e_sym_key = extract_cipher_data(pickled_data)
              decrypted_data = decrypt(cipher, e_iv, e_sym_key)
              A = str(decrypted_data["A"])
              username = str(decrypted_data["username"])
              if(not logged_users.has_key(username)):
                num = util.get_random_challenge()
                hashed_num = util.get_hash(num)
                message_queue[s].put(hashed_num)
                # num is added so u can check in the next step that value sent by client is same as num 
                client_progress[s] = (2, A, username, num)
              else:
                print 'User: %s is already logged in!' %(username)
                message_queue[s].put('ERROR')

            if(status[0] == 2):
              salt = util.get_random_number() #Salt
              user_tuple = client_progress[s]
              username = user_tuple[2]
              numCheck = user_tuple[3]
              if user_tuple[1] and user_tuple[2] and pickled_data == numCheck:
                salt_and_B_dict = {}
                A = user_tuple[1]
                B, v, b = get_params(user_tuple[2], user_tuple[1], salt)
                u = util.H(A,B)
                signed_salt = util.sign_document(private_key, str(salt).encode())
                signed_B =  util.sign_document(private_key, str(B).encode())
                salt_and_B_dict.update({'SALT': salt})
                salt_and_B_dict.update({'SIGNED_SALT': signed_salt})
                salt_and_B_dict.update({'B': B})
                salt_and_B_dict.update({'SIGNED_B': signed_B})
                message_queue[s].put(salt_and_B_dict)
                Kas = util.get_server_shared_key(A, v, u, b) 
                client_progress[s] = (3, util.MD5_HASH(Kas), username)
            if(status[0] == 3):
                user_tuple = client_progress[s]
                cipher, e_iv , e_sym_key = extract_cipher_data(pickled_data)
                decrypted_data = decrypt(cipher, e_iv, e_sym_key)
                Challenge_PK = decrypted_data['CHALLENGE_PK']
                IV = decrypted_data['IV']
                final_decrypted_data = util.decrypt_using_Kas(Challenge_PK, user_tuple[1], IV)
                d= ast.literal_eval(final_decrypted_data)
                if str(d['CHALLENGE']) == str(decrypted_data['CHALLENGE']):
                  print 'Challenge matches'
                  #global logged_users
                  client_ip = s.getpeername()[0]
                  client_port = s.getpeername()[1]
                  ip_port = str(client_ip) + ":" + str(client_port)
                  logged_users[username] = (user_tuple[1], s, d['PK_CLIENT'],ip_port, IV) # .................
                else:
                  print 'Challenge does not match'

                nonce = d['CHALLENGE']
                subtracted_nonce = long(nonce) - 1
                #iv = os.urandom(16)
                encrypted_nonce = util.encrypt_message_KAS(str(subtracted_nonce), user_tuple[1], IV)
                message_queue[s].put(encrypted_nonce)
                client_progress[s] = (4, util.MD5_HASH(Kas), username, IV)

            if(status[0] == 4):
              user_tuple = client_progress[s]
              IV = user_tuple[3]
              final_decrypted_data = util.decrypt_using_Kas(pickled_data, user_tuple[1], IV)
              d= ast.literal_eval(final_decrypted_data)
              if(type(d) != long):
                valid = False
                if(action_progress.has_key(s)):
                  action_status = action_progress[s]
                  status_2 = action_status[1]
                  valid = (status_2 == 3)
                else:
                  valid = True

                if (valid):
                  if(d['ACTION'] == 'LIST'):
                    A_ip_port = ''
                    all_users = []
                    for username, value in logged_users.items():
                      if not username == d['username']:
                        A_ip_port = value[3]
                        all_users.append((username, A_ip_port))
                    if len(all_users) == 0:
                      all_users = 'No user is online currently'
                    action_challenge = util.get_random_number()
                    user_list = {}
                    user_list.update({'MESSAGE': all_users})
                    user_list.update({'NONCE': action_challenge})
                    user_list.update({'ACTION': 'LIST'})
                    final_kas = user_tuple[1]
                    try:
                      to_send = util.encrypt_message_KAS(user_list, final_kas, IV)
                    except:
                      print "An error occured while encrypting the text message for ACTION. ", message, "! %s" %e
                    message_queue[s].put(to_send)
                    action_progress[s] = ('LIST', 2, action_challenge)
                  
                  if(d['ACTION'] == 'LOGOUT'):
                    user_to_remove = d['username']
                    challenge_received = d['NONCE']
                    decrement_nonce = long(challenge_received) - 1
                    new_nonce = util.get_random_number()
                    user_list = {}
                    user_list.update({'MESSAGE': decrement_nonce})
                    user_list.update({'NONCE': new_nonce})
                    user_list.update({'ACTION': 'LOGOUT'})
                    final_kas = user_tuple[1]
                    try:
                      to_send = util.encrypt_message_KAS(user_list, final_kas, IV)
                    except:
                      print "An error occured while encrypting the text message for ACTION. ", message, "! %s" %e
                    message_queue[s].put(to_send)
                    action_progress[s] = ('LOGOUT', 2, new_nonce)
                  
                  # UPDATE START

                  if(d['ACTION'] == 'CHAT'):
                    A_ipport = ''
                    B_ipport = ''
                    A_PK = ''
                    B_PK = ''
                    Kbs = ''
                    Kas = ''
                    for username, value in logged_users.items():
                      if username == d['A']:
                        A_ipport = value[3]
                        Kas = value[0]
                        A_PK = str(value[2])
                      if username == d['B']:
                        B_ipport = value[3]
                        Kbs = value[0]
                        B_PK = value[2]

                    A_IP = A_ipport.split(":")[0]
                    A_PORT = A_ipport.split(":")[1]
                    username_A = d['A']
                    N6 = util.get_random_number()
                    TICKET = {}
                    ticket_and_stuff = {}
                    TICKET.update({'A_PORT':A_PORT})
                    TICKET.update({'A_IP':A_IP})
                    TICKET.update({'A_PK':A_PK})
                    TICKET.update({'A':username_A})
                    TICKET.update({'NONCE':N6})
                    final_kas = user_tuple[1]
                    username_B = str(d['B'])
                    # use B's IV
                    login_tuple = logged_users[username_B]    
                    B_IV = login_tuple[4]

                    Kbs_encrypted_ticket = util.encrypt_message_KAS(TICKET, Kbs, B_IV)
                    
                    N4 = d['NONCE']
                    B_IP = B_ipport.split(":")[0]
                    B_PORT = B_ipport.split(":")[1]
                    N4_minus_1 = long(N4) - 1

                    ticket_and_stuff.update({'TICKET':Kbs_encrypted_ticket})
                    ticket_and_stuff.update({'B_PORT':B_PORT})
                    ticket_and_stuff.update({'B_IP':B_IP})
                    ticket_and_stuff.update({'B_PK':B_PK})
                    ticket_and_stuff.update({'NONCE':N4_minus_1})
                    ticket_and_stuff.update({'CHALLENGE':N6})
                    ticket_and_stuff.update({'ACTION':'CHAT'})
                    ticket_and_stuff.update({'B_IV': B_IV})
                    ticket_and_stuff.update({'B': username_B})              
                    Kas_final_encrypt = util.encrypt_message_KAS(ticket_and_stuff, Kas, IV)
                    message_queue[s].put(Kas_final_encrypt)
                  #UPDATE END

              else:
                action_status = action_progress[s]
                if(action_status[1] == 2 and action_status[0] == 'LIST'):
                  action_progress[s] = (action_status[0], 3)
                if(action_status[1] == 2 and action_status[0] == 'LOGOUT'):
                  earlier_nonce = action_status[2]
                  if(long(final_decrypted_data) == long(earlier_nonce) - 1):
                    print ' deleting user info '
                    del logged_users[user_to_remove]
                    print 'Deleting user: ', user_to_remove
                    del client_progress[s]
                    action_progress[s] = (action_status[0], 3)
                  else:
                    print ' Did not receive logout confirmation '
                else:
                  print 'Message ignored'

            #message_queue[s].put(pickled_data)
            if s not in write_sockets:
              write_sockets.append(s)
          else:
            if (client_progress.has_key(s)):
              client_status = client_progress[s]
              if(client_status[0] > 1):
                print("Connection closed ...... !")
                del logged_users[client_status[2]]
                print 'Deleting user: ', client_status[2]
                if s in read_sockets:
                  read_sockets.remove(s)
                if s in write_sockets:
                  write_sockets.remove(s)
                s.close()

      for s in writable:
        try:
          next_msg = message_queue[s].get_nowait()
          to_send = pickle.dumps(next_msg)
        except Queue.Empty:
          write_sockets.remove(s)
        else:
          #print("Sending message - %s to %s" %(to_send, s.getpeername())) 
          s.send(to_send)

      for s in exceptional:
        print("Exceptional condition occurred for user - %s" %(s.getpeername()))
        read_sockets.remove(s)
        if s in write_sockets:
          write_sockets.remove(s)
        close_socket(s)
        del message_queue[s]
  except KeyboardInterrupt:
    "Inside KeyboardInterrupt!!!!!!!!"
    server.close()
    for s in read_sockets:
      s.close()
    for s in write_sockets:
      s.close()
  except:
    traceback.print_exc()
    print 'Closing server .....'
    server.close()
    for s in read_sockets:
      s.close()
    for s in write_sockets:
      s.close()

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument( '-sp', '-server_port', 
                       required = True,
                       dest='port',
                       metavar='server port', 
                       action='store', 
                       help='server port')
  args = parser.parse_args()
  s = create_socket()
  bind_socket(s, HOST='localhost', PORT=int(args.port))
  #start_listening(s)
  non_blocking_listen(s)
  s.close()
