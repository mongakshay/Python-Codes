
import os
import socket 
from threading import Thread
from thread import *
import thread
import sys
import pickle 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography import exceptions
from cryptography.hazmat.primitives import padding as plain_text_padder
from cryptography.hazmat.primitives.asymmetric import padding as signature_padder
import chat_library as util
import ast
import traceback
import select 
import Queue
import random 
from socket import error as socket_err


SERVER_CONFIG = 'server_config.txt'
progress = {}
shared_key = 0
SERVER_KEY = 'server_public_key.pem'
#PUBLIC_KEY = util.get_public_key('server_public_key.pem')
CLIENT_PRIVATE_KEY = util.get_private_key('client_private_key.pem')
CLIENT_PRIVATE_KEY_STR = util.get_public_key_string('client_private_key.pem')
CLIENT_PUBLIC_KEY_STR = util.get_public_key_string('client_public_key.pem')
NONCE_SENT = 0
IV = os.urandom(16)
GENERATED_IV = IV
USERNAME_TO_PORT = {}
EXIT_IN_ERROR = False
ACTION_NONCE = 0
CHAT_NONCE = 0
g = 5 #627
p = 23 #941
a = 0
df_keys = {}
message_tracker = {}
IV_tracker = {}
df_progress = {}
port_tracker = {}


#To do:
# client retries 
# wrong password handling 
# sending message to wrong user name handle
# udp socket send - use received b's ip and port 
# chat log out 

class ServerConnectionBroken(Exception):
    pass

def close_socket( socket_conn ):
  try:
    socket_conn.shutdown()
    socket_conn.close()
  except socket_err as err:
    logger.info('Error while closing the socket'% traceback.format_exc() )
    sys.exit()
  except Exception as e:
      print('Error occured:', e)
      sys.exit()

def read_server_details(filename):
  fh = open(filename, 'r')
  data = fh.read()
  values = data.split(" ")
  return (values[0].strip(), values[1].strip())

# create a socket 
def create_tcp_socket():
  try:
    # create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # handling socket errors
    return sock
  except socket.error, s_error:
    error_code = s_error[0]
    error_message = s_error[1]
    print('Error in creating TCP socket: ', error_code, ' - ', error_message)
    sys.exit()
  except Exception as e:
    print('Error occured in creating TCP socket: %s' %e)
    sys.exit()

def create_udp_socket():
    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return udp_socket
    except socket.error, s_error:
      error_code = s_error[0]
      error_message = s_error[1]
      rint('Error in creating UDP socket: ', error_code, ' - ', error_message)
      sys.exit()
    except Exception as e:
      print('Error occured in creating UDP socket: %s' %e)
      sys.exit()


def find_value_from_hash(msg):
  for i in range(10000, 99999):
    value = util.get_hash(i)
    if (value == msg):
      return i 

def compute_shared_key(A, msg, username, password, a):
  try:
    if(msg.has_key('SIGNED_SALT') and msg.has_key('SIGNED_B') and msg.has_key('SALT') and msg.has_key('B')):
      signed_salt = msg['SIGNED_SALT']
      signed_B = msg['SIGNED_B']
      salt = msg['SALT']
      B = msg['B']

      util.verify_signature(SERVER_KEY, signed_salt, str(salt).encode())
      util.verify_signature(SERVER_KEY, signed_B, str(B).encode())
    else:
      raise Exception('Did not found the expected keys for Salt and B')
  except Exception as e:
    print "An error occured while verifying the digital signature"
    raise 

  u = util.H(A, B)
  x = util.H(salt, username, password)
  k = util.get_K()
  key = util.get_client_shared_key(B, k, x, a, u)
  return key 

# receive messages 
def receiveMessages(sock, username, sip, sport, A, password, a):
  while(1):
    try:
      # try to receive messages from the server
      msg = sock.recv(40960)  # changed here akshay
      if msg != '':
        msg1 = pickle.loads(msg)
        #print("Received message:%s" %(msg1))
        status = progress[username]
        if(status == 1):
          if(msg1 == 'ERROR'):
            global EXIT_IN_ERROR
            EXIT_IN_ERROR = True
            sys.exit()
          value = find_value_from_hash(msg1)
          send_message(sock, value, sip, sport)
          progress[username] = 2
      
        if(status == 2):
          challenge_pk_data = {}
          data_for_kas = {}
          final_to_server = {}
          global shared_key
          shared_key = compute_shared_key(A, msg1, username, password, a)
          final_kas = util.MD5_HASH(shared_key)
          challenge = util.get_random_number()
          global NONCE_SENT
          NONCE_SENT = challenge
          data_for_kas.update({'CHALLENGE': challenge , 'PK_CLIENT': CLIENT_PUBLIC_KEY_STR})
          Kas_encrypted_data = util.encrypt_message_KAS(data_for_kas, final_kas, GENERATED_IV)
          # add IV here 
          challenge_pk_data.update({'CHALLENGE_PK': Kas_encrypted_data, 'CHALLENGE': challenge, 'IV': GENERATED_IV})
          data_to_server = util.encrypt_message_PSK(challenge_pk_data, SERVER_KEY)
          send_message(sock, data_to_server, sip, sport)
          progress[username] = 3

        if(status == 3):
          hash_shared_key = util.MD5_HASH(shared_key)
          nonce = util.decrypt_using_Kas(msg1, hash_shared_key, GENERATED_IV)
          incremented_nonce = long(nonce) + 1
          if incremented_nonce == NONCE_SENT:
            print ("Login Success !")
            return True
          else:
            print("Authentication pending!")
            return False

      else:
        print("Connection with server is broken...")
        sys.exit()
    except KeyboardInterrupt:
      sock.close()
    # handling socket errors
    except socket.error, s_error:
      sock.close()
      error_code = s_error[0]
      error_message = s_error[1]
      print('Error in reading messages: ', error_code, ' - ', error_message)
    except Exception as e:
      print('Error occured:', e)
      sock.close()
      sys.exit()

def send_msg_to_server(sock, msg, sip, sport):
  #print("Sending message to server: %s") %(msg)
  while(1):
    try:
      msg1 = pickle.dumps(msg)
      # sending message to the server
      sent = sock.send(msg1)
      if sent == 0:
        print("Connection with server is broken!")
        sys.exit()
      else:
        return 1
    except KeyboardInterrupt:
      sock.close()
    except:
      sock.close()
      print('Error occured:', sys.exc_info()[0])

def send_message(sock, msg, sip, sport):
  done = False
  while(done == False):
    sent = send_msg_to_server(sock, msg, sip, sport)
    if(sent == 1):
      done = True
      return 

def request_authentication(username, sock, sip, sport, password):
  a = util.get_random_number()
  A = util.get_public_ephemeral(a)
  message = {}
  message.update({'username': username})
  message.update({'A': A})
  try:
    msg = util.encrypt_message_PSK(message, SERVER_KEY)
  except Exception as e:
    print "An error occured while encrypting the text message - ", message, "! %s" %e
  try:
    #start_new_thread(receiveMessages, (sock,)) 
    sock.connect((sip, int(sport)))
    send_message(sock, msg, sip, sport)
    progress[username] = 1
    t1 = Thread(target=receiveMessages, args=(sock, username, sip, sport, A, password, a))
    t1.start()
    t1.join()
    if(EXIT_IN_ERROR):
      sys.exit()
  except ServerConnectionBroken:
    print 'Connection broken !!'
    sys.exit()

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

def extract_cipher_data(data):
  if (not data.has_key('CIPHER') or 
      not data.has_key('SYM_KEY') or 
      not data.has_key('IV')):
       raise Exception(' ERROR: Did not find expected stucture...')
  cipher = data['CIPHER']
  IV = data['IV']
  sym_key = data['SYM_KEY']
  return cipher, IV, sym_key

# decrypt the data 
def decrypt(cipher, e_iv, e_sym_key):
  iv = util.decrypt_iv(CLIENT_PRIVATE_KEY, e_iv)
  sym_key = util.decrypt_iv(CLIENT_PRIVATE_KEY, e_sym_key)
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

def non_blocking_listen(server, current_username):
  global USERNAME_TO_PORT
  global CHAT_NONCE
  global shared_key
  global g
  global p 
  global a
  global df_keys
  global message_tracker 
  global IV_tracker
  global df_progress
  global port_tracker

  udp_socket = create_udp_socket()
  udp_socket.bind(server.getsockname())
  read_sockets = [server, sys.stdin, udp_socket]
  write_sockets = []
  message_queue = {}
  timeout = 30
  try:
    while(read_sockets):
      #print("Waiting for read/write event...")
      readable, writable, exceptional = select.select(read_sockets, write_sockets, read_sockets, timeout)

      for s in readable:
        if s == sys.stdin:
          command = s.readline().strip()
          if command.lower() == 'list' or command.lower() == 'logout':
            global ACTION_NONCE
            ACTION_NONCE = util.get_random_number()
            message = {}
            message.update({'ACTION': command.upper()})
            message.update({'username': current_username})
            message.update({'NONCE': ACTION_NONCE})
            try:
              final_kas = util.MD5_HASH(shared_key)
              to_send = util.encrypt_message_KAS(message, final_kas, GENERATED_IV)
            except Exception as e:
              print "An error occured while encrypting the text message for ACTION. ", message, "! %s" %e
            send_message(server, to_send, sip, sport)
          
          # you are A
          if command.split(" ")[0] == "send":
            chat_text = command.split(" ")[1:]
            sender_username = chat_text[0]
            message_tracker[sender_username] = ' '.join(chat_text)

            #udp_socket.sendto(' '.join(chat_text[1:]),('localhost',int(USERNAME_TO_PORT[sender_username])))

            # update
            CHAT_NONCE = util.get_random_number()
            message = {}
            message.update({'ACTION': 'CHAT'})
            message.update({'A': current_username})
            message.update({'B': sender_username})
            message.update({'NONCE': CHAT_NONCE})
            try:
              final_kas = util.MD5_HASH(shared_key)
              to_send = util.encrypt_message_KAS(message, final_kas, GENERATED_IV)
            except Exception as e:
              print "An error occured while encrypting the text message for ACTION. ", message, "! %s" %e
            send_message(server, to_send, sip, sport)
            # update ends 

        if s is server and s != sys.stdin:
          data = s.recv(40960)
          if data:
            pickled_data = pickle.loads(data)
            #print("Received data - %s from %s" %(pickled_data, s.getpeername()))

            hash_shared_key = util.MD5_HASH(shared_key)
            response = util.decrypt_using_Kas(pickled_data, hash_shared_key, GENERATED_IV)
            d = ast.literal_eval(response)
            
            valid = False
            if(str(d['ACTION']).strip() == 'LIST'):
              list_message = d['MESSAGE']
              list_of_users = []
              if type(list_message) == str:
                print list_message
              else:
                print "~~~~~~~~~~~~~ Online Users ~~~~~~~~~~~~~"
                for item in list_message:
                  username =  item[0]
                  portip = item[1]
                  port = portip.split(":")[1]
                  USERNAME_TO_PORT.update({username:int(port)})
                  print username
                print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
              valid = True
              
            if(str(d['ACTION']).strip() == 'LOGOUT'):
              received_nonce = d['MESSAGE']
              if(long(received_nonce) + 1 == ACTION_NONCE):
                print "Confirming logout"
                valid = True
            
            if valid:
              challenge_nonce = d['NONCE']
              decrement_nonce = long(challenge_nonce) - 1
              try:
                final_kas = util.MD5_HASH(shared_key)
                to_send = util.encrypt_message_KAS(decrement_nonce, final_kas, GENERATED_IV)
              except Exception as e:
                print "An error occured while encrypting the text message for ACTION. ", message, "! %s" %e
              send_message(server, to_send, sip, sport)

              if(str(d['ACTION']).strip() == 'LOGOUT'):
                server.close()
                for s in read_sockets:
                  if s != sys.stdin:
                    s.close()
                for s in write_sockets:
                  s.close()
                #sys.exit()
            #message_queue[s].put(pickled_data)

            # update starts 

            # you are A
            if(str(d['ACTION']).strip() == 'CHAT'):
              ticket = d['TICKET']
              b_port = d['B_PORT']
              b_ip = d['B_IP']
              b_pk = d['B_PK']
              b_iv = d['B_IV']
              b = d['B']
              IV_tracker[b] = b_iv
              port_tracker[b] = int(b_port)
              nonce = d['NONCE']
              new_challenge = d['CHALLENGE']


              if(long(nonce) + 1 == long(CHAT_NONCE)):
                message = {}
                message.update({'TICKET': ticket})
                message.update({'NONCE': new_challenge})
                a = random.randint(1, 9)
                A = (g**a) % p
                message.update({'A': A})
                message.update({'g': g})
                message.update({'p': p})

                try:
                  msg = util.encrypt_with_PSK(message, b_pk)
                  #pickled_msg = pickle.dumps(msg)
                except Exception as e:
                  print "An error occured while encrypting the text message - ", message, "! %s" %e

                protocol_identity = {}
                protocol_identity.update({'CIPHER': msg})
                protocol_identity.update({'PROTOCOL': 'PUBLIC_KEY'})

                pickled_msg = pickle.dumps(protocol_identity)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 18000)
                udp_socket.sendto(pickled_msg,('localhost',int(b_port)))

              # update ends 

          else:
            print("Connection closed")
            if s in write_sockets:
              write_sockets.remove(s)
            read_sockets.remove(s)
            close_socket(s)
            del message_queue[s]

        elif s == udp_socket:

          # update begins 

          msg = s.recvfrom(30000)
          if msg:
            pickled_data = pickle.loads(msg[0])

            protocol = pickled_data['PROTOCOL']
            cipher = pickled_data['CIPHER']
            
            if(protocol == 'PUBLIC_KEY'):
              # You are user B
              cipher2, e_iv , e_sym_key = extract_cipher_data(cipher)
              decrypted_data = decrypt(cipher2, e_iv, e_sym_key)
              
              if(decrypted_data.has_key('A')):
                A = long(decrypted_data['A'])
                g = long(decrypted_data['g'])
                p = long(decrypted_data['p'])

                ticket = decrypted_data['TICKET']
                nonce = decrypted_data['NONCE']
                
                b = random.randint(100, 999)
                B = (g**b) % p
                b_shared_key = (A**b) % p

                hash_shared_key = util.MD5_HASH(shared_key)
                response = util.decrypt_using_Kas(ticket, hash_shared_key, GENERATED_IV)
                d = ast.literal_eval(response)
                message = {}
                message.update({'B': B})
                # B's username 
                message.update({'username': current_username})
                a_pk = d['A_PK']
                a_ip = d['A_IP']
                a_port = d['A_PORT']
                # A's username
                username = d['A']
                ticket_nonce = d['NONCE']

                if long(nonce) == long(ticket_nonce):
                  df_keys[username] = str(b_shared_key)
                  df_progress[current_username] = (2, username)
                  try:
                    msg = util.encrypt_with_PSK(message, a_pk)
                    #pickled_msg = pickle.dumps(msg)
                  except Exception as e:
                    print "An error occured while encrypting the text message - ", message, "! %s" %e

                  protocol_identity = {}
                  protocol_identity.update({'PROTOCOL': 'PUBLIC_KEY'})
                  protocol_identity.update({'CIPHER': msg})
                  pickled_msg = pickle.dumps(protocol_identity)
                  #udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 20000)
                  udp_socket.sendto(pickled_msg,('localhost',int(a_port)))

              else:
                # you are user A
                if(decrypted_data.has_key('B')):
                  B = long(decrypted_data['B'])
                  # B's username 
                  username = decrypted_data['username']

                  ds_shared_key = (B ** a) % p
                  df_keys[username] = str(ds_shared_key)

                  B_IV = IV_tracker[username]
                  B_port = port_tracker[username]

                  message_to_send = message_tracker[username]
                  hmac_msg = util.get_hmac(message_to_send, B_IV)
                  to_send_dict = {}
                  to_send_dict.update({'MESSAGE': message_to_send})
                  to_send_dict.update({'HMAC': hmac_msg})

                  try:
                    final_kas = util.MD5_HASH(df_keys[username])

                    to_send = util.encrypt_message_KAS(to_send_dict, final_kas, B_IV)
                  except Exception as e:
                    print "An error occured while encrypting the text message for CHAT. ", message, "! %s" %e

                  protocol_identity = {}
                  protocol_identity.update({'PROTOCOL': 'SESSION_KEY'})
                  protocol_identity.update({'CIPHER': to_send})
                  pickled_msg = pickle.dumps(protocol_identity)
                  udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 20000)
                  udp_socket.sendto(pickled_msg,('localhost',int(B_port)))
                  
            if(protocol == 'SESSION_KEY'):
              # you are user B 
              progress_tuple = df_progress[current_username]
              
              if (progress_tuple[0] == 2):
                b_username = progress_tuple[1]
                hash_shared_key = util.MD5_HASH(str(df_keys[b_username]))

                response = util.decrypt_using_Kas(cipher, hash_shared_key, GENERATED_IV)
                d = ast.literal_eval(response)
                msg_received = d['MESSAGE']
                msg_hmac = d['HMAC']
                util.verify_with_hmac(msg_received, msg_hmac, GENERATED_IV)
                print msg_received
                del df_progress[current_username]

            # update ends

      for s in writable:
        try:
          next_msg = message_queue[s].get_nowait()
          to_send = pickle.dumps(next_msg)
        except Queue.Empty:
          print("Queue Empty")
          write_sockets.remove(s)
        else:
          print("Sending message - %s to %s" %(to_send, s.getpeername())) 
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
      if s != sys.stdin:
        s.close()
    for s in write_sockets:
      s.close()
    sys.exit()
  except:
    print 'Closing client .....'
    server.close()
    for s in read_sockets:
      if s != sys.stdin:
        s.close()
    for s in write_sockets:
      s.close()
    sys.exit()



if __name__ == "__main__":
  # arg parse will be here
  sip, sport = read_server_details(SERVER_CONFIG)
  sport = sys.argv[1]
  print "IP: %s Port number: %s" %(sip, sys.argv[1])
  username = raw_input("Please enter your username: ")
  print "Entered username is: %s" %(username)
  password = raw_input("Please enter your password: ")
  print "Entered password is: %s" %(password)
  tcp_socket = create_tcp_socket()
  #bind_socket(s, HOST='localhost', PORT=int(args.port))
  progress[username] = 0
  try_num = 0
  authenticated = request_authentication(username.strip(), tcp_socket, sip, sport, password.strip())
  if(authenticated == False):
    try_num = 1
    while(try_num < 5 and authenticated == False):
      authenticated = request_authentication(username.strip(), tcp_socket, sip, sport, password.strip())
      try_num = try_num + 1
  if(authenticated == False):
    print('Exceeded maximum number of tries. Exiting client application')
    tcp_socket.close()
    sys.exit()
  else:
    try:
      tcp_socket.setblocking(0)
      non_blocking_listen(tcp_socket, str(username))
    except KeyboardInterrupt:
      tcp_socket.close()
      sys.exit()
    except Exception as e:
      raise
      tcp_socket.close()
      sys.exit()


