
import socket 
from threading import Thread
from thread import *
import sys
import pickle 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import chat_library as util

SERVER_CONFIG = '/Users/AKSHAY/Desktop/server_config.txt'

def read_server_details(filename):
  fh = open(filename, 'r')
  data = fh.read()
  values = data.split(" ")
  return (values[0].strip(), values[1].strip())

# create a socket 
def create_socket():
  try:
    # create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # handling socket errors
    return sock
  except socket.error, s_error:
    error_code = s_error[0]
    error_message = s_error[1]
    print('Error in creating socket: ', error_code, ' - ', error_message)
    sys.exit()


def find_value_from_hash(msg):
  for i in range(10000, 99999):
    value = util.get_hash(i)
    if (value == msg):
      return i 

# receive messages 
def receiveMessages(sock):
  while(1):
    try:
      print("waiting to receive message")
      # try to receive messages from the server
      #msg, addr = sock.recvfrom(4096)
      msg  = sock.recv(4096)
      #msg = pickle.loads(msg)
      # handling socket errors
    except socket.error, s_error:
      error_code = s_error[0]
      error_message = s_error[1]
      print('Error in reading messages: ', error_code, ' - ', error_message)
    print msg
  #value = find_value_from_hash(msg)

def send_msg_to_server(sock, msg, sip, sport):
  print("Sending message to server: %s") %(msg)
  sock.connect((sip, int(sport)))
  while(1):
    try:
      msg1 = pickle.dumps(msg)
      # sending message to the server
      #sock.sendto(msg1, (sip, int(sport)))
      sock.send(msg1)
      break
    except:
      raise 

def encrypt_message(username, A):
  #data = {}
  #data.update({'request':'HELLO','userinfo':A, 'username':username})
  return username+" : "+str(A)


def request_authentication(username, sock, sip, sport):
  a = util.get_random_number()
  A = util.get_public_ephemeral(a)
  msg = encrypt_message(username, A)
  #print("A: %s, a: %s, msg: %s") %(A, a, msg)
  # start a thread that only handles receipt of messages 
  #start_new_thread(receiveMessages, (sock,))	
  send_msg_to_server(sock, msg, sip, sport)
  '''
  t1 = Thread(target=receiveMessages, args=(sock,))
  t1.start()
  t1.join()
  '''

if __name__ == "__main__":
  # arg parse will be here
  sip, sport = read_server_details(SERVER_CONFIG)
  print "IP: %s Port number: %s" %(sip, sport)
  username = raw_input("Please enter your username: ")
  print "Entered username is: %s" %(username)
  password = raw_input("Please enter your password: ")
  print "Entered password is: %s" %(password)
  sock = create_socket()
  request_authentication(username.strip(), sock, sip, sport)
  sock.close()
