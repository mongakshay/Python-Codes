#!/usr/bin/python

import argparse
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM, socket, error as socket_err
import logging
import sys
import traceback
import pickle

logger = logging.getLogger('ChatServer')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)
client_store = {}

def create_socket():
  '''
  Creates the UDP socket 
  '''
  try:
    s = socket( AF_INET, SOCK_STREAM )
    #s.setblocking(0)
    logger.info( 'Creating the UDP socket connection...' )
  except socket_err as err:
    logger.info( 'Error occurred while creating socket connection; %s' % traceback.format_exc() )
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

def load_client_vault():
  try:
    vdata = []
    with open('server_cache', 'r') as fhandle:
      for line in fhandle:
        # do decryption of pwd here
        client_store.update({line.split('\t')[0], line.split('\t')[1]})
  except Exception:
    logger.info( 'Error occurred while fetching users from vault' % traceback.format_exc() )


def do_user_auth(uname, A):
  if uname and A:
    b = util.get_random_number()
    s = util.get_random_number()
    p = client_store[uname]
    x = util.H(s, uname, p)
    N, g = util.get_ng()
    v = pow(g, x, N)  
    k = util.get_k()
    B = (k * v + pow(g, b, N)) % N
  else:
    raise Exception('Please enter valid username and A')

def start_listening(socket_conn):
  '''
  Server now starts listening to the UDP port to which it is connected
  Now the server will be expecting clients to conect to this socket
  And then serve those clients with the request message 
  '''
  socket_conn.listen(1)
  conn, addr = socket_conn.accept()
  print 'Connection address: ', addr

  while(True):
    try:
      clients_message = conn.recv(4096)
      if not clients_message == '' or  clients_message:
        '''
        if the data is valid and if the cleint is first time 
        sending the message, then it registers the client as Active
        and does not send the message to anyone.
        '''
        #conn.send('mongakshay@gmail.com')
        '''
        message = pickle.loads(clients_message[0])
        addr = clients_message[1]
        '''
        message = pickle.loads(clients_message)
        print "Message received -->  ",message
        '''
        if(message['request'] == "HELLO"):
          user_info_A = message['userinfo']
          username = message['username']
          print user_info_A, ' -------- ', username
        '''
          #do_user_auth(user_info['username'], user_info['A'])
    except socket_err as err:
      logger.info( 'Error occurred while creating socket lstening; %s' % traceback.format_exc() )
      close_socket(conn)
      sys.exit()
      
def close_socket( socket_conn ):
  try:
    socket_conn.close()
  except socket_err as err:
    logger.info('Error while closing the socket'% traceback.format_exc() )
    sys.exit()

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
  start_listening(s)
  s.close()
