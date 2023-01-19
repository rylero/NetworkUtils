from cryptography.fernet import Fernet
import rsa
import pickle

#header
HEADER_LEN = 64
FORMAT = "utf-8"

#messages
CLOSE_CONN = "!CLOSE_CONN!"
MSG_RECIVED = "!MSG_RECIVED!"

CONN_REQ = "!CONN_REQ!"
CONN_COMF = "!CONN_COMF!"

PING = "!PING!"
PONG = "!PONG!"

SHARE_PUBLIC_KEY = "!SHARE_PUBLIC_KEY!"
SERVE_PUBLIC_KEY = "!SERVE_PUBLIC_KEY!"

START_SYMMETRIC = "!START_SYMMETRIC!"
SYMMETRIC_CONFIRMED = "!SYMMETRIC_CONFIRMED"

FILE_TRANSFER = "!FILE_TRANSFER!"
FILE_RECEIVED = "!FILE_RECEIVED!"

#errors
CONN_ERROR = "!CONN_ERROR!"
ENCRYPTION_ERROR = "!ENCRYPTION_ERROR!"


#file extraction functions
def extractFileBinary(filePath):
	f = open(filePath, "rb")
	data = f.read()
	f.close()
	return data


def writeFileBinary(filePath, data):
	f = open(filePath, "wb")
	f.write(data)
	f.close()


# encryption sevices
class Encrypter:

	def __init__(self):
		self.publicKey, self.privateKey = rsa.newkeys(1024)
		self.otherPublicKey = None
		self.symmetricKey = None
		self.fernet = None

	def setOtherPublicKey(self, k):
		self.otherPublicKey = k

	def setSymmetricKey(self, key):
		self.symmetricKey = key
		self.fernet = Fernet(self.symmetricKey)

	def generateSymmetricKey(self):
		self.symmetricKey = Fernet.generate_key()
		self.fernet = Fernet(self.symmetricKey)
		return self.symmetricKey

	def encryptMessage(self, msg, encMethod=0):
		if encMethod == 0:
			if self.fernet:
				return self.fernet.encrypt(msg)
			else:
				return msg
		elif encMethod == 1:
			return rsa.encrypt(msg, self.otherPublicKey)
		elif encMethod == 2:
			return msg

	def decryptMessage(self, msg, encMethod=0):
		if encMethod == 0:
			if self.fernet:
				return self.fernet.decrypt(msg)
			else:
				return msg
		elif encMethod == 1:
			return rsa.decrypt(msg, self.privateKey)
		elif encMethod == 2:
			return msg


# sending Messages
class MessageTerminal:

	def __init__(self, conn):
		self.conn = conn
		self.enc = Encrypter()

	def close(self):
		self.sendMessage({"cmd": CLOSE_CONN})
		self.conn.close()

	def sendMessage(self, msg, encMethod=0):
		msg = self.enc.encryptMessage(pickle.dumps(msg), encMethod)
		msgLen = str(len(msg)).encode(FORMAT)
		msgLen += b' ' * (HEADER_LEN - len(msgLen))
		self.conn.send(msgLen)
		self.conn.send(msg)

	def recvMessage(self, encMethod=0):
		msgLen = self.conn.recv(HEADER_LEN)
		msgLen = int(msgLen.decode(FORMAT))
		msg = self.conn.recv(msgLen)
		msg = self.enc.decryptMessage(msg, encMethod)
		return pickle.loads(msg)

	def initializeAsClient(self):
		#request connection
		self.sendMessage({"cmd": CONN_REQ}, 2)
		if self.recvMessage(2)["cmd"] != CONN_COMF:
			return CONN_ERROR

		#setup rsa
		self.sendMessage({"cmd": SHARE_PUBLIC_KEY, "key": self.enc.publicKey}, 2)
		msg = self.recvMessage(2)
		if msg["cmd"] != SERVE_PUBLIC_KEY or not msg["key"]:
			return ENCRYPTION_ERROR
		key = msg["key"]
		self.enc.setOtherPublicKey(key)

		#share symmetric key
		symKey = self.enc.generateSymmetricKey()
		self.sendMessage({"cmd": START_SYMMETRIC, "key": symKey}, 1)
		if self.recvMessage(1)["cmd"] != SYMMETRIC_CONFIRMED:
			return ENCRYPTION_ERROR

		# ping - pong
		self.sendMessage({"cmd": PING})
		if self.recvMessage()["cmd"] != PONG:
			return CONN_ERROR

		return None  # fully connected

	def initializeAsServer(self):
		msg = self.recvMessage(2)
		if msg["cmd"] != CONN_REQ:
			return CONN_ERROR
		self.sendMessage({"cmd": CONN_COMF}, 2)

		msg = self.recvMessage(2)
		if msg["cmd"] != SHARE_PUBLIC_KEY or not msg["key"]:
			return ENCRYPTION_ERROR
		self.enc.setOtherPublicKey(msg["key"])
		self.sendMessage({"cmd": SERVE_PUBLIC_KEY, "key": self.enc.publicKey}, 2)

		msg = self.recvMessage(1)
		if msg["cmd"] != START_SYMMETRIC or not msg["key"]:
			return ENCRYPTION_ERROR
		self.enc.setSymmetricKey(msg["key"])
		self.sendMessage({"cmd": SYMMETRIC_CONFIRMED}, 1)

		msg = self.recvMessage()
		if msg["cmd"] != PING:
			return CONN_ERROR
		self.sendMessage({"cmd": PONG})
