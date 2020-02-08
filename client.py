# -*- coding:utf8 -*-
import asyncio
from protocol import TvAsSProtocol
from handshake import Handshake
import ssl
import json
import base64
from threading import Thread

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class Client(TvAsSProtocol,Handshake):

	def __init__(self,*args,**kwargs):
		super().__init__(*args,**kwargs)
		self.in_interactive = False


	def handshake(self):

		recipient_key = RSA.import_key(open("public.pem").read())
		self.session_key = get_random_bytes(16)

		# Encrypt the session key with the public RSA key
		cipher_rsa = PKCS1_OAEP.new(recipient_key)
		enc_session_key = cipher_rsa.encrypt(self.session_key)
		self.transport.write(enc_session_key)

		print("SESSION KEY: ",self.session_key)


	def connectionMade(self,transport):
		self.handshake()


	def dataReceive(self,data):
		if data:
			try:
				decoded = self.decodeMessage(data)
				if decoded == b"handshake_finish":
					thr = Thread(target=self.interactive)
					thr.start()

			except Exception as e:
				raise e

	def interactive(self):
		if self.in_interactive:
			return

		self.in_interactive = True;
		while True:
			message = input("> ")
			message = message.strip()
			if message:
				self.sendMessage(message.encode())


	def sendMessage(self,data):
		"""
		methode chargée de formater les requetes
		et de les envoyer

		@param data les données
		"""

		cipher = AES.new(self.session_key,AES.MODE_CBC)
		ct = cipher.encrypt(pad(data,AES.block_size))
		iv = cipher.iv

		msg = {"iv":base64.b64encode(iv).decode(),'token':base64.b64encode(ct).decode()}
		msg = json.dumps(msg).encode()
		self.transport.write(msg)


	def decodeMessage(self,data):
		"""
		methode chargée de formater les requetes
		et de les envoyer

		@param data les données
		"""
		try:
			b64 = json.loads(data)
			iv = base64.b64decode(b64['iv'])
			ct = base64.b64decode(b64['token'])
			cipher = AES.new(self.session_key, AES.MODE_CBC, iv=iv)
			pt = unpad(cipher.decrypt(ct), AES.block_size)
			return pt
		except Exception as e:
			print("Incorrect decryption")


			

				


ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.check_hostname = False
ssl_context.load_verify_locations('cert.crt')

loop = asyncio.get_event_loop()
coro = loop.create_connection(lambda: Client(loop),"10.0.1.28", 8888)

loop.run_until_complete(coro)
loop.run_forever()
loop.close()