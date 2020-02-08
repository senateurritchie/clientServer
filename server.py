# -*- coding:utf8 -*-
import asyncio
import datetime
import json
import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


from protocol import TvAsSProtocol
from handshake import Handshake
from event.EventDispatcher import EventDispatcher

class Server(EventDispatcher,Handshake):
	"""
	"""

	def __init__(self,*args,**kwargs):
		super().__init__(*args,**kwargs)

		self.server = None
		self.version = '1.0.0'
		self.name = 'Mega deez'
		self.loop = None
		self.components = []

	def handshake(self,protocol,data):

		try:
			private_key = RSA.import_key(open("private.pem").read())
			# Decrypt the session key with the private RSA key
			cipher_rsa = PKCS1_OAEP.new(private_key)
			protocol.session_key = cipher_rsa.decrypt(data)
			print("SESSION KEY: ",protocol.session_key)
			self.sendMessage(protocol,"handshake_finish".encode())
		except Exception as e:
			raise e

	def run(self):

		loop = asyncio.get_event_loop()
		coro = loop.create_server(self.buildProtocol,None, 8888)
		server = loop.run_until_complete(coro)

		print('Serveur en ecoute sur {}'.format(server.sockets[0].getsockname()))

		self.server = server
		self.loop = loop

		try:
		    loop.run_forever()
		except KeyboardInterrupt:
		    pass

		server.close()
		loop.run_until_complete(server.wait_closed())
		loop.close()

	def buildProtocol(self):
		p = TvAsSProtocol(self.loop)
		p.server = self
		return p

	def on_new_connection(self,e):
		"""
		a chaque nouvelle connexion sur le serveur
		cette methode est appellée

		@param protocol est le protocol cree
		"""
		key = get_random_bytes(16)
		protocol = e.data

	def on_data_receive(self,e):
		"""
		a chaque message recu sur le serveur
		cette methode est appellée
		"""
		protocol = e.data["protocol"]
		data = e.data["data"]

		if protocol.session_key is None:
			self.handshake(protocol,data)
		else:
			decoded = self.decodeMessage(protocol,data.decode())
			print(decoded)

	

	def sendMessage(self,protocol,data):
		"""
		methode chargée de formater les requetes
		et de les envoyer

		@param protocol est le client qui recoit les données
		@param data les données
		"""
		cipher = AES.new(protocol.session_key,AES.MODE_CBC)
		ct = cipher.encrypt(pad(data,AES.block_size))
		iv = cipher.iv
		msg = {"iv":base64.b64encode(iv).decode(),'token':base64.b64encode(ct).decode()}
		msg = json.dumps(msg).encode()
		protocol.transport.write(msg)


	def decodeMessage(self,protocol,data):
		"""
		methode chargée de formater les requetes
		et de les envoyer

		@param data les données
		"""
		try:
			b64 = json.loads(data)
			iv = base64.b64decode(b64['iv'])
			ct = base64.b64decode(b64['token'])
			cipher = AES.new(protocol.session_key, AES.MODE_CBC, iv=iv)
			pt = unpad(cipher.decrypt(ct), AES.block_size)
			return pt
		except Exception as e:
			print("Incorrect decryption")


if __name__ == "__main__":
	s = Server()
	s.run()