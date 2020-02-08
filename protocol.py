# -*- coding:utf8 -*-
import asyncio

from enum import Enum 

class Protocol(asyncio.Protocol):

	def __init__(self,loop,*args, **kwargs):
		self.transport = None
		self.peername = None
		self.server = None
		self.loop = loop
		self.session_key = None

	"""
	les methodes heritées
	"""
	def connection_made(self,transport):
		self.transport = transport
		peername = transport.get_extra_info("peername")
		self.peername = peername
		print("nouvelle connexion a l'adresse: {}".format(peername))
		self.connectionMade(transport)

		if self.server:
			self.server.dispatch("new_connection",self)


	def connection_lost(self,exc):
		self.connectionLost(exc)
		if self.server is None:
			print("connexion au serveur perdue")
			self.loop.stop()
		else:
			print("deconnexion au serveur client {}".format(self.peername))


	def data_received(self,data):
		self.dataReceive(data)

		if self.server:
			self.server.dispatch("data_receive",{'protocol':self,'data':data})

	def eof_received(self):
		self.eofReceived()



	"""
	les methodes public
	"""
	def connectionMade(self,transport):
		pass

	def connectionLost(self,exc):
		pass

	def dataReceive(self,data):
		pass

	def eofReceived(self):
		pass


	def disconnect(self):
		"""
		permet de se deconnecter du serveur
		"""
		print("deconnexion à: {}".format(self.peername))
		self.transport.close()

	


class TvAsSProtocol(Protocol):
	"""
	"""

	def __init__(self,*args, **kwargs):
		super().__init__(*args, **kwargs)

