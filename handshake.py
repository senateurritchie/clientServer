# -*- coding:utf8 -*-

class Handshake:
	"""
	classe abstraite pour protocol de mise en relation client - serveur
	"""

	def __init__(self,*args,**kwargs):
		pass

	def handshake(self,*args,**kwargs):
		raise NotImplementedError