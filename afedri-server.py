#!/usr/bin/python

import threading
import SocketServer
import socket
import re
import sys
import struct
import os
import numpy
import select
import traceback
from afedri import AfedriSDR

CMDLEN = 1024 # should always fit
BUFFER_SIZE = 1024 # from dspserver
PERIOD = 1028 # packet length
TXLEN = 500 # from dspserver
PTXLEN = 1024 # for predsp

class SharedData(object):
	def __init__(self, predsp=False):
		self.mutex = threading.Lock()
		self.clients = {}
		self.receivers = {}
		self.predsp = predsp
		self.exit = False

	def acquire(self):
		self.mutex.acquire()

	def release(self):
		self.mutex.release()

class ConnectedClient(object):
	def __init__(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8*1024**2)
		self.receiver = -1
		self.port = -1

class Listener(SocketServer.ThreadingTCPServer):
	def __init__(self, server_address, RequestHandlerClass, shared):
		SocketServer.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass)
		self.shared = shared

class ListenerHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		caddr = self.client_address
		shared = self.server.shared
		shared.acquire()
		shared.clients[caddr] = ConnectedClient()
		shared.release()
		while 1:
			while not select.select([self.request], [], [], 1)[0]:
				if shared.exit:
					self.request.close()
					return
			try:
				data = self.request.recv(CMDLEN)
			except:
				break
			if not data:
				break
			m = re.search('^attach (\d+)', data, re.M)
			if m:
				shared.acquire()
				if shared.clients[caddr].receiver!=-1:
					shared.release()
					self.request.sendall('Error: Client is already attached to receiver')
					continue
				if int(m.group(1)) not in shared.receivers.keys():
					shared.release()
					self.request.sendall('Error: Invalid Receiver')
					continue
				if int(m.group(1)) in [shared.clients[i].receiver for i in shared.clients.keys()]:
					shared.release()
					self.request.sendall('Error: Receiver in use')
					continue
				shared.clients[caddr].receiver = int(m.group(1))
				shared.release()
				self.request.sendall('OK 192000')
				continue
			m = re.search('^detach (\d+)', data, re.M)
			if m:
				shared.acquire()
				if shared.clients[caddr].receiver==-1:
					shared.release()
					self.request.sendall('Error: Client is not attached to receiver')
					continue
				if shared.clients[caddr].receiver!=int(m.group(1)):
					shared.release()
					self.request.sendall('Error: Invalid Receiver')
					continue
				shared.clients[caddr].receiver = -1
				shared.clients[caddr].port = -1
				shared.release()
				self.request.sendall('OK 192000')
				continue
			m = re.search('^frequency ([0-9.,e+-]+)', data, re.M)
			if m:
				shared.acquire()
				if shared.clients[caddr].receiver==-1:
					shared.release()
					self.request.sendall('Error: Client is not attached to receiver')
					continue
				idx = shared.clients[caddr].receiver
				afedri = shared.receivers[idx]
				shared.release()
				try:
					freq = int(m.group(1))
					afedri.set_freq(freq)
				except:
					self.request.sendall('Error: Invalid frequency')
					continue
				self.request.sendall('OK')
				continue
			m = re.search('^start (iq|bandscope) (\d+)', data, re.M)
			if m:
				shared.acquire()
				if shared.clients[caddr].receiver==-1:
					shared.release()
					self.request.sendall('Error: Client is not attached to receiver')
					continue
				if m.group(1)=='iq':
					shared.clients[caddr].port = int(m.group(2))
				shared.release()
				self.request.sendall('OK')
				continue
			m = re.search('^stop (iq|bandscope)', data, re.M)
			if m:
				shared.acquire()
				if shared.clients[caddr].receiver==-1:
					shared.release()
					self.request.sendall('Error: Client is not attached to receiver')
					continue
				if m.group(1)=='iq':
					if shared.clients[caddr].port==-1:
						shared.release()
						self.request.sendall('Error: Client is not started')
						continue
					shared.clients[caddr].port = -1
				shared.release()
				self.request.sendall('OK')
				continue
			#m = re.search('^hardware\?', data, re.M)
			#if m:
			#	self.request.sendall('OK afedrisdrnet')
			#	continue
			self.request.sendall('Error: Invalid Command')
		shared.acquire()
		shared.clients.pop(caddr)
		shared.release()

def run_listener(c, h, p):
	try:
		server = Listener((h, p), ListenerHandler, c)
	except:
		c.exit = True
		traceback.print_exc()
		return
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		server.shutdown()
		server.server_close()
		c.exit = True
		try:
			c.release()
		except:
			pass

def afedrisdrnet_io(shared, afedri, idx):
	shared.acquire()
	if idx in shared.receivers.keys():
		shared.release()
		raise IOError, 'Receiver with inde %d already connected' % (idx)
	shared.receivers[idx] = afedri
	predsp = shared.predsp
	shared.release()
	pcm = afedri.setup_recv()
	afedri.stream(True)
	seq = 0L
	while 1:
		audio = pcm.recv(PERIOD)
		(b, n) = struct.unpack('<HH', audio[:4])
		if b!=0x8404:
			continue
		if seq==0:
			seq = n
		if n>(seq&0xFFFF):
			seq = (seq&(~0xFFFF))|n
		audio = audio[4:]
		rcv = []
		shared.acquire()
		for caddr in shared.clients.keys():
			if shared.clients[caddr].receiver==idx and shared.clients[caddr].port!=-1:
				rcv.append((shared.clients[caddr].socket, (caddr[0], shared.clients[caddr].port)))
		shared.release()
		if shared.exit:
			afedri.stream(False)
			return
		if predsp:
			for j in xrange(0, (len(audio)+PTXLEN-1)/(PTXLEN)):
				for k in rcv:
					snd = struct.pack('<I', seq&0xFFFFFFFF)
					k[0].sendto(snd+audio[j*PTXLEN:j*PTXLEN+min(len(audio)-j*PTXLEN, PTXLEN)], (k[1][0], k[1][1]+500))
		else:
			naudio = numpy.fromstring(audio, dtype="<h")/numpy.float32(32767.0)
			naudio.resize(len(naudio)/(BUFFER_SIZE*2), BUFFER_SIZE*2)
			for i in naudio:
				if afedri.swapiq:
					txdata = i[::2].tostring() + i[1::2].tostring()
				else:
					txdata = i[1::2].tostring() + i[::2].tostring()
				for j in xrange(0, (len(txdata)+TXLEN-1)/(TXLEN)):
					for k in rcv:
						snd = struct.pack('<IIHH', seq&0xFFFFFFFF, (seq>>32)&0xFFFFFFFF, j*TXLEN, min(len(txdata)-j*TXLEN, TXLEN))
						k[0].sendto(snd+txdata[j*TXLEN:j*TXLEN+min(len(txdata)-j*TXLEN, TXLEN)], k[1])
				seq += 1

def create_afedrisdrnet_thread(clients, afedri, idx=0):
	t = threading.Thread(target=afedrisdrnet_io, args=(clients, afedri, idx))
	t.start()
	return t

shared = SharedData(predsp='-p' in sys.argv)
try:
	afedri = AfedriSDR(swapiq='-s' in sys.argv, need_init=True)
except IOError:
	sys.stderr.write('AfedriSDR not found\n')
	sys.exit(0)
ft = create_afedrisdrnet_thread(shared, afedri, 0)

run_listener(shared, '0.0.0.0', 11000)

