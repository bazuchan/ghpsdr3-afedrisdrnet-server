#!/usr/bin/python

import socket
import struct

REQ_ITEM_SET = 0b000
#REQ_ITEM_GET = 0b001
#REQ_RANGE_GET = 0b010
#REQ_DATA_ACK = 0b011
#REQ_DATA_BASE = 0b100
RESP_ACK = 0b000
#RESP_BAD = 0b001
#RESP_RANGE = 0b010
#RESP_DATA_ACK = 0b011
#RESP_DATA_BASE = 0b100

TCP_HID_PACKET = 7
HID_COMMAND_SIZE = 7

HID_MEMORY_READ_WRITE_REPORT = 1
HID_GENERIC_REPORT = 2
HID_FREQUENCY_REPORT = 3

HID_GENERIC_GET_INIT_STATUS_COMMAND = 4
HID_GENERIC_VER_COMMAND = 9
HID_GENERIC_INIT_FE_COMMAND = 0xE1
HID_GENERIC_GET_FREQ_COMMAND = 1
HID_GENERIC_GET_SR_COMMAND = 14
HID_GENERIC_SET_SAMPLE_RATE_COMMAND = 30
HID_GENERIC_GAIN_COMMAND = 2
HID_GENERIC_DAC_COMMAND = 8

HID_READ_EEPROM_COMMAND = 0x55
HID_WRITE_EEPROM_COMMAND = 0x56

CI_FREQUENCY = 0x0020
CI_DDC_SAMPLE_RATE = 0x00B8
CI_RF_GAIN = 0x0038

VADDRESS_MAIN_CLOCK_FREQ_LOW_HALFWORD = 0x0000
VADDRESS_MAIN_CLOCK_FREQ_HIGH_HALFWORD = 0x0001
VADDRESS_SAMPLE_RATE_LO = 0x0006
VADDRESS_SAMPLE_RATE_HI = 0x0007

FE_GAINS = [1.00, 1.14, 1.33, 1.60, 2.00, 2.67, 4]

def rf_gain2db(gain):
	return -10+3*(gain>>3)

def db2rf_gain(gain):
	return int((float(gain)+10)/3)<<3

def _db2rf_gain(gain):
	return int((float(gain)+9.8)*5.1)

def _rf_gain2db(gain):
	return float(gain)/5.1-9.8

class AfedriSDR(object):
	def __init__(self, addr=('192.168.1.8',50000), network=True):
		self.network = network
		self.cmdsize = HID_COMMAND_SIZE
		if self.network:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
			self.sock.connect(addr)
			self.local = self.sock.getsockname()
		else:
			#hid_open
			pass
		r = self.get_init_status()
		if r:
			raise IOError, 'Init error %u' % (r)
		self.clock = self.get_main_clock()

	def pad(self, s):
		return s[:self.cmdsize]+'\0'*(self.cmdsize-len(s[:self.cmdsize]))

	def hid_write(self, s):
		if self.network:
			h = struct.pack('<BB', self.cmdsize + 2, TCP_HID_PACKET << 5)
			self.sock.send(h + self.pad(s))
		else:
			#wid_write
			pass

	def hid_read(self):
		if self.network:
			d = self.sock.recv(1024)
			if len(d)<2 or ord(d[0])==0 or ord(d[1])>>5!=TCP_HID_PACKET:
				return ''
			return d[2:][:self.cmdsize]
		else:
			#wid_read
			pass

	def hid_generic_command(self, command, param=None, paramtype='B'):
		if param==None:
			cmd = struct.pack('<BB', HID_GENERIC_REPORT, command)
		else:
			cmd = struct.pack('<BB%s' % (paramtype), HID_GENERIC_REPORT, command, param)
		self.hid_write(cmd)
		return self.hid_read()

	def hid_set_eeprom_data(self, addr, data):
		cmd = struct.pack('<BBBH', HID_MEMORY_READ_WRITE_REPORT, HID_WRITE_EEPROM_COMMAND, addr, data)
		self.hid_write(cmd)
		return self.hid_read()

	def hid_get_eeprom_data(self, addr):
		cmd = struct.pack('<BBB', HID_GENERIC_REPORT, HID_READ_EEPROM_COMMAND, addr)
		self.hid_write(cmd)
		return struct.unpack('<H', self.hid_read()[2:4])[0]

	def tcp_command(self, m_type, code, data):
		sz = 5+len(data)
		cmd = struct.pack('<BBH', sz, ((m_type<<5)&0xFF)|((sz>>8)&0x1F), code) + data + '\x00'
		self.sock.send(cmd)
		r = self.sock.recv(1024)
		if ord(r[1])>>5==RESP_ACK and struct.unpack('<H', r[2:4])[0]==code:
			return r[4:]
		else:
			return None

	def get_init_status(self):
		r = self.hid_generic_command(HID_GENERIC_GET_INIT_STATUS_COMMAND, ~HID_GENERIC_GET_INIT_STATUS_COMMAND&0xFF)
		return struct.unpack('<I', r[2:6])[0]

	def get_fw_version(self):
		r = self.hid_generic_command(HID_GENERIC_VER_COMMAND)
		return '%X' % struct.unpack('<I', r[2:6])

	def init_fe(self):
		self.hid_generic_command(HID_GENERIC_INIT_FE_COMMAND, ~HID_GENERIC_INIT_FE_COMMAND&0xFF)

	def get_freq(self, chan=0):
		r = self.hid_generic_command(HID_GENERIC_GET_FREQ_COMMAND, chan)
		return struct.unpack('<I', r[1:5])[0]

	def set_freq(self, freq, chan=0):
		if self.network:
			cmd = struct.pack('<BI', chan, int(freq))
			self.tcp_command(REQ_ITEM_SET, CI_FREQUENCY, cmd)
		else:
			cmd = struct.pack('<BI', HID_FREQUENCY_REPORT, int(freq))
			self.hid_write(cmd)
			self.hid_read()

	def calc_sample_rate(self, rate):
		dec = round(float(self.clock)/(4*float(rate)))
		return float(self.clock)/(4*dec)

	def get_sample_rate(self):
		r = self.hid_generic_command(HID_GENERIC_GET_SR_COMMAND)
		return struct.unpack('<I', r[2:6])[0]&0xFFFFF

	def set_sample_rate(self, rate):
		self.hid_set_eeprom_data(VADDRESS_SAMPLE_RATE_LO, rate&0xFFFF)
		self.hid_set_eeprom_data(VADDRESS_SAMPLE_RATE_HI, (rate>>16)&0xFFFF)

	def set_network_sample_rate(self, rate):
		if self.network:
			cmd = struct.pack('<BI', 0, int(rate))
			return self.tcp_command(REQ_ITEM_SET, CI_DDC_SAMPLE_RATE, cmd)
		else:
			return self.hid_generic_command(HID_GENERIC_SET_SAMPLE_RATE_COMMAND, rate, 'I')

	def set_fe_gain(self, gainindex):
		self.hid_generic_command(HID_GENERIC_GAIN_COMMAND, int(gainindex)+1)

	def set_rf_gain(self, gain):
		if self.network:
			cmd = struct.pack('<BB', 0, int(gain))
			self.tcp_command(REQ_ITEM_SET, CI_RF_GAIN, cmd)
		else:
			self.hid_generic_command(HID_GENERIC_DAC_COMMAND, int(gain))
	
	def get_main_clock(self):
		return self.hid_get_eeprom_data(VADDRESS_MAIN_CLOCK_FREQ_LOW_HALFWORD) | (self.hid_get_eeprom_data(VADDRESS_MAIN_CLOCK_FREQ_HIGH_HALFWORD)<<16)


a = AfedriSDR(addr=('172.17.2.98', 50000))
#a.init_fe()
print a.get_fw_version()
a.set_freq(7300000)
print a.get_freq()
a.set_network_sample_rate(250000)
#a.set_sample_rate(200000)
#print a.get_sample_rate()
a.set_fe_gain(0)
a.set_rf_gain(0)
print a.calc_sample_rate(250000)

