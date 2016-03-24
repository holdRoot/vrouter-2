#!/usr/bin/env python2.7

# Import C extension
#import vifdb_notify
import os, sys, struct, itertools

# Global list of vif objects
VRFS_list = dict()

class Vif(object):
	__hdr__ = (
		("name", "32s", "-" * 32),
		("ip", "4s", "\x00" * 4),
		("mask", "4s", "\x00" * 4),
		("mac", "6s", "\x00" * 6),
		("label", "4s", "\x00" *4),
		("cpus", "1s", "\x00"),
		("cpusets", "32s", "\x00" * 32),
	)

	def __init__(self, data):
		hdr = self.__hdr__
		self.__config_fields__ = [ f[0] for f in hdr ]
		self.__config_fmt__ = "!" + "".join([ f[1] for f in hdr ])
		self.__config_len__ = struct.calcsize(self.__config_fmt__)
		for k, v in itertools.izip(self.__config_fields__, struct.unpack(self.__config_fmt__, data[:self.__config_len__])):
			setattr(self, k, v)

	def Create(self):
		self.path = "/var/run/vrouter/" + self.name
		self.vifp = vifdb_notify.add_notify(self.name.strip(), self.ip, self.mask, \
					self.mac, self.label, self.path.strip(), self.cpus, \
					self.cpusets)
		if self.vifp is None:
			print ("VIF creation failed")
			return -1
		VRFS_list.update( {self.path.strip() : self} )
		return 0

	def Delete(self):
		VRFS_list.pop(self.path.strip())
		vifdb_notify.del_notify(self.vifp)

def vifdb_init(nbCores):
	# Create socketServer for vif add/del listen.
	try:
		vif1 = Vif("vif-1" + " " * (32 - len("vif-1")) + "\xc0\xa8\x01\x02" + \
		           "\xff\xff\xff\x00" + "\xde\xad\xbe\xef\x01\x3c" + \
		           "\x00\x00\x00\x00" + "\x01" + "\x01\x02\x03\x04" +\
		           "\x00" * 28)
		vif1.Create()
		vif2 = Vif("vif-2" + " " * (32 - len("vif-1")) + "\xc0\xa8\x01\x03" + \
		           "\xff\xff\xff\x00" + "\xde\xad\xbe\xef\x01\x3d" \
		           + "\x00\x00\x00\x00" + "\x01" + "\x02\x03\x04\x05" +\
		           "\x00" * 28)
		vif2.Create()
	except:
		return 0
	return 1

def vifdb_find(path):
	print ("Find %s path in VRFS_list" % path)
	print (VRFS_list)
	if path in VRFS_list:
		vif = VRFS_list[path]
		print "Found entry ", vif.vifp
		return vif.vifp
	else:
		return None
