#!/usr/bin/env python2.7

import dpkt
import SocketServer
import sys
import struct
import socket
import threading
import itertools
import os
import linecache

from bitarray import bitarray

# Global object for VRFS
VRFS = dict()
VRFS_lock = threading.Lock()

# -----------------------------------------------------------------------------
# Custom Error Type
# -----------------------------------------------------------------------------
class NotADhcpPacketError(Exception):
    def __init__(self, message):
        self.message = "DHCP: "  + message
        pass

class VrfError(Exception):
    def __init__(self, message):
        self.message = "VRF:" + message
        pass

def GetExceptionInfo():
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    return 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)

# -----------------------------------------------------------------------------
# HexString, Iny conversion
# -----------------------------------------------------------------------------
def Int2HexString(val):
    return struct.pack(">I", val)

def HexString2Int(val):
    return struct.unpack(">I", val)[0]

def DottedIP2Int(ipstr):
    return struct.unpack(">I", socket.inet_aton(ipstr))[0]

def Int2DottedIP(ip):
    return socket.inet_ntoa(struct.pack(">I", ip))

def Mac2Str(mac):
    return ':'.join(['%02x' % ord(char) for char in mac])

# -----------------------------------------------------------------------------
# Dynamic Config support 
# -----------------------------------------------------------------------------
class ConfigRequestHandler(SocketServer.BaseRequestHandler):
    __hdr__ = (
        ("vrf_no", "1c", -1),
        ("server_ip", "4s", '\x00' * 4),
        ("range_start", "4s", '\x00' * 4),
        ("range_end", "4s", '\x00' * 4),
        ("netmask", "4s", '\x00' * 4),
        ("dns1", "4s", '\x00' * 4),
        ("dns2", "4s", '\x00' * 4),
        ("broadcast_ip", "4s", '\x00' * 4),
        ("server_mac", "6s", '\x00' * 6),
        ("domain_name", "32s", '\x00' * 4),
    )

    def Parse(self):
        hdr = self.__hdr__
        self.__config_fields__ = [ f[0] for f in hdr ]
        self.__config_fmt__ = "!" + "".join([ f[1] for f in hdr ])
        self.__config_len__ = struct.calcsize(self.__config_fmt__)
        for k, v in itertools.izip(self.__config_fields__, struct.unpack(self.__config_fmt__, self.data[:self.__config_len__])):
            setattr(self, k, v)

    # Got one Config Request from a client
    def handle(self):
        self.data = self.request.recv(2048).strip()
        if len(self.data) != 0:
            print ("Config struct received of length: %d" % len(self.data))
            # Parse the config records
            self.Parse()
            if self.__config_len__ != len(self.data):
                self.request.sendall("Check config record size %d expected %d" % (self.__config_len__, len(self.data)))
                return
            VRFS_lock.acquire()
            if int(self.vrf_no) not in VRFS:
                try:
                    vrf = Vrf()
                    print ("Creating VRF (%d)\n" % int(self.vrf_no))
                    vrf.config(self.range_start, self.range_end, self.netmask, self.server_ip, self.server_mac, \
                            self.dns1, self.dns2, self.broadcast_ip, self.domain_name)
                    VRFS.update({int(self.vrf_no) : vrf})
                except Exception as e:
                    VRFS_lock.release()
                    self.request.sendall("VRF error: " + GetExceptionInfo())
                    return
            VRFS_lock.release()
            self.request.sendall("VRF created")
        self.request.sendall("Check config record size")

# -----------------------------------------------------------------------------
# Lease Object
# -----------------------------------------------------------------------------
class IpLease(object):
    def __init__(self, ip, client_mac,  is_dynamic=True, lease_time=86400):
        self.ip = ip
        self.lease_time = lease_time
        self.dynamic = is_dynamic
        self.client_mac = client_mac

# -----------------------------------------------------------------------------
# Virtual Routing Instance
# -----------------------------------------------------------------------------
class Vrf(object):
    def __init__(self):
        self.ip_range_start = ""
        self.ip_range_end = ""
        self.netmask = ""
        self.server_ip = ""
        self.server_mac = ""
        self.dns1_ip = ""
        self.dns2_ip = ""
        self.broadcast_ip = ""
        self.domain_name = ""
        self.leases = dict()
        self.arp_tables = dict()
        self.lock = threading.Lock()

    # Configure the VRF object
    def config(self, ip_range_start, ip_range_end, netmask, server_ip, server_mac, dns1_ip="0.0.0.0", dns2_ip="0.0.0.0", broadcast_ip="0.0.0.0", domain_name=""):
        self.ip_range_start = ip_range_start
        self.ip_range_end = ip_range_end
        self.netmask = netmask
        self.server_ip = server_ip
        self.server_mac = server_mac
        self.dns1_ip = dns1_ip
        self.dns2_ip = dns2_ip
        self.broadcast_ip = broadcast_ip
        self.domain_name = domain_name

        self.lock.acquire()
        # Calculate the range
        self.rstart = struct.unpack("!4B", ip_range_start)[3]
        self.rend = struct.unpack("!4B", ip_range_end)[3]
        if self.rend > self.rstart:
            self.ip_bitarray = bitarray(self.rend - self.rstart)
            self.ip_bitarray.setall(0)
        else:
            self.lock.release()
            raise VrfError("Invalid range %s - %s" % (self.ip_range_start, self.ip_range_end))
        print ("VRF Created: [")
        print ("Server IP: " + socket.inet_ntoa(self.server_ip))
        print ("Netmask: " + socket.inet_ntoa(self.netmask))
        print ("Range Start: " + socket.inet_ntoa(self.ip_range_start))
        print ("Range End: " + socket.inet_ntoa(self.ip_range_end))
        print ("Server MAC: " +  ':'.join(['%02x' % ord(char) for char in self.server_mac]) )
        print ("DNS1: " + socket.inet_ntoa(self.dns1_ip))
        print ("DNS2: " + socket.inet_ntoa(self.dns2_ip))
        print ("Broadcast IP: " + socket.inet_ntoa(self.broadcast_ip))
        print ("Domian Name: " + self.domain_name + "]")

        # Add server ARP entry
        self.arp_tables.update({server_ip : server_mac})
        self.lock.release()

    def NewLease(self, client_mac):
        try:
            self.lock.acquire()
            ip_bit = self.ip_bitarray.index(0, 0, self.rend - self.rstart)
            ip_last_octet = self.rstart + ip_bit
            ip = ".".join([str(x) for x in struct.unpack("!4B", self.ip_range_start)[0:3]]) + "." + str(ip_last_octet)          
            self.ip_bitarray[ip_bit] = 1
            self.lock.release()
            lease = IpLease(ip, client_mac)
            lease.client_mac = client_mac
            lease.dynamic = True
            self.leases.update({ip_last_octet : lease})
            print ("Allocated a new IP: %s\n" % ip)
            return ip
        except ValueError as e:
            print GetExceptionInfo()
            return None

    def StaticLease(self, ip, client_mac):
        try:
            self.lock.acquire()
            ip_last_octet = ip & 0xff
            ip_bit = ip_last_octet - self.rstart
            try:
                self.ip_bitarray.index(0, ip_bit)
            except Exception as e:
                return False
            ip = ".".join([str(x) for x in struct.unpack("!4B", self.ip_range_start)[0:3]]) + "." + str(ip_last_octet)          
            self.ip_bitarray[ip_bit] = 1
            self.lock.release()
            lease = IpLease(ip, client_mac, False, 86400)
            lease.client_mac = client_mac
            lease.dynamic = False
            self.leases.update({ip_last_octet : lease})
            return True

        except ValueError as e:
            print GetExceptionInfo()
            return None

    def ReleaseLease(self, ip):
        ip_last_octet = int(ip.split(".")[3])
        self.lock.acquire()
        self.leases.update({ip_last_octet : None})
        self.ip_bitarray[ip_last_octet - self.rstart] = 0
        self.lock.release()

    def CheckLease(self, ipint, macstr):
        ret = False
        self.lock.acquire()
        if (ipint & 0xff) in self.leases and self.leases[ipint & 0xff].client_mac == macstr:
            ret = True
        self.lock.release()
        return ret

# We dont need timer based flush mechanism here, if a VM (with a HW address) is given a new l3 address.
# then we would get a notification from controller about deletion of VM. which would result into deletion
# of entry from arp table.
    def AddArpEntry(self, ha, pa):
        self.lock.acquire()
        if ha not in self.arp_tables:
            # Add the entry
            self.arp_tables.update({pa : ha})
        self.lock.release()
        
    def DelArpEntry(self, ha, pa):
        self.lock.acquire()
        if ha in self.arp_tables:
            self.arp_tables.pop(pa, None)
        self.lock.release()

    # get ARP details for a HW
    def GetArpL3Address(self, pa):
        ha = None
        self.lock.acquire()
        if pa in self.arp_tables:
            ha = self.arp_tables[pa]
        self.lock.release()
        return ha

# -----------------------------------------------------------------------------
# DHCP Handler
# -----------------------------------------------------------------------------
class BroadcastRequestHandler(SocketServer.BaseRequestHandler):
    # Got one DHCP Request from a client
    def handle(self):
        while True:
            self.rdata = self.request.recv(2048).strip()
            if len(self.rdata) == 0:
                return

            self.data = self.rdata[1:len(self.rdata)]

            self.vrf_no = int(self.rdata[0], 16)
            
            if self.vrf_no not in VRFS:
                print ("VRF does not exists")
                return
            
            try:
                self.ParseBroadcastRequest()
            except Exception as e:
                print ("Error ocurred: %s" % GetExceptionInfo())
                # Let the other sidde continue
                self.request.sendall("*")

    def GetDhcpOption(self, code):
        for opt in self.dhcp.opts:
            if opt[0] == code:
                return opt[1]
        return None

    def ParseBroadcastRequest(self):
        self.eth = dpkt.ethernet.Ethernet(self.data)

        # Is it arp packet?
        if self.eth.type == dpkt.ethernet.ETH_TYPE_ARP:
            self.reply = self.HandleArpRequest()

        # DHCP Requests
        elif self.eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = self.eth.data
            udp = ip.data
            if udp.dport == 67 and udp.sport == 68:
                self.dhcp = dpkt.dhcp.DHCP(udp.data)

                # DHCP Discover request
                if self.dhcp.op == dpkt.dhcp.DHCP_OP_REQUEST:
                    # Read the 53 byte
                    mstype = map(ord,self.GetDhcpOption(dpkt.dhcp.DHCP_OPT_MSGTYPE))[0]
                    if  mstype == dpkt.dhcp.DHCPDISCOVER:
                        self.reply = self.DhcpHandleDiscoverRequest()
                    if mstype == dpkt.dhcp.DHCPREQUEST:
                        self.reply = self.DhcpHandleRequestRequest()

            else:
                raise NotADhcpPacketError("Not a DHCP Packet")

        if self.reply:
            self.request.sendall(self.reply)
            self.reply = None

    def Str2Mac(self, mac_str):
        return int(mac_str.replace(':', ''), 16)

# =============================================================================
# ARP Support
    def HandleArpRequest(self):
        arp = self.eth.data
        vrf = VRFS[self.vrf_no]
        if arp.hrd == dpkt.arp.ARP_HRD_ETH and arp.pro == dpkt.arp.ARP_PRO_IP:
            # No reverse ARP support
            if arp.op == dpkt.arp.ARP_OP_REQUEST:
                vrf.AddArpEntry(arp.sha, arp.spa)
                tha = vrf.GetArpL3Address(arp.tpa)

                # Make ARP reply
                arp = dpkt.arp.ARP (
                    op = dpkt.arp.ARP_OP_REPLY,
                    sha = tha,
                    spa = arp.tpa,
                    tha = arp.sha,
                    tpa = arp.spa
                )

                # Make the eth frame
                dst_mac = self.eth.src
                src_mac = vrf.server_mac
                eth = dpkt.ethernet.Ethernet(
                    dst = dst_mac,
                    src = src_mac,
                    data = arp,
                    type = dpkt.ethernet.ETH_TYPE_ARP
                )

                # Send the data back to socket
                print ("[ARP Reply sent successfully]")
                return str(eth)



# =============================================================================
# DHCP Support
    def DhcpHandleDiscoverRequest(self):
        client_mac = self.dhcp.chaddr
        xid = self.dhcp.xid
        vrf = VRFS[self.vrf_no]
        your_ip = DottedIP2Int(vrf.NewLease(client_mac)) 
        server_ip = vrf.server_ip
        dnsserver1 = vrf.dns1_ip
        dnsserver2 = vrf.dns2_ip
        netmask = vrf.netmask
        lease_time = Int2HexString(86400)
        renew_time = Int2HexString(86400)
        broadcast = (self.dhcp.flags & 0x80)
        server_mac = vrf.server_mac 

        # Log the request
        print ("[Got one Discover request from client %s]" % Mac2Str(client_mac))
        # Make a new reply packet
        reply = dpkt.dhcp.DHCP (
                chaddr = client_mac,
                xid = xid,
                op = dpkt.dhcp.DHCP_OP_REPLY,
                yiaddr = your_ip,
                opts = (
                    (dpkt.dhcp.DHCP_OPT_MSGTYPE, chr(dpkt.dhcp.DHCPOFFER)),
                    (dpkt.dhcp.DHCP_OPT_NETMASK, netmask),
                    (dpkt.dhcp.DHCP_OPT_RENEWTIME, renew_time),
                    (dpkt.dhcp.DHCP_OPT_REBINDTIME, renew_time),
                    (dpkt.dhcp.DHCP_OPT_LEASE_SEC, lease_time),
                    (dpkt.dhcp.DHCP_OPT_SERVER_ID, server_ip),
                    (dpkt.dhcp.DHCP_OPT_ROUTER, server_ip),
                    (dpkt.dhcp.DHCP_OPT_DNS_SVRS, dnsserver1 + dnsserver2 ),
                )
            )
        # Make a UDP packet
        udp = dpkt.udp.UDP(sport = 67, dport = 68, data = reply)
        udp.ulen = len(udp)

        # Build IP packet
        ip_dst = Int2HexString(your_ip)
        ip_src = server_ip
        if broadcast:
            ip_dst = Int2HexString(DottedIP2Int("255.255.255.255"))
        ip = dpkt.ip.IP(
                dst = ip_dst,
                src = ip_src,
                data = udp,
                p = dpkt.ip.IP_PROTO_UDP,
            )
        ip.len = len(ip)

        # Make ethernet frame
        dst_mac = client_mac
        if broadcast:
            dst_mac = "\xff\xff\xff\xff\xff\xff"
        src_mac = server_mac

        eth = dpkt.ethernet.Ethernet(
                dst = dst_mac,
                src = src_mac,
                data = ip
            )

        # Send the data back to socket
        print ("[Reply sent successfully]")
        return str(eth)

    def DhcpHandleRequestRequest(self):
        client_mac = self.dhcp.chaddr
        xid = self.dhcp.xid
        vrf = VRFS[self.vrf_no]
        your_ip = HexString2Int(self.GetDhcpOption(dpkt.dhcp.DHCP_OPT_REQ_IP))
        server_ip = vrf.server_ip
        dnsserver1 = vrf.dns1_ip
        dnsserver2 = vrf.dns2_ip
        netmask = vrf.netmask
        lease_time = Int2HexString(86400)
        renew_time = Int2HexString(86400)
        broadcast = (self.dhcp.flags & 0x80)
        server_mac = vrf.server_mac 

        # Check for valid IP
        server_ip_int = HexString2Int(server_ip)
        netmask_int = HexString2Int(netmask)

        # Log the request
        print ("[Got one Request request from client %s %s]" % (Int2DottedIP(your_ip), Mac2Str(client_mac)))

        if (server_ip_int & netmask_int) != (your_ip & netmask_int) or not vrf.CheckLease(your_ip, client_mac):
            print ("Error: requested IP " + Int2DottedIP(your_ip) + " does not match the alloted IP")
            # Make a new reply packet
            reply = dpkt.dhcp.DHCP(
                    chaddr = client_mac,
                    xid = xid,
                    op = dpkt.dhcp.DHCP_OP_REPLY,
                    yiaddr = your_ip,
                    opts = (
                        (dpkt.dhcp.DHCP_OPT_MSGTYPE, chr(dpkt.dhcp.DHCPNAK)),
                        (dpkt.dhcp.DHCP_OPT_NETMASK, netmask),
                        (dpkt.dhcp.DHCP_OPT_RENEWTIME, renew_time),
                        (dpkt.dhcp.DHCP_OPT_REBINDTIME, renew_time),
                        (dpkt.dhcp.DHCP_OPT_LEASE_SEC, lease_time),
                        (dpkt.dhcp.DHCP_OPT_SERVER_ID, server_ip),
                    )
                )
        else:
            # Make a new reply packet
            reply = dpkt.dhcp.DHCP(
                    chaddr = client_mac,
                    xid = xid,
                    op = dpkt.dhcp.DHCP_OP_REPLY,
                    yiaddr = your_ip,
                    opts = (
                        (dpkt.dhcp.DHCP_OPT_MSGTYPE, chr(dpkt.dhcp.DHCPACK)),
                        (dpkt.dhcp.DHCP_OPT_NETMASK, netmask),
                        (dpkt.dhcp.DHCP_OPT_RENEWTIME, renew_time),
                        (dpkt.dhcp.DHCP_OPT_REBINDTIME, renew_time),
                        (dpkt.dhcp.DHCP_OPT_LEASE_SEC, lease_time),
                        (dpkt.dhcp.DHCP_OPT_SERVER_ID, server_ip),
                    )
                )

        # Make a UDP packet
        udp = dpkt.udp.UDP(dport = 68, sport = 67, data = reply)
        udp.ulen = len(udp)

        # Build IP packet
        ip_dst = Int2HexString(your_ip)
        ip_src = server_ip
        if broadcast:
            ip_dst = Int2HexString(DottedIP2Int("255.255.255.255"))
        ip = dpkt.ip.IP(
                dst = ip_dst,
                src = ip_src,
                data = udp,
                p = dpkt.ip.IP_PROTO_UDP,
            )
        ip.len = len(ip)

        # Make ethernet frame
        dst_mac = client_mac
        if broadcast:
            dst_mac = "\xff\xff\xff\xff\xff\xff"
        src_mac = server_mac

        eth = dpkt.ethernet.Ethernet(
                dst = dst_mac,
                src = src_mac,
                data = ip
            )

        # Send the data back to socket
        print ("[ACK sent successfully]")
        return str(eth)

if __name__ == "__main__":
    SocketServer.UnixStreamServer.allow_reuse_address = True

    dhcpd_server_address = sys.argv[1] + "dhcpd.socket"
    os.unlink(dhcpd_server_address)
    print ("Satrting DHCPD on " + dhcpd_server_address)
    dhcpd_server = SocketServer.UnixStreamServer(dhcpd_server_address, BroadcastRequestHandler)
    dhcpd_thread = threading.Thread(target=dhcpd_server.serve_forever)
    dhcpd_thread.daemon = True
    dhcpd_thread.start()

    # Start Dynamic Config server
    config_server_address = sys.argv[1] + "dhcp-config.socket"
    os.unlink(config_server_address)
    print ("Satrting CONFIG on " + config_server_address)
    config_server = SocketServer.UnixStreamServer(config_server_address, ConfigRequestHandler)
    config_server.serve_forever()

