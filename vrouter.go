package main

import "fmt"
import "unsafe"
import "strings"
import "sync"
import "net"

/*

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "dpdk.h"

static int64_t ffz(uint64_t word)
{
	if (word == ~0UL)
		return -1;
	asm("rep; bsf %1, %0"
	    : "=r"(word)
	    : "r"(~word));
	return word;
}

#cgo CFLAGS: -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2 -DRTE_COMPILE_TIME_CPUFLAGS=RTE_CPUFLAG_SSE,RTE_CPUFLAG_SSE2,RTE_CPUFLAG_SSE3,RTE_CPUFLAG_SSSE3,RTE_CPUFLAG_SSE4_1,RTE_CPUFLAG_SSE4_2,RTE_CPUFLAG_AES,RTE_CPUFLAG_PCLMULQDQ,RTE_CPUFLAG_AVX,RTE_CPUFLAG_RDRAND,RTE_CPUFLAG_FSGSBASE,RTE_CPUFLAG_F16C,RTE_CPUFLAG_AVX2 -I/home/user/dpdk_install/share/dpdk/x86_64-native-linuxapp-gcc/include -include /home/user/dpdk_install/share/dpdk/x86_64-native-linuxapp-gcc/include/rte_config.h

#cgo LDFLAGS: -L. -ldpdk -Wl,--no-as-needed -export-dynamic -L/home/user/dpdk_install/share/dpdk//x86_64-native-linuxapp-gcc/lib  -L/home/user/dpdk_install/share/dpdk//x86_64-native-linuxapp     -gcc/lib -Wl,--whole-archive -lrte_distributor -lrte_reorder -lrte_kni -lrte_pipeline -lrte_table -lrte_port -lrte_timer -lrte_hash -lrte_jobstats -lrte_lpm -lrte_power -lrte_acl -lrte_meter -lrte_sched -lm -lrt -lrte_vhost -Wl,--start-group -lrte_kvargs -lrte_mbuf -lrte_mbuf_offload -lrte_ip_frag -lethdev -lrte_cryptodev -lrte_mempool -lrte_ring -lrte_eal -lrte_cmdline -lrte_cfgfile -lrte_pmd_bond -lrte_pmd_vmxnet3_uio -lrte_pmd_virtio -lrte_pmd_cxgbe -lrte_pmd_enic -lrte_pmd_i40e -lrte_pmd_fm10k -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring -lrte_pmd_af_packet -lrte_pmd_null -lrt -lm -ldl -Wl,--end-group -Wl,--no-whole-archive -lpthread

*/
import "C"

// Path where vhost user socket are created 
const VrouterVarPath = "/var/run/vrouter/"

// Number of Virtual Routing Instances
const NbVrfEntries = 64 * 1024

/* -------------------------------------------------------------------------
 *  Bitmap support
 * -------------------------------------------------------------------------
 */
type Bits uint64

// Size of uint64
const BitSize = 64

// BitSet is a set of bits that can be set, cleared and queried.
type BitSet []Bits

func (s *BitSet) Set(i uint) {
	if len(*s) < int(i / BitSize + 1) {
		fmt.Printf("%d is beyond the size of bitmap(%d)\n", i, 64 * len(*s));
		return
	}
	(*s)[i / BitSize] |= (1 << (i % BitSize))
}

func (s *BitSet) Clear(i uint) {
	if len(*s) < int(i / BitSize + 1) {
		fmt.Printf("%d is beyond the size of bitmap(%d)\n", i, 64 * len(*s));
		return
	}
	(*s)[i / BitSize] &^= (1 << (i % BitSize))
}

// Find first zero bit in the bitnmap
func (s *BitSet) FFZ() (bit int) {
	nbits := len(*s) * 64
	i := 0
	for i < (nbits) {
		bit = int( C.ffz( C.uint64_t( (*s)[i / BitSize]) ) )
		if (bit != -1) {
			return
		}
		i += 64
	}

	bit = -1
	return
}

// Initialize the bitmap of said size
func (s *BitSet) Init(size uint) {
	*s = make([]Bits, (size / BitSize + 1))
}

/* -------------------------------------------------------------------------
 *  Event handler
 * -------------------------------------------------------------------------
 */
type EventHandlerList [](*BitSet)
type EventHandleMap map[uint](unsafe.Pointer)
type EventHandleMapList []EventHandleMap

const EventHandlerListSize = 64 * 1024

// Global List of even handlers
type EventHandler struct {
	gList *EventHandlerList
	gHandles *EventHandleMapList
}

// Global event handler object
var G_EventHandler EventHandler

// Initialize the event handle list module
func (evh *EventHandlerList) Init(lcores uint) {
	*evh = make([](*BitSet), lcores)
	for i := 0 ; i < int(lcores); i++ {
		(*evh)[i] = new(BitSet)
		(*evh)[i].Init(EventHandlerListSize)
        // 0 is reserved for event cmd
        (*evh)[i].Set(0)
	}
}

// Add a new entry to event handle list
func (evh *EventHandlerList) Add(lcore uint) (slot int) {
	slot = (*evh)[lcore].FFZ()
	if (slot != -1) {
		(*evh)[lcore].Set(uint(slot))
	}
	return
}

// Delete a entry from event handle list
func (evh *EventHandlerList) Del(lcore uint, slot int) {
	if (slot != -1) {
		(*evh)[lcore].Clear(uint(slot))
	}
	return
}

// Event handler map init
func (emap *EventHandleMapList) Init(lcores uint) {
	*emap = make([]EventHandleMap, lcores)
	for i := 0; i < int(lcores); i++ {
		(*emap)[i] = make(EventHandleMap)
	}
}

// Add entry to map
func (emap *EventHandleMapList) Add(lcore uint, slot uint, data unsafe.Pointer) {
	(*emap)[lcore][slot] = data
}

// Delete entry from map
func (emap *EventHandleMapList) Del(lcore uint, slot uint) {
	(*emap)[lcore][slot] = nil
}

// Event Handle Module init
func EventHandlerInit(lcores uint) {
	G_EventHandler.gList = new(EventHandlerList)
	G_EventHandler.gHandles = new(EventHandleMapList)

	G_EventHandler.gList.Init(lcores)
	G_EventHandler.gHandles.Init(lcores)
}

//export GetFreeSlot
func GetFreeSlot(lcore uint, data unsafe.Pointer) (slot int) {
	slot = G_EventHandler.gList.Add(lcore)
	if (slot != -1){
		G_EventHandler.gHandles.Add(lcore, uint(slot), data)
	}
	return
}

//export DeleteSlot
func DeleteSlot(lcore uint, slot int) {
	G_EventHandler.gList.Del(lcore, slot)
	G_EventHandler.gHandles.Del(lcore, uint(slot))
}

/* -------------------------------------------------------------------------
 *  VIF management
 * -------------------------------------------------------------------------
 */
type Vif struct {
	name     string
	ip       [4]byte
	mac_addr [6]byte
	mask     byte
	label    uint32
	path     string
	cpusets  []int32
	// Handle to the C VIF struct
	vifp     unsafe.Pointer
}

type VifList map[string](*Vif)

var G_Vif VifList

// Initialize the Vif list
func VifInit(lcores uint) {
	G_Vif = make(map[string](*Vif));
}

// Add a new vif entry
func VifAdd(name string, ip [4]byte, mask byte, macaddr [6]byte, label uint32, cpusets []int32) {
	vif := new(Vif)
	vif.name = name
	vif.ip = ip
	vif.mac_addr = macaddr
	vif.label = label;
	vif.path = fmt.Sprintf("%s/%s", VrouterVarPath, name) 
	vif.cpusets = cpusets
	G_Vif[name] = vif

	// let DPDK engine know about this vif
	G_Vif[name].vifp = unsafe.Pointer(C.vif_add(C.CString(name),
							     (*C.uint8_t)(&ip[0]),
							     C.uint8_t(mask),
								 (*C.uint8_t)(&macaddr[0]), 
								 C.uint32_t(label), 
								 C.CString(vif.path),
								 C.int(len(cpusets)),
								 (*C.int)(unsafe.Pointer(&cpusets[0]))) )
}

// Del a vif entry
func VifDel(name string) {
	if _,ok := G_Vif[name]; ok {
		// let DPDK engine know about this vif
		C.vif_del((*C.struct_vif)(G_Vif[name].vifp))
		G_Vif[name] = nil
	} else {
		fmt.Printf("@@Error: %s named vif not found in Vif database\n", name)
	}
}

func (vif *Vif) ProgramEventHandler(lldev unsafe.Pointer) {
	for i := 0; i < len((*vif).cpusets); i++ {
		// Get slot in the evenhandler list for the lcore.
		slot := GetFreeSlot( uint((*vif).cpusets[i]), unsafe.Pointer(vif))
		if slot != -1 {
			C.event_handler_add(C.int((*vif).cpusets[i]), C.int(i), C.int(slot), (*vif).vifp, unsafe.Pointer(lldev))
		} else {
			fmt.Printf("@@Error: failed to get a free slot in the event handler list for %d core\n", (*vif).cpusets[i])
		}
	}
}

//export VifFind
func VifFind(path string, lldev unsafe.Pointer) (unsafe.Pointer) {
	tokens := strings.Split(path, "/")
	// Last token is the name of vif
	vif_name := tokens[len(tokens) - 1]
	if _,ok := G_Vif[vif_name]; ok {
		G_Vif[vif_name].ProgramEventHandler(lldev)
		return G_Vif[vif_name].vifp
	}
	return nil
}

// Used for signalling completion of dodk_init
var DpdkInit_Sync sync.WaitGroup

// Initialize the DPDK engines.
// Call C code, which creates a pthread and run DPDK init code in it.
func dpdk_init() {
	var ret = int(C.dpdk_init())
    fmt.Printf("DPDK: dpdk_main returned with %d\n", ret)
    defer DpdkInit_Sync.Done()
}


//export ProxyPacketHandler
func ProxyPacketHandler(pkt unsafe.Pointer, l C.int) (C.int){
    var buf [512]byte
    pkt_data := C.GoBytes(pkt, l)

    conn, err := net.DialUnix("unix", nil, &net.UnixAddr{"/var/run/vrouter/dhcpd.socket", "unix"})
    if err != nil {
        fmt.Printf("Failed to connect to DHCP server\n")
        return C.int(-1)
    }

    fmt.Printf("[Sending %d bytes to DHCP server]\n", l)

    // Write VRF Label
    conn.Write([]byte{'0'})

    // Write the packets
    conn.Write(pkt_data)

    // Wait for response from DHCP server
    n,err := conn.Read(buf[:])
    if err != nil {
        fmt.Printf("Failed to get response from DHCP server\n")
        conn.Close()
        return C.int(-2)
    }

    // Copy the reponse to RTE buffer
    C.memcpy(pkt, unsafe.Pointer(&buf[0]), C.size_t(n));

    // Close the connection
    conn.Close()

    fmt.Printf("[Received %d bytes]\n", n)
    return C.int(n)
}

func main() {
    // Init dodk
    DpdkInit_Sync.Add(1)
    go dpdk_init()
    DpdkInit_Sync.Wait()

    lcores := C.GetCoreCount()
    fmt.Printf("VROUTER: %d cores found\n", lcores)

    // IPV4 routing
    C.ipv4_route_init(NbVrfEntries)

    // Initialize the event handler module 
    EventHandlerInit(uint(lcores))

    // Initialize the vif module 
	VifInit(uint(lcores))

	cpusets := []int32{0}
	VifAdd("vif-1", [4]byte{192, 168, 1, 9}, 32, [6]byte{ 0xde, 0xad, 0xbe, 0xef, 0x17, 0x3c}, 0, cpusets)
	VifAdd("vif-2", [4]byte{192, 168, 1, 10}, 32, [6]byte{ 0xde, 0xad, 0xbe, 0xef, 0x17, 0x3d}, 0, cpusets)

    var wait sync.WaitGroup

    wait.Add(1)
    wait.Wait()
	VifDel("vif-1")
}

