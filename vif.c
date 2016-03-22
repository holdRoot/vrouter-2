/* DPDK file */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <sched.h>
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <poll.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dpdk.h"
#include "vif.h"
#include "virtio_rxtx.h"
#include "ipv4.h"

#include <Python.h>


#define NB_VRFS     (64 * 1024) // Support 64k

static PyObject *pName, *pModule;

// Attach a VIF to a vrf
struct vif* vif_add(char* name, uint8_t* ip, uint32_t mask, uint8_t* macaddr,
    uint32_t label, char* path, uint32_t cpus, int cpusets[])
{
    unsigned i;
    struct vif* vif = (struct vif*) malloc (sizeof(struct vif));
    if (!vif) {
        log_crit("Failed to allocated memory for vif struct (%s)\n", name);
        return NULL;
    }

    strcpy(vif->name, name);
    vif->label = label;
    vif->mask = mask;
    memcpy(vif->ip, ip, 4);
    memcpy(vif->macaddr, macaddr, 6);
    strcpy(vif->path, path);
    rte_atomic64_clear(&vif->rx_packets);
    rte_atomic64_clear(&vif->tx_packets);
    rte_atomic64_clear(&vif->dropped_packets);
    rte_atomic64_clear(&vif->error_packets);

    vif->cpus = cpus;
    for (i = 0; i < cpus; i++) {
        vif->cpusets[i] = cpusets[i];
    }

    vif->lldev = NULL;

    // Add route to this VM in VRF/RIB.
    vif->nh.data = vif;
    vif->nh.fn = virtio_tx_packet;
    ipv4_route_add(label, ip, &vif->nh);

    /* Create VHOST-User socket */
    unlink(vif->path);
    if (rte_vhost_driver_register(vif->path) < 0) {
        free(vif);
        return NULL;
    }

    log_crit("%s vif added to the system\n", name);
    return vif;
}

// detach a VIF from a vrf
void vif_del(struct vif* vif)
{
    ipv4_route_del(vif->label, vif->ip);
    rte_vhost_driver_unregister(vif->path);
    free(vif);
}

/* Python bindings */
static inline uint32_t string_to_uint32(uint8_t *intStr)
{
    return (uint32_t)( (intStr[0] << 24) |
                       (intStr[1] << 16) |
                       (intStr[2] << 8)  |
                       intStr[3]);
}

static PyObject* vifdb_add_notify(CC_UNUSED PyObject* self, PyObject* args)
{
    char *name;
    uint8_t *ip;
    uint8_t *mask;
    uint8_t *macaddr;
    uint8_t *label;
    char *path;
    uint8_t *cpus;
    int cpuset[32];
    uint8_t *pCpuset;
    unsigned i;
    struct vif* vifp;
    PyObject* obj;

    obj = PyTuple_GetItem(args, 0);
    name = PyString_AsString(obj);
    obj = PyTuple_GetItem(args, 1);
    ip = (uint8_t*)PyString_AsString(obj);
    obj = PyTuple_GetItem(args, 2);
    mask = (uint8_t*)PyString_AsString(obj);
    obj = PyTuple_GetItem(args, 3);
    macaddr = (uint8_t*)PyString_AsString(obj);
    obj = PyTuple_GetItem(args, 4);
    label = (uint8_t*)PyString_AsString(obj);
    obj = PyTuple_GetItem(args, 5);
    path = PyString_AsString(obj);
    obj = PyTuple_GetItem(args, 6);
    cpus = (uint8_t*)PyString_AsString(obj);
    obj = PyTuple_GetItem(args, 7);
    pCpuset = (uint8_t*)PyString_AsString(obj);

    // Parse the cpsets
    for (i = 0; i < *cpus; i++) {
        cpuset[i] = (int)pCpuset[i];
    }

    printf ("vif_add called: [\n");
    printf ("\tName: %s\n", name);
    printf ("\tIP: %x\n", string_to_uint32(ip) );
    printf ("\tMask: %x\n", string_to_uint32(mask));
    printf ("\tLabel: %x\n", string_to_uint32(label));
    printf ("\tCpus: %x\n", string_to_uint32(cpus));
    printf ("\tPath: %s]\n", path);

    Py_DECREF(args);

    // Call C vif_add
    vifp = vif_add(name, ip, string_to_uint32(mask), macaddr, \
                        string_to_uint32(label), path, *cpus, cpuset);
    if (!vifp)
        Py_RETURN_NONE;

    return PyCObject_FromVoidPtr(vifp, NULL);
}

static PyObject* vifdb_del_notify(CC_UNUSED PyObject* self, PyObject* args)
{
    struct vif* vifp = (struct vif*) PyCObject_AsVoidPtr(args);
    Py_DECREF(args);
    if (vifp != NULL) {
        vif_del(vifp);
    }
    Py_RETURN_NONE;
}

static struct PyMethodDef vifdb_notify_methods[] = {
    { "add_notify", vifdb_add_notify, METH_VARARGS,
        "Notify when a vif is added to system"},
    { "del_notify", vifdb_del_notify, METH_VARARGS,
        "Notify when a vif is deleted from system"},
    { NULL, NULL, 0, NULL }
};

static void PyInit_vifdb_notify(void)
{
    Py_InitModule3("vifdb_notify", vifdb_notify_methods, "VIFDB Notify Helper");
}

int vif_init(int nb_lcores)
{
    PyObject *pFunc;
    PyObject *pArgs, *pValue;

    // Launc threads for each lcore/queue.
    if (ipv4_route_init(NB_VRFS)) {
        log_crit("ipv4_route_init failed\n");
        return -1;
    }

    pName = PyString_FromString("vifdb");

    PyImport_AppendInittab("vifdb_notify", PyInit_vifdb_notify);

    // Import the vif_db.py
    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, "vifdb_init");
        if (pFunc && PyCallable_Check(pFunc)) {
            pArgs = PyTuple_New(1);
            pValue = PyInt_FromLong(nb_lcores);
            PyTuple_SetItem(pArgs, 0, pValue);

            pValue = PyObject_CallObject(pFunc, pArgs);
            Py_DECREF(pArgs);
            if (PyInt_AsLong(pValue) != 1) {
                log_crit("vifdb_init (python) failed\n");
                return -1;
            }
        }
    }
    else {
        PyErr_Print();
        log_crit("Failed to load \'vifdb\' module\n");
        return -1;
    }

    return 0;
}

void vif_exit(void)
{
}

struct vif* vif_find_entry(char *path)
{
    PyObject *pFunc;
    PyObject *pArgs, *pValue;

    pFunc = PyObject_GetAttrString(pModule, "vifdb_find");
    if (pFunc && PyCallable_Check(pFunc)) {
        pArgs = PyTuple_New(1);
        pValue = PyString_FromString(path);
        PyTuple_SetItem(pArgs, 0, pValue);

        pValue = PyObject_CallObject(pFunc, pArgs);
        Py_DECREF(pArgs);
        if (PyCObject_AsVoidPtr(pValue) == NULL) {
            log_crit("vifdb_init (python) failed\n");
            return NULL;
        }
        return PyCObject_AsVoidPtr(pValue);
    }

    return NULL;
}

