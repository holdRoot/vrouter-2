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
#include <unistd.h>
#include <sys/un.h>

#include "dpdk.h"
#include "vif.h"
#include "virtio_rxtx.h"
#include "ipv4.h"

#include <Python.h>

static PyObject *pName, *pModule;

// Attach a VIF to a vrf
struct vif* vif_add(char* name, uint8_t* ip, uint8_t mask, uint8_t* macaddr,
    uint32_t label, char* path, int cpus, int cpusets[])
{
    int i;
    struct vif* vif = (struct vif*) malloc (sizeof(struct vif));
    if (!vif) {
        log_crit("Failed to allocated memory for vif struct (%s)\n", name);
        return NULL;
    }

    strcpy(vif->name, name);
    vif->label = label;
    vif->mask = mask;
    memcpy(vif->ip, ip, 4);
    memcpy(vif->macaddr, macaddr, 4);
    strcpy(vif->path, path);
    rte_atomic64_clear(&vif->rx_packets);
    rte_atomic64_clear(&vif->tx_packets);
    rte_atomic64_clear(&vif->dropped_packets);
    rte_atomic64_clear(&vif->error_packets);

    vif->cpus = cpus;
    for (i = 0; i < cpus; i++) {
        CPU_ZERO(&vif->cpusets[i]);
        CPU_SET(cpusets[i], &vif->cpusets[i]);
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
static PyObject* vifdb_add_notify(CC_UNUSED PyObject* self, PyObject* args)
{
    char *name;
    uint8_t *ip;
    uint8_t mask;
    uint8_t *macaddr;
    uint32_t label;
    char *path;
    int cpus;
    int cpuset[32];
    PyObject *pCpuset;
    int i;
    struct vif* vifp;

    if (!PyArg_ParseTuple(args, "ssIsIsio", &name, &ip, &mask,
        &macaddr, &label, &path, &cpus, &pCpuset)) {
        Py_RETURN_NONE;
    }

    // Parse the cpsets
    for (i = 0; i < cpus; i++) {
        PyObject *obj = PyTuple_GetItem(pCpuset, (Py_ssize_t)i);
        if (!obj) {
            Py_RETURN_NONE;
        }
        cpuset[i] = (int) PyInt_AsLong(obj);
        Py_DECREF(obj);
    }

    Py_DECREF(args);

    // Call C vif_add
    vifp = vif_add(name, ip, mask, macaddr, label, path, cpus, cpuset);
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
    Py_InitModule("vifdb_notfy", vifdb_notify_methods);
}

int vif_init(int nb_lcores)
{
    PyObject *pFunc;
    PyObject *pArgs, *pValue;

    Py_Initialize();
    PyImport_AppendInittab("vifdb_notify", &PyInit_vifdb_notify);

    pName = PyString_FromString("./scripts/vifdb.py");

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
        log_crit("Failed to load ./script/vifdb.py file\n");
    }

    return 0;
}