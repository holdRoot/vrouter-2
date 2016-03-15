#ifndef MTRIE_H
#define MTRIE_H

#include "mutex.h"

struct mtrie_node_s;
typedef struct mtrie_node_s mtrie_node_t;

struct mtrie_s {
    struct mutex lock;
    uint8_t maxLevel;
    mtrie_node_t* root;
};

typedef struct mtrie_s mtrie_t;

int mtrie_init(mtrie_t* mtrie, uint8_t maxLevel);
int mtrie_add_entry(mtrie_t* mtrie, uint8_t* prefix, int prefixLen, void* data);
int mtrie_del_entry(mtrie_t* mtrie, uint8_t* prefix, int prefixLen);
void* mtrie_lookup(mtrie_t* mtrie, uint8_t* prefix, int prefixLen);

#endif

