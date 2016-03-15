#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "mtrie.h"
#include "dpdk.h"

#define BITS_PER_LEVEL  8
#define LEVEL_SIZE      (1 << BITS_PER_LEVEL)
#define LEVEL_MASK      (LEVEL_SIZE - 1)
#define CHILD(N,X)      ((mtrie_node_t**) N)[(X)]
#define NODE_SIZE       ( sizeof(mtrie_node_t) + ( sizeof(mtrie_node_t*) * LEVEL_SIZE ) )

#define WARN_ON         assert
#define __error         log_crit

struct mtrie_node_s {
    void* data;
    int numChilds;
    struct mtrie_node_s *childs[0];
};

int mtrie_init(mtrie_t* mtrie, uint8_t maxLevel)
{
    WARN_ON(mtrie != NULL);
    mutex_init(&mtrie->lock);
    mtrie->root = NULL;
    mtrie->maxLevel = maxLevel;
    return 0;
}

static mtrie_node_t* get_new_mtrie_node(void)
{
    mtrie_node_t* node = (mtrie_node_t *) malloc(NODE_SIZE);
    WARN_ON(node != NULL);

    memset(node, 0, NODE_SIZE);
    node->data = NULL;
    node->numChilds = 0;
    return node;
}

static mtrie_node_t* get_new_mtrie_leaf_node(void)
{
    mtrie_node_t* node = (mtrie_node_t *) malloc(sizeof(mtrie_node_t));
    WARN_ON(node != NULL);

    memset(node, 0, sizeof(mtrie_node_t));
    node->data = NULL;
    node->numChilds = 0;
    return node;
}

static void free_node(mtrie_node_t* node)
{
    free(node);
}

int mtrie_add_entry(mtrie_t* mtrie, uint8_t* prefix, int prefixLen, void* data)
{
    int ret = 0;
    int l;
    mtrie_node_t* node;
    // ipv4 has only 4 octects
    mtrie_node_t *store[4];

    WARN_ON(mtrie != NULL);
    WARN_ON(prefixLen >= 0);

    mutex_lock(&mtrie->lock);
    if (!mtrie->root) {
        mtrie->root = get_new_mtrie_node();
        WARN_ON(mtrie->root != NULL);
    }

    /* Since the trie is used by data path and we don't to take a lock for best performance.
     * we build the mtrie from bottom-up way. so that no dangling pointers. */
    node = mtrie->root;
    for (l = 0; l <= mtrie->maxLevel; l++) {
        /* Wildcard */
        if (BITS_PER_LEVEL > prefixLen) {
            uint8_t index = prefix[l] & ~( (1u << (BITS_PER_LEVEL - prefixLen) ) - 1u);
            int j;

            /* Fill the information for wildcard entries */
            for (j = index; j < LEVEL_SIZE; j++) {
                if (node->childs[j] == NULL) {
                    if (l == mtrie->maxLevel)
                        node->childs[j] = get_new_mtrie_leaf_node();
                    else
                        node->childs[j] = get_new_mtrie_node();
                    node->numChilds++;
                }

                /* Overwrites existing data */
                node->childs[j]->data = data;
            }

            /* Stop the loop, as all valid and wildcard bits are processed */
            break;
        }
        else {
            uint8_t index = prefix[l] & ( (1u << BITS_PER_LEVEL) - 1u);

            if (l == mtrie->maxLevel) {
                node->childs[index] = get_new_mtrie_leaf_node();
                node->childs[index]->data = data;
                node->numChilds++;
            }
            else {
                if (node->childs[index] == NULL) {
                    mtrie_node_t* tmpNode = get_new_mtrie_node();
                    WARN_ON(tmpNode != NULL);
                    node->numChilds++;
                    node->childs[index] = tmpNode;
                    node = tmpNode;
                }
                else {
                    node = node->childs[index];
                }

                prefixLen -= BITS_PER_LEVEL;

                /* prefixLen is multiple of BITS_PER_LEVEL */
                if (prefixLen == 0) {
                    node->data = data;
                    break;
                }
            }
        }
    }
        
    mutex_unlock(&mtrie->lock);

    return ret;
}

static mtrie_node_t* __mtrie_del_entry(mtrie_node_t* node, int maxLevel, int level, 
    uint8_t* prefix, int prefixLen)
{
    mtrie_node_t* ret;
    uint8_t index;

    if (level <= maxLevel) {
        if (prefixLen < BITS_PER_LEVEL) {
            int j;

            index = prefix[level] & ~( (1u << (BITS_PER_LEVEL - prefixLen) ) - 1u);
            j = index;

            for ( ; j < LEVEL_SIZE; j++) {
                if (node->childs[j]) {
                    /* recurse into the next level of entries */
                    ret = __mtrie_del_entry(node->childs[j], maxLevel, level + 1, prefix, 0);
                    if (ret == NULL)  node->numChilds--;
                    node->childs[j] = ret;
                }
            }
        }
        else {
            index = prefix[level] & ( (1u << BITS_PER_LEVEL) - 1u);
            if (node->childs[index]) {
                ret = __mtrie_del_entry(node->childs[index], maxLevel, level + 1,
                        prefix, prefixLen -= BITS_PER_LEVEL);
                if (ret == NULL)  node->numChilds--;
                node->childs[index] = ret;
            }
            else {
                __error("Failed to find the prefix in mtrie table\n");
                goto out;
            }
        }
    }

    if (node->numChilds == 0) {
        free_node(node);
        return NULL;
    }

out:
    return node;
}

int mtrie_del_entry(mtrie_t* mtrie, uint8_t* prefix, int prefixLen)
{
    int ret = 0;

    WARN_ON(mtrie != NULL);
    WARN_ON(prefixLen >= 0);

    mutex_lock(&mtrie->lock);

    if (mtrie->root == NULL) {
        ret = -1;
        goto out;
    }

    mtrie->root = __mtrie_del_entry(mtrie->root, mtrie->maxLevel, 0, 
                        prefix, prefixLen);
out:
    mutex_unlock(&mtrie->lock);

    return ret;
}

void* mtrie_lookup(mtrie_t* mtrie, uint8_t* prefix, int prefixLen)
{
    int l;
    mtrie_node_t* node;
    void* data = NULL;

    WARN_ON(mtrie != NULL);
    WARN_ON(prefixLen >= 0);

    mutex_lock(&mtrie->lock);

    if (mtrie->root == NULL) {
        goto out;
    }

    node = mtrie->root;
    for (l = 0; l <= mtrie->maxLevel; l++) {
        uint8_t index = prefix[l] & ( (1u << BITS_PER_LEVEL) - 1u);
        if (node->childs[index]) {
            if (node->childs[index]->data != NULL) {
                data = node->childs[index]->data;
            }
            node = node->childs[index];
        }
        else
            break;
    }

out:
    mutex_unlock(&mtrie->lock);

    return data;
}

