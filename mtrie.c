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
    mtrie->ops_root = NULL;
    return 0;
}

// Stores the ops data in a stack
static int mtrie_ops_stack_push(mtrie_t* mtrie, mtrie_node_t** address, mtrie_node_t* value, mtrie_node_t* node, void *data)
{
    struct mtrie_ops_stack_node *onode = MALLOC(struct mtrie_ops_stack_node);
    if (!onode)
        return -EAGAIN;

    onode->address = address;
    onode->node = node;
    onode->value = value;
    onode->data = data;
    onode->next = mtrie->ops_root;
    mtrie->ops_root = onode;

    return 0;
}

// pops a ops data from stack
static struct mtrie_ops_stack_node* mtrie_ops_stack_pop(mtrie_t* mtrie)
{
    struct mtrie_ops_stack_node *onode = NULL;

    if (mtrie->ops_root) {
        onode = mtrie->ops_root;
        mtrie->ops_root = onode->next;
    }

    return onode;
}

// Used in error conditions
#if 0
static void mtrie_ops_stack_free(mtrie_t* mtrie)
{
    struct mtrie_ops_stack_node *onode = NULL;

    while (mtrie->ops_root) {
        onode = mtrie->ops_root->next;
        free(mtrie->ops_root);
        mtrie->ops_root = onode;
    }
}
#endif

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

#if 0 // Uncomment when hard delete logic is added. 
static void free_node(mtrie_node_t* node)
{
    free(node);
}
#endif

int mtrie_add_entry(mtrie_t* mtrie, uint8_t* prefix, int prefixLen, void* data)
{
    int ret = 0;
    int l;
    mtrie_node_t* node;

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
        uint8_t index = prefix[l] & ( (1u << BITS_PER_LEVEL) - 1u);
        mtrie_node_t* tmpNode;

        if (l == mtrie->maxLevel) {
            if (node->childs[index])
                printf("Possible case of route overwrite!");

            tmpNode = get_new_mtrie_leaf_node();
            WARN_ON(tmpNode != NULL);
            tmpNode->data = data;
            mtrie_ops_stack_push(mtrie, &node->childs[index], tmpNode, node, NULL);
        }
        else {
            if (node->childs[index] == NULL) {
                mtrie_node_t* tmpNode = get_new_mtrie_node();
                WARN_ON(tmpNode != NULL);
                mtrie_ops_stack_push(mtrie, &node->childs[index], tmpNode, node, NULL);

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

    // Building in bottom to up fashion, helps in protection from race-conditions.
    // Process the ops stack
    while (mtrie->ops_root) {
        struct mtrie_ops_stack_node* onode = mtrie_ops_stack_pop(mtrie);
        onode->node->numChilds++;
        onode->node->data = onode->data;
        // Let above writes complete from we plug the entry in mtrie.
        __sync_synchronize();
        (*onode->address) = onode->value;
        free(onode);
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
                }
            }
        }
        else {
            index = prefix[level] & ( (1u << BITS_PER_LEVEL) - 1u);
            if (node->childs[index]) {
                ret = __mtrie_del_entry(node->childs[index], maxLevel, level + 1,
                        prefix, prefixLen -= BITS_PER_LEVEL);
                if (ret == NULL)  node->numChilds--;
            }
            else {
                __error("Failed to find the prefix in mtrie table\n");
                goto out;
            }
        }
    }

    if (node->numChilds == 0) {
        node->data = NULL;
        // we actually don't delete the node. we keep it for re-use.
        // Only make the data points to NULL. This we are safe from race-conditions.
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


// Called from fast path (no lock taken)
void* mtrie_lookup(mtrie_t* mtrie, uint8_t* prefix, CC_UNUSED int prefixLen)
{
    mtrie_node_t* node;
    void* data = NULL;
    int l;

    node = mtrie->root;
    for (l = 0; likely(l <= mtrie->maxLevel); l++) {
        uint8_t index = prefix[l] & ( (1u << BITS_PER_LEVEL) - 1u);
        if (likely(node->childs[index] != NULL)) {
            if (likely(node->childs[index]->data != NULL)) {
                data = node->childs[index]->data;
            }
            node = node->childs[index];
        }
        else
            break;
    }

    return data;
}

// TODO: Implement hard delete logic. which deletes the complete trie.