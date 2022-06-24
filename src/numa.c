
#include <rte_lcore.h>
#include <rte_memory.h>
#include <rte_malloc.h>

#define MAX_LSOCKS 20

struct lsock {
	int socket_id;
	volatile bool should_stop;
};

struct lsock *lsocks[MAX_LSOCKS];

volatile bool *get_stopper_for_socket(int socket)
{
	int i;
	for (i = 0; i < MAX_LSOCKS; i++) {
		if (!(lsocks[i] == NULL)) {
			if (lsocks[i]->socket_id == socket) {
				return &lsocks[i]->should_stop;
			} else {
				continue;
			}
		}
		// need to summon a new one
		lsocks[i] =
		    rte_zmalloc_socket("STOPPER", sizeof(struct lsock), 0,
				       socket);
		lsocks[i]->socket_id = socket;
		return &lsocks[i]->should_stop;
	}
	return NULL;
}

void stop_all_sockets()
{
	int i;
	for (i = 0; i < MAX_LSOCKS; i++) {
		if (!(lsocks[i] == NULL)) {
			lsocks[i]->should_stop = true;
		}
	}
}

int get_core_on_socket(int socket)
{
	unsigned core;

	RTE_LCORE_FOREACH_WORKER(core) {
		enum rte_lcore_state_t status = rte_eal_get_lcore_state(core);
		if ((status == WAIT) &&
		    ((socket == SOCKET_ID_ANY)
		     || (rte_lcore_to_socket_id(core) == socket))) {
			return core;
		}
	}
	return -1;
}
