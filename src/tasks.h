#ifndef DPDKCAP_TASKS_H
#define DPDKCAP_TASKS_H

#include <sys/types.h>
#include <sys/stat.h>

#include <rte_bpf.h>
#include <rte_errno.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

#define DPDKCAP_MAX_PATH_LEN 1024
#define DPDKCAP_MAX_FILE_LEN 256

#define DPDKCAP_MAX_BPF_LEN 1024

#define DPDKCAP_MAX_TASKS_PER_DIR 16

#define DPDKCAP_OUTPUT_TEMPLATE_TOKEN_FILECOUNT "\%FCOUNT"
#define DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID   "\%COREID"
#define DPDKCAP_OUTPUT_TEMPLATE_DEFAULT "output_" \
	  DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID

#define DPDKCAP_OUTPUT_TEMPLATE_LENGTH 2 * DPDKCAP_OUTPUT_FILENAME_LENGTH

enum task_state_t {
	TASK_UNUSED,
	TASK_INACTIVE,
	TASK_ACTIVE,
};

// TODO shuffle struct members for cache alignment

struct task {
	enum task_state_t task_state;
	time_t task_seen;

	char task_filename[DPDKCAP_MAX_FILE_LEN];
	time_t task_mtime;
	size_t task_size;

	char output_template[DPDKCAP_MAX_PATH_LEN];
	int output_rotate_seconds;
	size_t output_rotate_size;

	char output_filename[DPDKCAP_MAX_PATH_LEN];
	void *output_buffer;
	struct timeval output_tstamp;
	size_t output_size;
	int output_count;

	char bpf_str[DPDKCAP_MAX_BPF_LEN];
	struct rte_bpf *bpf;
	int snaplen;
	int compression;
	int sampling;
};

struct taskdir {
	time_t lastscan;
	int interval;

	char dirname[DPDKCAP_MAX_PATH_LEN];

	struct task tasks[DPDKCAP_MAX_TASKS_PER_DIR];
};

void scan_by_fd(int dirfd, void (*cb)(char *, int, struct stat *, void *),
		void *cbd);
void scan_by_name(char *dirname, void (*cb)(char *, int, struct stat *, void *),
		  void *cbd);

void check_scan_taskdir(struct taskdir *td, int now);

#endif
