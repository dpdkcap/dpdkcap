
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "tasks.h"
#include "parse.h"
#include "pcap.h"


#define FLAGS_OPEN_DIR O_RDONLY|O_DIRECTORY
#define FLAGS_OPEN_FILE O_RDONLY
#define FLAGS_STAT 0

#define TASKFILE_SIZE_MAX 8000





void apply_taskkv(char *key, char *val, void* cbd)
{
	struct task* task = (struct task*)cbd;
        printf("TASK payload: k:'%s' v:'%s'\n",key,val);

	if (strcmp(key,"output_template")==0) {
		strncpy(task->output_template,val,DPDKCAP_MAX_PATH_LEN);
	} else if (strcmp(key,"bpf")==0) {
		strncpy(task->bpf_str,val,DPDKCAP_MAX_BPF_LEN);
	} else if (strcmp(key,"rotate_seconds")==0) {
		task->output_rotate_seconds = strtoul(val, NULL, 10);
	} else if (strcmp(key,"rotate_size")==0) {
		task->output_rotate_size = strtoul(val, NULL, 10);
	} else if (strcmp(key,"snaplen")==0) {
		task->snaplen = strtoul(val, NULL, 10);
	} else if (strcmp(key,"sampling")==0) {
		task->sampling = strtoul(val, NULL, 10);
	} else if (strcmp(key,"compression")==0) {
		if (val) {
			task->compression = strtoul(val, NULL, 10);
		} else {
			task->compression = 999;
		}
	} else {
		printf("TASK IGNORE unknown: key='%s', val='%s'\n", key, val);
	}
}




void scan_by_fd(int dirfd, void (*cb)(char*,int,struct stat*,void*), void* cbd)
{
	DIR *dir;
	struct dirent *dent;

	dir = fdopendir(dirfd);   

	if(dir==NULL)
	{
		perror("fdopendir");
		return;
	}

	while((dent=readdir(dir))!=NULL)
	{
//		printf("scan name %s ... ",dent->d_name);

		if (dent->d_name[0]=='.') {
//			printf("dot skip\n");
			continue;
		} 
		int rc, fd;
		struct stat statbuf;

		rc = fstatat(dirfd, dent->d_name, &statbuf, FLAGS_STAT);
		if (rc < 0)
		{
			perror("fstatat");
			continue;
		}


		if (statbuf.st_mode & S_IFDIR)
		{
//			printf("dir skip\n");
			continue;
		}
		else if (!(statbuf.st_mode & S_IFREG))
		{
//			printf("weird skip\n");
			continue;
		}
		

//		printf("reg ... ");
//		printf("size %d ... ", statbuf.st_size);
		if (statbuf.st_size > TASKFILE_SIZE_MAX)
		{
//			printf("toobig skip\n");
			continue;
		}

//		if (dent->d_name[0]!='T') {
//			printf("test skip\n");
//			continue;
//		} 

//		printf("scan name %s ... \n",dent->d_name);

		// XXX TOCTOU potential
		fd = openat(dirfd, dent->d_name, FLAGS_OPEN_FILE);
		if (fd < 0) 
		{
			perror("open");
			continue;
		}

		(*cb)(dent->d_name, fd, &statbuf, cbd);
//		printf("NO PAYLOAD\n");
//		parse_config(fd, statbuf.st_size, &payload);
		close(fd);


//		printf("done\n");
	}
	closedir(dir);
}

void scan_by_name(char *dirname, void (*cb)(char*,int,struct stat*,void*), void* cbd)
{
	int dirfd;
//	printf("dirscan %s ...\n", dirname);
	dirfd = open(dirname, FLAGS_OPEN_DIR);
	if (dirfd < 0) {
		perror("open");
	}
	scan_by_fd(dirfd, cb, cbd);
}

void compile_filter(struct task* task)
{
	struct rte_bpf_prm *bpf_prm = NULL;
        struct bpf_program bf;
        pcap_t *pcap = NULL;

        pcap = pcap_open_dead(DLT_EN10MB, task->snaplen);
        if (!pcap)
                rte_exit(EXIT_FAILURE, "can not open pcap\n");

        if (pcap_compile(pcap, &bf, task->bpf_str,
                         1, PCAP_NETMASK_UNKNOWN) != 0)
                rte_exit(EXIT_FAILURE, "pcap filter string not valid (%s)\n",
                         pcap_geterr(pcap));

        bpf_prm = rte_bpf_convert(&bf);
        if (bpf_prm == NULL)
                rte_exit(EXIT_FAILURE,
                         "bpf convert failed: %s(%d)\n",
                         rte_strerror(rte_errno), rte_errno);

#if 0
//        if (dump_bpf) {
                printf("cBPF program (%u insns)\n", bf.bf_len);
                bpf_dump(&bf, 1);
                printf("\neBPF program (%u insns)\n", bpf_prm->nb_ins);
                rte_bpf_dump(stdout, bpf_prm->ins, bpf_prm->nb_ins);
//                exit(0);
//        }
#endif

        /* Don't care about original program any more */
        pcap_freecode(&bf);
        pcap_close(pcap);

	task->bpf = rte_bpf_load(bpf_prm);
}

void check_scan_task(char* fn, int fd, struct stat* st, void* cbd)
{
	struct taskdir* td = (struct taskdir*)cbd;
	struct task* t = NULL;
	int task_idx;

	// do we have an existing task?
	for (task_idx=0; task_idx<DPDKCAP_MAX_TASKS_PER_DIR; task_idx++)
	{
		struct task* cand = &td->tasks[task_idx];

//		printf("TASKSCAN checking %d for %s\n", i, fn);

		// skip unused task slots
		if (cand->task_filename[0] == 0x00)
			continue;

		// skip nonmatching task slots
		if (strncmp(cand->task_filename, fn, DPDKCAP_MAX_FILE_LEN))
			continue;

//		printf("TASKSCAN MATCH %d for %s\n", i, fn);

		// we have a matching task
		t = cand;

		// is task unchanged?
		if (!((t->task_mtime == st->st_mtime) &&
		      (t->task_size == st->st_size)))
			break;

		t->task_seen = td->lastscan;
//		printf("TASKSCAN HAVE %s\n", fn);
		return;
	}

	// do we need to allocate a task?
	if (t == NULL)
	{
		for (task_idx=0; task_idx<DPDKCAP_MAX_TASKS_PER_DIR; task_idx++)
		{
			struct task* cand = &td->tasks[task_idx];
	
			if (!(cand->task_filename[0] == 0x00))
				continue;

			t = cand;

			memset(t, 0x00, sizeof(struct task));

			printf("TASKSCAN NEW %s\n", fn);
			break;
		}
	} else {
		printf("TASKSCAN UPDATE %s\n", fn);
	}

	strncpy(t->task_filename, fn, DPDKCAP_MAX_FILE_LEN);
	t->task_mtime = st->st_mtime;
	t->task_size = st->st_size;
	t->task_seen = td->lastscan;

	parse_config(fd, st->st_size, &apply_taskkv, t);
//	printf("TASKSCAN LOADED task %g from '%s'\n", fn);

	// TODO check task is valid
	if (!(t->output_template[0] == 0x00)) {

  /* Add suffixes to output if needed */
  if (!strstr(t->output_template,
        DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID))
    strcat(t->output_template,
        "_"DPDKCAP_OUTPUT_TEMPLATE_TOKEN_CORE_ID);
  if (t->output_rotate_size &&
      !strstr(t->output_template,
        DPDKCAP_OUTPUT_TEMPLATE_TOKEN_FILECOUNT))
    strcat(t->output_template,
        "_"DPDKCAP_OUTPUT_TEMPLATE_TOKEN_FILECOUNT);

  strcat(t->output_template, ".pcap");

  if(t->compression)
    strcat(t->output_template, ".lzo");

		if (!t->snaplen)
			t->snaplen = PCAP_SNAPLEN_DEFAULT;

		if (!(t->bpf_str[0] == 0x00)) 
			compile_filter(t);

		printf("TASKSCAN task %i from '%s' ACTIVE\n", task_idx, fn);
		t->task_state = TASK_ACTIVE;
	} else {
		printf("TASKSCAN task %i from '%s' INACTIVE\n", task_idx, fn);
		t->task_state = TASK_INACTIVE;
	}

}

void check_scan_taskdir(struct taskdir* td, int now) 
{
	int i;

	if (td->dirname[0] == 0x00)
		return;

	if (now < (td->lastscan + td->interval))
		return;

	td->lastscan = now;
	scan_by_name(td->dirname, &check_scan_task, (void *)td);

	for (i=0; i<DPDKCAP_MAX_TASKS_PER_DIR; i++)
	{
		struct task* t = &td->tasks[i];

		if (t->task_filename[0] == 0x00)
			continue;

		if (!(t->task_seen == now))
		{
			printf("TASKSCAN GONE %s\n", t->task_filename);
			t->task_filename[0] = 0x00;
			t->task_state = TASK_UNUSED;
		}
	}
}


