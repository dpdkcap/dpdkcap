#include "statistics.h"

#include <signal.h>
#include <ncurses.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_timer.h>
#include <rte_ring.h>
#include <rte_log.h>

#include "utils.h"

#define RTE_LOGTYPE_DPDKCAP RTE_LOGTYPE_USER1

#define STATS_PERIOD_MS 500
#define ROTATING_CHAR "-\\|/"

static void wglobal_stats(int height, int width,
    int starty, int startx,
    struct stats_data * data) {
  long total_packets = 0;
  long total_bytes = 0;
  long total_compressedbytes = 0;
  unsigned int i;

  for (i=0; i<data->cores_write_stats_list_size; i++) {
    total_packets += data->cores_stats_write_list[i].packets;
    total_bytes += data->cores_stats_write_list[i].bytes;
    total_compressedbytes += data->cores_stats_write_list[i].compressed_bytes;
  }

  WINDOW *local_win = newwin(height, width, starty, startx);
  box(local_win, 0 , 0);
  mvwprintw(local_win,0,2,"Global stats");
  wrefresh(local_win);

  WINDOW *inner_win = newwin(height-2, width-2, starty+1, startx+1);
  wprintw(inner_win,"Writing logs to: %s\n", data->log_file);
  wprintw(inner_win,"Entries free on ring: %u\n",
      rte_ring_free_count(data->ring));
  wprintw(inner_win,"Total packets written: %lu\n", total_packets);
  wprintw(inner_win,"Total bytes written: %s", bytes_format(total_bytes));
  wprintw(inner_win,"compressed to %s\n", bytes_format(total_compressedbytes));
  wprintw(inner_win,"Compressed/uncompressed size ratio: 1 / %.2f\n",
      total_compressedbytes?
      (float)total_bytes/(float)total_compressedbytes:0.0f);
  wrefresh(inner_win);
}

static void wcapture_stats(int height, int width,
    int starty, int startx,
    struct stats_data * data) {
  unsigned int i,j;
  static struct rte_eth_stats port_statistics;

  WINDOW *local_win = newwin(height, width, starty, startx);
  box(local_win, 0 , 0);
  mvwprintw(local_win,0,2,"Capture stats");
  wrefresh(local_win);

  WINDOW *inner_win = newwin(height-2, width-2, starty+1, startx+1);
  for (i=0; i<data->port_list_size; i++) {
    rte_eth_stats_get(data->port_list[i], &port_statistics);

    wprintw(inner_win,"- PORT %d -\n", data->port_list[i]);
    wprintw(inner_win,"  RX Successful bytes: %s (avg: %d bytes/pkt)\n",
        bytes_format(port_statistics.ibytes),
        port_statistics.ipackets?(int)((float)port_statistics.ibytes/
          (float)port_statistics.ipackets):0);
    wprintw(inner_win, "  RX Successful packets: %lu\n",
        port_statistics.ipackets);
    wprintw(inner_win, "  RX Unsuccessful packets: %lu\n",
        port_statistics.ierrors);
    wprintw(inner_win, "  RX Missed packets: %lu\n", port_statistics.imissed);
    wprintw(inner_win, "  No MBUF: %lu\n", port_statistics.rx_nombuf);

    wprintw(inner_win,"  Per queue:\n");
    for (j=0; j<data->queue_per_port; j++) {
      wprintw(inner_win, "    Queue %d RX: %lu RX-Error: %lu\n", j,
          port_statistics.q_ipackets[j], port_statistics.q_errors[j]);
    }
    wprintw(inner_win, "    (%d queues hidden)\n",
        RTE_ETHDEV_QUEUE_STAT_CNTRS - data->queue_per_port);
    wprintw(inner_win, "\n");
  }
  wrefresh(inner_win);
}

static void wwrite_stats(int height, int width, int starty, int startx,
    struct stats_data * data) {
  unsigned int i;
  WINDOW *local_win = newwin(height, width, starty, startx);
  box(local_win, 0 , 0);
  mvwprintw(local_win,0,2,"Write stats");

  for (i=0; i<data->cores_write_stats_list_size; i++) {
    mvwprintw(local_win,i+1,1,"Writing core %d: %s ",
        data->cores_stats_write_list[i].core_id,
        data->cores_stats_write_list[i].output_file);
    wprintw(local_win,"(%s)", bytes_format(
          data->cores_stats_write_list[i].current_file_compressed_bytes));
  }
  wrefresh(local_win);
}

/*
 * Handles signals
 */
static bool should_stop = false;
static void signal_handler(int sig) {
  RTE_LOG(NOTICE, DPDKCAP, "Caught signal %s on core %u%s\n",
      strsignal(sig), rte_lcore_id(),
      rte_get_master_lcore()==rte_lcore_id()?" (MASTER CORE)":"");
  should_stop = true;
}

static int printscreen(
    __attribute__((unused))struct rte_timer * timer,
    struct stats_data * data) {
    static int nb_updates = 0;
    nb_updates++;
    mvprintw(0,0,"%c - Press Ctrl+C to quit",ROTATING_CHAR[nb_updates%4]);
    refresh();
    wglobal_stats((LINES-1)/2, COLS/2, 1, 0, data);
    wwrite_stats((LINES-1)/2, COLS/2, (LINES-1)/2+1, 0, data);
    wcapture_stats(LINES-1, COLS/2, 1, COLS/2+1, data);
    return 0;
}

static struct rte_timer stats_timer;

void start_stats_display(struct stats_data * data) {
  signal(SIGINT,signal_handler);

  initscr();
  cbreak();
  noecho();
  keypad(stdscr, TRUE);
  curs_set(0);

  //Initialize timers
  rte_timer_subsystem_init();
  //Timer launch
  rte_timer_init (&(stats_timer));
  rte_timer_reset(&(stats_timer), 2000000ULL * STATS_PERIOD_MS, PERIODICAL,
      rte_lcore_id(), (void*) printscreen, data);
  //Wait for ctrl+c
  for (;;) {
    if (unlikely(should_stop)) {
      break;
    }
    rte_timer_manage();
  }
  rte_timer_stop(&(stats_timer));

  endwin();

  signal(SIGINT,SIG_DFL);
}

