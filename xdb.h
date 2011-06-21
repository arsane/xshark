#ifndef XDB_H
#define XDB_H

enum {
    XDB_ERROR,
    XDB_DROP = 0,
    XDB_DATA,
    XDB_SIGNAL,
};

struct xshark_stats {
    unsigned int packet_dropped;
    unsigned int packet_saved;
    unsigned int packet_data;
    unsigned int packet_data_interval;
    unsigned int packet_signal;
    unsigned int packet_signal_interval;
};

extern struct xshark_stats xstats;

extern int xdb_init(char *dns);
extern int xdb_process_packet(epan_dissect_t *edt);
extern int xdb_close();

#endif
