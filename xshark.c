#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>

#ifdef WIN32
#include <windows.h>
#include <shellapi.h>
#include "wsutil/wsgetopt.h"
#else
#include <unistd.h>
#endif

#include <glib.h>
#include <wsutil/privileges.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/timestamp.h>
#include <epan/filesystem.h>
#include "xdb.h"
#include "xutils.h"
#include "xprint.h"

/* parsing */
typedef struct _capture_file {
    wtap *wth;
    gchar *filename;
    guint16 cd_t;        /* File type of capture file */
    gint64 filesize;     /* size of capture file */
    int count;           /* Total number of frames */
} capture_file;

capture_file cfile;

unsigned int xshark_count = 0;
/* capture file name */
static gchar *opt_cf_name;
/* odbc source name */
static gchar *opt_dsn_name;
/* ignore error when storage */
static gboolean opt_ignore_error = FALSE;
/* show progress info when loading */
gboolean opt_show_progress = FALSE;
/* suppress sql server error */
int opt_disable_odbc_error = 0;
/* data packet bulk insert step */
int opt_data_bulk_insert_step = 20000;
int opt_signal_bulk_insert_step = 5000;
gboolean opt_add_application_params = FALSE;
gboolean opt_add_ranap_params = FALSE;

#define PROGRESS_INTERVAL   (200)

static
void print_usage(void)
{
    FILE *output;

    output = stderr;

    fprintf(output, "\n Usage: xshark [options] ...\n");
    fprintf(output, "\n");
    fprintf(output, "  -r <infile>        set the filename to read from (no pipes or stdin!)\n");
    fprintf(output, "  -d <verbosity>     set the verbosity level.(1 = WARN, 2 = INFO, 3 = DEBUG)\n");
    fprintf(output, "  -o <odbc>          set the odbc source\n");
    fprintf(output, "  -h                 display this help and exit\n");
    fprintf(output, "  -p                 display progress info.\n");
    fprintf(output, "  -q                 quiet mode, disable odbc error message.\n");
    fprintf(output, "  -i <batch size>    data packets bulk batch size (default 20000)\n");
    fprintf(output, "  -j <batch size>    signal packets bulk batch size (default 5000)\n");
    fprintf(output, "  -c                 continue loading when odbc error occurs. \n");
    fprintf(output, "  -a                 add all media data upon tcp/udp as xml.\n");
    fprintf(output, "  -b                 add all ranap elements as xml.\n");
    fprintf(output, "  -v                 display version info and exit\n");
    fprintf(output, "\n");
}

/*static callbacks passed to EPAN */

/*
 * Open/create errors are reported with an console message
 */
static
void open_failure_message(const char *filename, int err, gboolean for_writing)
{
    fprintf(stderr, "xshark: ");
    fprintf(stderr, file_open_error_message(err, for_writing), filename);
    fprintf(stderr, "\n");
}

/*
 * General errors are reported with an console message
 */
static
void failure_message(const char *msg_format, va_list ap)
{
    fprintf(stderr, "xshark: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message
 */
static
void read_failure_message(const char *filename, int err)
{
    ERR("An error occurred while reading from the file \"%s\": %s.",
               filename, strerror(err));
}

/*
 * Write errors are reported with an console message in TShark.
 */
static void
write_failure_message(const char *filename, int err)
{
    ERR("An error occurred while writing to the file \"%s\": %s.",
            filename, strerror(err));
}

/*
 * capfile_open - open capture file.
 *
 * use wtap lib to open capture file,
 * and fill up related infomation
 */
static
int cf_open(capture_file *cf, const char *name)
{
    int err;
    wtap  *wth;
    gchar *err_info;

    wth = wtap_open_offline(name, &err, &err_info, FALSE);
    if (wth == NULL)
        goto fail;

    /* reinitialize for dissection */
    cleanup_dissection();
    init_dissection();

    /* fill in the information for this file */
    cf->wth = wth;

    /* set the file name */
    cf->filename = g_strdup(name);

    cf->cd_t = wtap_file_type(cf->wth);

    /* set the file size */
    cf->filesize = wtap_file_size(cf->wth, &err);
    if (cf->filesize == -1) {
        fprintf(stderr,
                "capinfos: Can't get size of \"%s\": %s.\n",
                name, strerror(err));
        return -1;
    }

    /* set timestamp precision. */
    switch(wtap_file_tsprecision(cf->wth)) {
        case(WTAP_FILE_TSPREC_SEC):
            timestamp_set_precision(TS_PREC_AUTO_SEC);
            break;

        case(WTAP_FILE_TSPREC_DSEC):
            timestamp_set_precision(TS_PREC_AUTO_DSEC);
            break;

        case(WTAP_FILE_TSPREC_CSEC):
            timestamp_set_precision(TS_PREC_AUTO_CSEC);
            break;

        case(WTAP_FILE_TSPREC_MSEC):
            timestamp_set_precision(TS_PREC_AUTO_MSEC);
            break;

        case(WTAP_FILE_TSPREC_USEC):
            timestamp_set_precision(TS_PREC_AUTO_USEC);
            break;

        case(WTAP_FILE_TSPREC_NSEC):
            timestamp_set_precision(TS_PREC_AUTO_NSEC);
            break;

        default:
            g_assert_not_reached();
    }

    return 0;

fail:
    ERR("can't open %s: %s\n", name, wtap_strerror(err));
    switch(err) {
        case WTAP_ERR_UNSUPPORTED:
        case WTAP_ERR_UNSUPPORTED_ENCAP:
        case WTAP_ERR_BAD_RECORD:
            ERR("(%s)\n", err_info);
            g_free(err_info);
            break;
    }

    return -1;
}

static void
fillin_data (frame_data *fdata, capture_file *cf,
             const struct wtap_pkthdr *phdr, gint64 offset)
{
    static guint32 cum_bytes = 0;

    fdata->next = NULL;
    fdata->prev = NULL;
    fdata->pfd = NULL;
    fdata->num = cf->count;
    fdata->pkt_len = phdr->len;
    cum_bytes += phdr->len;
    fdata->cum_bytes  = cum_bytes;
    fdata->cap_len = phdr->caplen;
    fdata->file_off = offset;
    fdata->lnk_t = phdr->pkt_encap;
    fdata->abs_ts = *((nstime_t *) &phdr->ts);
    fdata->flags.passed_dfilter = 0;
    fdata->flags.encoding = 0;
    fdata->flags.visited = 0;
    fdata->flags.marked = 0;
    fdata->flags.ref_time = 0;
    fdata->color_filter = NULL;

    /* use abs time */
    fdata->rel_ts = fdata->abs_ts;
    fdata->del_dis_ts = fdata->abs_ts;
    fdata->del_cap_ts = fdata->abs_ts;
}

/*
 * process_packet - deal with packet
 *
 * dissect packet and deal with proto tree,
 * send relative information to database.
 */
static
int process_packet(capture_file *cf, gint64 offset)
{
    struct wtap_pkthdr *whdr = wtap_phdr(cf->wth);
    union wtap_pseudo_header *pseudo_header = wtap_pseudoheader(cf->wth);
    const guchar* pd = wtap_buf_ptr(cf->wth);

    frame_data fdata;
    epan_dissect_t *edt;

    /* count this packet */
    cf->count++;
    xshark_count++;

    INFO("Processing packet %d ...\n", cf->count);

    /* set up fdata */
    fillin_data(&fdata, cf, whdr, offset);

    edt = epan_dissect_new(TRUE, TRUE);

    tap_queue_init(edt);
    epan_dissect_run(edt, pseudo_header, pd, &fdata, NULL);
    tap_push_tapped_queue(edt);

    if (opt_verbosity > 2) {
        proto_tree_write_pdml(edt, stderr);
    }

    if (xdb_process_packet(edt) < 0) {
        if (!opt_disable_odbc_error) {
            proto_tree_write_pdml(edt, stderr);
        }
        return -1;
    }

    epan_dissect_free(edt);
    return 0;
}

static
int load_cap_file(capture_file *cf)
{
    gint linktype;
    int  err;
    gchar *err_info;
    gint64 data_offset;
    int  cycle_count = 0;

    linktype = wtap_file_encap(cf->wth);

    do {
        if (!wtap_read(cf->wth, &err, &err_info, &data_offset)) {
            if (err != 0) {
                goto error;
            } else {
                goto out;
            }
        }

        err = process_packet(cf, data_offset);
        if (err) {
            if (!opt_ignore_error) {
                goto out;
            }
        }

        cycle_count++;

        if (opt_show_progress) {
            if (cycle_count == PROGRESS_INTERVAL) {
                cycle_count = 0;
                fprintf (stdout,"%lld %lld %u %u %u %u\n",
                            data_offset, cf->filesize,
                            xstats.packet_dropped,
                            xstats.packet_saved,
                            xstats.packet_data,
                            xstats.packet_signal
                            );
                fflush(stdout);
            }
        }

//        if (cf->count >= 100000)
//            goto out;
    } while(1);

error:
    ERR("xshark: An error occurred after reading %u packets from \"%s\": %s.\n",
            cf->count, cf->filename, wtap_strerror(err));
    switch (err) {
        case WTAP_ERR_UNSUPPORTED:
        case WTAP_ERR_UNSUPPORTED_ENCAP:
        case WTAP_ERR_BAD_RECORD:
            ERR("(%s)\n", err_info);
            g_free(err_info);
            break;
    }
out:
    fprintf (stdout, "%lld %lld %u %u %u %u\n",
            data_offset, cf->filesize,
            xstats.packet_dropped,
            xstats.packet_saved,
            xstats.packet_data,
            xstats.packet_signal
           );
    fflush(stdout);
    wtap_close(cf->wth);
    cf->wth = NULL;
    return err;
}

static
void xshark_init(void)
{
    /* specify timestamp format */
    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);

    get_credential_info();

    epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL,
            failure_message, open_failure_message, read_failure_message,
            write_failure_message);
    init_dissection();

    setlocale(LC_ALL, "");
    g_thread_init(NULL);

    if (xdb_init(opt_dsn_name) != 0) {
        exit (EXIT_FAILURE);
    }
}

static
void xshark_cleanup(void)
{
    epan_cleanup();

    xdb_close();
}

#define OPTSTRING "r:o:d:i:j:vabpqch"

void parse_options(int argc, char *argv[])
{
    static const char    optstring[] = OPTSTRING;
    int opt;


    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
            case 'r':
                opt_cf_name = g_strdup(optarg);
                break;
            case 'o':
                opt_dsn_name = g_strdup(optarg);
                break;
            case 'd':
                opt_verbosity = atoi(optarg);
                break;
            case 'p':
                opt_show_progress = TRUE;
                break;
            case 'q':
                opt_disable_odbc_error = 1;
                break;
            case 'c':
                opt_ignore_error = TRUE;
                break;
            case 'i':
                opt_data_bulk_insert_step = atoi(optarg);
                break;
            case 'j':
                opt_signal_bulk_insert_step = atoi(optarg);
                break;
            case 'a':
                opt_add_application_params = TRUE;
                break;
            case 'b':
                opt_add_ranap_params = TRUE;
                break;
            case 'h':
                print_usage();
                exit(EXIT_FAILURE);
            case 'v':
                print_usage();
                exit(EXIT_FAILURE);
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (!opt_cf_name) {
        print_usage();
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    GTimeVal start, end;
    int ret;

#ifdef _WIN32
    LPWSTR              *wc_argv;
    int                  wc_argc, i;
    char                *init_progfile_dir_error;

    /*
     * Attempt to get the pathname of the executable file.
     */
    init_progfile_dir_error = init_progfile_dir(argv[0], main);
    if (init_progfile_dir_error != NULL) {
        fprintf(stderr, "tshark: Can't get pathname of tshark program: %s.\n",
                init_progfile_dir_error);
    }

    /* Convert our arg list to UTF-8. */
    wc_argv = CommandLineToArgvW(GetCommandLineW(), &wc_argc);
    if (wc_argv && wc_argc == argc) {
        for (i = 0; i < argc; i++) {
            argv[i] = g_strdup(g_utf16_to_utf8(wc_argv[i],
                                -1 , NULL, NULL, NULL));
        }
    } /* XXX else bail because something is horribly, horribly wrong? */
#endif  /* _WIN32 */

    /* parse options */
    parse_options(argc, argv);

    g_get_current_time(&start);

    /* initialize wireshark libraries */
    xshark_init();

    /* open capture file */
    ret = cf_open(&cfile, opt_cf_name);
    if (ret < 0) {
        goto error;
    }

    /* load file */
    ret = load_cap_file(&cfile);
error:

    xshark_cleanup();
    g_get_current_time(&end);
    fprintf(stderr, "Time used %ld seconds\n", end.tv_sec - start.tv_sec);

    return ret;
}
