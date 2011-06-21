#include <config.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>
#include <epan/epan_dissect.h>
#include <epan/dissectors/packet-data.h>
#include "xdb.h"
#include "xodbc.h"
#include "xutils.h"
#include "xprint.h"

#define PNODE_FINFO(proto_node)  ((proto_node)->finfo)

enum XDB_TYPE {
    TYPE_UNDEF,
    TYPE_SHORT,
    TYPE_INT,
    TYPE_STR,
    TYPE_XML,
    TYPE_DATE,
    TYPE_BIGINT,
};

enum XDB_NAME {
    DB_UNDEF,
    DB_DROP,
    DB_DATA,
    DB_SIGNAL,
    DB_BOTH,
};

struct xdb_field_t {
  const char *xshark_field_name;
  const char *xdb_field_name;
  gboolean in_gtp;         /* GTP inner protocol */
  gboolean allow_null;     /* whether this field allowed to be null or not */
  enum XDB_TYPE type;
  enum XDB_NAME dbname;
};

struct xshark_stats xstats;

#define RANAPPDUPARAMS  "RanapPduParams"
#define PROCEDURENAME   "ProcedureName"

#if defined(WIN32)
#define DATA_FILE   "C:/data.tmp"
#define DATA_FILE_BULK  "C:/data.bulk"
#define DATA_FILE_FORMAT "C:/data.xml"
#define SIGNAL_FILE "C:/signal.tmp"
#define SIGNAL_FILE_BULK    "C:/signal.bulk"
#define SIGNAL_FILE_FORMAT "C:/signal.xml"
#else
#define DATA_FILE   "/tmp/data.tmp"
#define DATA_FILE_BULK "/tmp/data.bulk"
#define DATA_FILE_FORMAT "/tmp/data.xml"
#define SIGNAL_FILE "/tmp/signal.tmp"
#define SIGNAL_FILE_BULK "/tmp/signal.bulk"
#define SIGNAL_FILE_FORMAT "/tmp/signal.xml"
#endif

#define BULK_SIGNAL_INSERT_INTERVAL  (5000)
#define BULK_DATA_INSERT_INTERVAL  (20000)

#define BULK_DATA_VIEW      "dbo.bulk_data_view"
#define BULK_SIGNAL_VIEW    "dbo.bulk_signal_view"

char bulk_insert_data_sql[1024];
char bulk_insert_signal_sql[1024];
char bulk_create_data_view_sql[4096];
char bulk_create_signal_view_sql[4096];

static FILE *f_data;
static FILE *f_signal;
static int data_idx = 0;
static int signal_idx = 0;

extern int opt_data_bulk_insert_step;
extern int opt_signal_bulk_insert_step;
extern gboolean opt_show_progress;
extern gboolean opt_add_application_params;
extern gboolean opt_add_ranap_params;
/**
 * struct save the packet fields and database fileds
 *
 * Notice: fields belong to both table must be place before other fields
 */
static struct xdb_field_t xdb_fields[] = {
/* field name   -               db column name      -   in gtp    - not null     -   type   -   Database */
/* General information */
  {"frame.time",                "PacketArrivalTime",    FALSE,       TRUE,       TYPE_DATE,     DB_BOTH},
  {"frame.ns",                  "PacketArrivalInstant",  FALSE,       FALSE,      TYPE_INT,      DB_BOTH},
  {"frame.len",                 "FrameLength",          FALSE,       FALSE,      TYPE_INT,      DB_BOTH},
  {"frame.number",              "FrameNumber",          FALSE,       FALSE,      TYPE_INT,      DB_BOTH},
/* Layer 2 */
  {"eth.src",                   "SourceMac",            FALSE,       FALSE,      TYPE_STR,      DB_BOTH},
  {"eth.dst",                   "DestinationMac",       FALSE,       FALSE,      TYPE_STR,      DB_BOTH},
  {"vlan.etype",                "VlanType",             FALSE,       FALSE,      TYPE_STR,      DB_BOTH},
  {"ip.version",                "OuterIPVersion",       FALSE,       FALSE,      TYPE_STR,      DB_BOTH},
  {"ip.src",                    "OuterSourceIP",        FALSE,       FALSE,      TYPE_STR,      DB_BOTH},
  {"ip.dst",                    "OuterDestinationIP",   FALSE,       FALSE,      TYPE_STR,      DB_BOTH},
  {"ip.hdr_len",                "OuterIPHeaderLength",  FALSE,       FALSE,      TYPE_SHORT,    DB_BOTH},
  {"ip.len",                    "OuterIPTotalLength",   FALSE,       FALSE,      TYPE_SHORT,    DB_BOTH},
  {"ip.flags",                  "OuterIPFlag",          FALSE,       FALSE,      TYPE_STR,      DB_BOTH},
  {"ip.id",                     "OuterIPIdentification",FALSE,       FALSE,      TYPE_INT,      DB_BOTH},
  {"ip.frag_offset",            "OuterIPFragmentOffset",FALSE,       FALSE,      TYPE_INT,      DB_BOTH},
  {"ip.ttl",                    "OuterIPTTL",           FALSE,       FALSE,      TYPE_INT,      DB_BOTH},
  {"ip.proto",                  "OuterIPProtocol",      FALSE,       FALSE,      TYPE_STR,      DB_BOTH},
/* outer udp */
  {"udp.srcport",               "OuterSourcePort",      FALSE,       FALSE,      TYPE_INT,      DB_DATA},
  {"udp.dstport",               "OuterDestinationPort", FALSE,       FALSE,      TYPE_INT,      DB_DATA},
  {"udp.length",                "OuterUDPLength",       FALSE,       FALSE,      TYPE_SHORT,    DB_DATA},
/* GTP related infomation */
  {"gtp.flags",                 "GTPFlags",             TRUE,       FALSE,      TYPE_STR,       DB_DATA},
  {"gtp.message",               "GTPMessageType",       TRUE,       FALSE,      TYPE_STR,       DB_DATA},
  {"gtp.length",                "GTPLength",            TRUE,       FALSE,      TYPE_SHORT,     DB_DATA},
  {"gtp.teid",                  "GTPTEID",              TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"gtp.seq_number",            "GTPSequenceNumber",    TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"gtp.npdu_number",           "GTPNpduNumber",        TRUE,       FALSE,      TYPE_STR ,      DB_DATA},
  {"gtp.next",                  "GTPNextExtensionHeaderType", TRUE, FALSE,      TYPE_STR ,      DB_DATA},
/* Inner IP related infomation */
  {"ip.version",                "IPVersion",            TRUE,       FALSE,      TYPE_STR ,      DB_DATA},
  {"ip.hdr_len",                "IPHeaderlength",       TRUE,       FALSE,      TYPE_SHORT ,    DB_DATA},
  {"ip.dsfield",                "IPDifferentiatedService",TRUE,     FALSE,      TYPE_STR ,      DB_DATA},
  {"ip.len",                    "IPTotalLength",        TRUE,       FALSE,      TYPE_SHORT,     DB_DATA},
  {"ip.id",                     "IPIdentification",     TRUE,       FALSE,      TYPE_INT ,      DB_DATA},
  {"ip.flags",                  "IPFlags",              TRUE,       FALSE,      TYPE_STR,       DB_DATA},
  {"ip.frag_offset",            "IPFragmentOffset",     TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"ip.ttl",                    "IPTimeToLive",         TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"ip.proto",                  "IPProtocol",           TRUE,       FALSE,      TYPE_STR,       DB_DATA},
  {"ip.checksum",               "IPHeaderChecksum",     TRUE,       FALSE,      TYPE_STR,       DB_DATA},
  {"ip.src",                    "IPSource",             TRUE,       FALSE,      TYPE_STR,       DB_DATA},
  {"ip.dst",                    "IPDestination",        TRUE,       FALSE,      TYPE_STR,       DB_DATA},
/* Inner TCP related infomation */
  {"tcp.totallength",           "TCPTotalLength",       FALSE,       FALSE,      TYPE_SHORT,    DB_DATA},
  {"tcp.srcport",               "TCPSourcePort",        TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"tcp.dstport",               "TCPDestinationPort",   TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"tcp.len",                   "TCPSegmentLength",     TRUE,       FALSE,      TYPE_SHORT,     DB_DATA},
  {"tcp.stream",                "TCPStreamIndex",       TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"tcp.seq",                   "TCPSequenceNumber",    TRUE,       FALSE,      TYPE_BIGINT,    DB_DATA},
  {"tcp.ack",                   "TCPAcknowledgementNumber",TRUE,    FALSE,      TYPE_BIGINT,    DB_DATA},
  {"tcp.hdr_len",               "TCPHeaderLength",      TRUE,       FALSE,      TYPE_SHORT,     DB_DATA},
  {"tcp.flags",                 "TCPFlags",             TRUE,       FALSE,      TYPE_STR,       DB_DATA},
  {"tcp.window_size",           "TCPWindowSize",        TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"tcp.checksum",              "TCPChecksum",          TRUE,       FALSE,      TYPE_STR,       DB_DATA},
/* Inner UDP data */
  {"udp.srcport",               "UDPSourcePort",        TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"udp.dstport",               "UDPDestinationPort",   TRUE,       FALSE,      TYPE_INT,       DB_DATA},
  {"udp.checksum",              "UDPChecksum",          TRUE,       FALSE,      TYPE_STR,       DB_DATA},
  {"udp.length",                "UDPLength",            TRUE,       FALSE,      TYPE_SHORT,     DB_DATA},
  {"data.data",                 "DataPriview",          TRUE,       FALSE,      TYPE_STR,       DB_DATA},
/* Application data */
  {"http",                      "HTTPParams",           TRUE,       FALSE,      TYPE_XML,       DB_DATA},
  {"rtsp",                      "RTSPParams",           TRUE,       FALSE,      TYPE_XML,       DB_DATA},
  {"rtp",                       "RTPParams",            TRUE,       FALSE,      TYPE_XML,       DB_DATA},
  {"bittorrent",                "BitTorrentParams",     TRUE,       FALSE,      TYPE_XML,       DB_DATA},
  {"oicq",                      "OICQParams",           TRUE,       FALSE,      TYPE_XML,       DB_DATA},
  {"ftp",                       "FTPParams",            TRUE,       FALSE,      TYPE_XML,       DB_DATA},
  {"data.shouldnotfound",       "DataParams",           TRUE,       FALSE,      TYPE_XML,       DB_DATA},
  {"tcp.segments",              "ReassembledCollectionParams",TRUE, FALSE,      TYPE_XML,       DB_DATA},
  {"otherdata",                 "ApplicationDataParams",TRUE,       FALSE,      TYPE_XML,       DB_DATA},
/* SCTP */
  {"sctp.srcport",              "SCTPSourcePort",       FALSE,      TRUE,       TYPE_SHORT,     DB_SIGNAL},
  {"sctp.dstport",              "SCTPDestinationPort",  FALSE,      TRUE,       TYPE_SHORT,     DB_SIGNAL},
  {"sctp.verification_tag",     "SCTPVerificationTag",  FALSE,      TRUE,       TYPE_STR,       DB_SIGNAL},
/* M3UA */
  {"m3ua.version",              "M3UAVersion",          FALSE,      TRUE,       TYPE_STR,       DB_SIGNAL},
  {"m3ua.reserved",             "M3UAReserved",         FALSE,      TRUE,       TYPE_SHORT,     DB_SIGNAL},
  {"m3ua.message_class",        "M3UAMessageClass",     FALSE,      TRUE,       TYPE_STR,       DB_SIGNAL},
  {"m3ua.message_type",         "M3UAMessageType",      FALSE,      TRUE,       TYPE_STR,       DB_SIGNAL},
  {"m3ua.message_length",       "M3UAMessageLength",    FALSE,      TRUE,       TYPE_SHORT,     DB_SIGNAL},
  {"m3ua.parameter_tag",        "M3UAParameterTag",     FALSE,      TRUE,       TYPE_STR,       DB_SIGNAL},
  {"m3ua.parameter_length",     "M3UAParameterLength",  FALSE,      TRUE,       TYPE_SHORT,     DB_SIGNAL},
  {"m3ua.protocol_data_opc",    "M3UAOPC",              FALSE,      TRUE,       TYPE_SHORT,     DB_SIGNAL},
  {"m3ua.protocol_data_dpc",    "M3UADPC",              FALSE,      TRUE,       TYPE_SHORT,     DB_SIGNAL},
  {"m3ua.protocol_data_si",     "M3UASI",               FALSE,      TRUE,       TYPE_STR,       DB_SIGNAL},
  {"m3ua.protocol_data_ni",     "M3UANI",               FALSE,      TRUE,       TYPE_INT,       DB_SIGNAL},
  {"m3ua.protocol_data_mp",     "M3UAMP",               FALSE,      TRUE,       TYPE_INT,       DB_SIGNAL},
  {"m3ua.protocol_data_sls",    "M3UASLS",              FALSE,      TRUE,       TYPE_INT,       DB_SIGNAL},
  /* fake field, unexisting */
  {"m3ua.m3ua_wrap_idx",        "M3uaSequenceNumber",   FALSE,      TRUE,       TYPE_INT,       DB_SIGNAL},
/* SCCP */
  {"sccp.message_type",         "SCCPMessageType",      FALSE,      TRUE,       TYPE_STR,       DB_SIGNAL},
  {"sccp.slr",                  "SLR",                  FALSE,      FALSE,      TYPE_INT,       DB_SIGNAL},
  {"sccp.dlr",                  "DLR",                  FALSE,      FALSE,      TYPE_INT,       DB_SIGNAL},
  {"sccp.more",                 "EqualClass",           FALSE,      TRUE,       TYPE_STR,       DB_SIGNAL},
  {"sccp.release_cause",        "ReleaseCause",         FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  {"sccp.variable_pointer1",    "SCCPPointerToFirstMandatoryVariableParameter", FALSE,  FALSE, TYPE_INT, DB_SIGNAL},
  {"sccp.variable_pointer2",    "SCCPPointerToSecondMandatoryVariableParameter", FALSE, FALSE, TYPE_INT, DB_SIGNAL},
  {"sccp.variable_pointer3",    "SCCPPointerToThirdMandatoryVariableParameter", FALSE,  FALSE, TYPE_INT, DB_SIGNAL},
  {"sccp.optional_pointer",     "SCCPPointerToOptionalParameter",   FALSE,      FALSE,  TYPE_INT, DB_SIGNAL},
  {"sccp.called.pc",            "SCCPCalledPc",         FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  {"sccp.called.ssni",          "SCCPCalledSubSystemNumber", FALSE, FALSE,      TYPE_INT,       DB_SIGNAL},
  {"sccp.calling.pc",           "SCCPCallingPc",        FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  {"sccp.calling.ssni",         "SCCPCallingSubSystemNumber",FALSE, FALSE,      TYPE_INT,       DB_SIGNAL},
  /* special processing, both value and child elements need to save */
  {"ranap.RANAP_PDU",           "RanapPDU",             FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  /* special processing, we need find the "value" string for precodule code*/
  {"ranap.notExist",            PROCEDURENAME,          FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  /* special processing, we need save all protocol info for ranap.RANAP_PDU */
  {"ranap.childElements",       RANAPPDUPARAMS,         FALSE,      FALSE,      TYPE_XML,       DB_SIGNAL},
  {"ranap.gTP_TEI",             "RanapGtpTEI",          FALSE,      FALSE,      TYPE_INT,       DB_SIGNAL},
  {"ranap.procedureCode",       "RanapProcedureCode",   FALSE,      FALSE,      TYPE_SHORT,     DB_SIGNAL},
  {"ranap.iMSI",                "RanapIMSI",            FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  {"ranap.imsi_digits",         "RanapDigits",          FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  {"ranap.rAB_ID",              "RanapRAB_ID",          FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  {"ranap.LAI",                 "RanapLAIParams",       FALSE,      FALSE,      TYPE_XML,       DB_SIGNAL},
  {"ranap.RAC",                 "RanapRAC",             FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
#if 0
  {"ranap.SAI",                 "RanapSAIParams",       FALSE,      FALSE,      TYPE_XML,       DB_SIGNAL},
#else
  {"ranap.pLMNidentity.hide",   "SAI_pLMNidentity",     FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  {"e212.mcc.hide",             "SAI_MCC",              FALSE,      FALSE,      TYPE_SHORT,     DB_SIGNAL},
  {"e212.mnc.hide",             "SAI_MNC",              FALSE,      FALSE,      TYPE_SHORT,     DB_SIGNAL},
  {"ranap.lAC.hide",            "SAI_LAC",              FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  {"ranap.sAC.hide",            "SAI_SAC",              FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
#endif
  {"ranap.GlobalRNC_ID",        "RanapGlobalRNC_ID",    FALSE,      FALSE,      TYPE_XML,       DB_SIGNAL},
  {"gsm_a.tmsi",                "Gsm_a_dtapTMSI",       FALSE,      FALSE,      TYPE_BIGINT,    DB_SIGNAL},
  /* add server name - ???*/
  {"gsm_a.gm.serv_type",        "GsmServiceType",       FALSE,      FALSE,      TYPE_STR,       DB_SIGNAL},
  /* save all gsm layer as xml */
  {"gsm_a_dtap",                "GsmParams",            FALSE,      FALSE,      TYPE_XML,       DB_SIGNAL},
};

struct key_t {
    GQuark name;
    gboolean in_gtp;
};

struct attr_t {
    GQuark xdb_field_name;
    gboolean allow_null;
    enum XDB_TYPE type;
    int  field_idx;     /* idx for SQLBindParameter */
};

#define FIELDS_SIZE (sizeof(xdb_fields) / sizeof(xdb_fields[0]))

extern unsigned int xshark_count;
static struct key_t  keys[FIELDS_SIZE];
static struct attr_t attrs[FIELDS_SIZE];

/* hex array for fast char to hex */
static char **hex2ascii;

struct xdb_field_v {
  GQuark name;
  enum XDB_TYPE type;
  union {
    char  *str;   /* allocated value */
    char  *xml;   /* allocated value */
  };
  int field_idx;
};

struct record_t {
    enum XDB_NAME db;
    int max_idx;
    GQuark protocol;
    gboolean gtp_parsed;  /* FIXME in split records */
    gboolean ranap_value_parsed;
    gboolean http_parsed; /*we may encounter more than one http proto*/
    int m3ua_level;
    int fields_idx_before_m3ua;
    struct xdb_field_v v[FIELDS_SIZE];
};

//FIXME: how much size is enough, since we will not check buffer overflow.
#define MAX_XML_SIZE    (20 * 1024 * 1024)
struct get_fields_data {
    epan_dissect_t *edt;
    GSList *src_list;
    int level;
    int proto_level;
    struct record_t record;
    char *tmp;  /* point to xml_buffer[0] */
    char xml_buffer[MAX_XML_SIZE];
};

static GHashTable *g_tbl;
/* given database field quark value, return the sql value index */
static GHashTable *g_name_idx_tbl;
static GQuark quark_frame_protocols;
static GQuark quark_gtp;
static GQuark quark_gnsecs;
static GQuark quark_ranap;
static GQuark quark_ranap_value;
static GQuark quark_m3ua;
static GQuark quark_m3ua_index;
static GQuark quark_http;
static GQuark quark_application;
static GQuark quark_data;
static GQuark quark_procedure;
static GQuark quark_ranappdu;
static GQuark quark_udp_data;
static GQuark quark_data_data;
static GQuark quark_ranap_sai;
static GQuark quark_ranap_sai_plMNidentity;
static GQuark quark_ranap_sai_plMNidentity_hide;
static GQuark quark_ranap_sai_mcc;
static GQuark quark_ranap_sai_mcc_hide;
static GQuark quark_ranap_sai_mnc;
static GQuark quark_ranap_sai_mnc_hide;
static GQuark quark_ranap_sai_lac;
static GQuark quark_ranap_sai_lac_hide;
static GQuark quark_ranap_sai_sac;
static GQuark quark_ranap_sai_sac_hide;
static GQuark quark_gsm;
static GQuark quark_gsm_service_name;
static int xdb_error = 0;
static gboolean xdb_save_to_odbc = FALSE;
GMutex *bulk_insert_data_mutex;
GMutex *bulk_insert_signal_mutex;

static int xdb_save_packet(struct get_fields_data *pdata, gboolean release);
static gchar *
xdb_abs_time_to_str (const nstime_t *abs_time)
{
    struct tm *tmp= NULL;

    tmp = gmtime(&abs_time->secs);
    return g_strdup_printf("%04d-%02d-%02d %02d:%02d:%02d",
                           tmp->tm_year + 1900,
                           tmp->tm_mon + 1,
                           tmp->tm_mday,
                           tmp->tm_hour,
                           tmp->tm_min,
                           tmp->tm_sec
                           );
}

/*
 * release allocated strings from index start_idx
 */
static void
xdb_record_release(struct record_t *r, int start_idx)
{
    int i;

    for (i = start_idx; i <= r->max_idx; i++) {
        if (r->v[i].str) {
            g_free(r->v[i].str);
            r->v[i].str = NULL;
        }
    }

    r->max_idx = start_idx;
}

static guint
hash_func (gconstpointer v)
{
    return ((struct key_t *) v)->name;
}

static gboolean
equal_func (gconstpointer v1, gconstpointer v2)
{
    struct key_t *t1 = (struct key_t *) v1;
    struct key_t *t2 = (struct key_t *) v2;

    return t1->name == t2->name && t1->in_gtp == t2->in_gtp;
}

/* escape string for xml */
static char *
xdb_escaped_xml(gchar *dst, const char *str)
{
    char *s = dst;
    const char *p;
    char temp_str[8];

    for (p = str; *p != '\0'; p++) {
        switch(*p) {
            case '&':
                s = g_stpcpy(s, "&amp;");
                break;
            case '<':
                s = g_stpcpy(s, "&lt;");
                break;
            case '>':
                s = g_stpcpy(s, "&gt;");
                break;
            case '"':
                s = g_stpcpy(s, "&quot;");
                break;
            case '\'':
                s = g_stpcpy(s, "&apos;");
                break;
            default:
                if (g_ascii_isprint(*p)) {
                    *s++ = *p;
                    *s = '\0';
                } else {
                    g_snprintf(temp_str, sizeof(temp_str), "\\x%x", (guint8)*p);
                    s = g_stpcpy(s, temp_str);
                }
        }
    }

    return s;
}

/* field value to hex value */
static char *
xdb_field_to_hex_value(char *dst, struct get_fields_data *pdata, field_info *fi)
{
    int i;
    const guint8 *pd;
    char *s = dst;

    if (!fi->ds_tvb) {
        ERR("%s\n", "fs->ds_tvb is null");
        return s;
    }

    if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start)) {
        ERR("%s\n", "field length invalid!");
        return s;
    }

    /* Find the data for this field. */
    pd = get_field_data(pdata->src_list, fi);

    if (pd) {
        /* Print a simple hex dump */
        for (i = 0 ; i < fi->length; i++) {
            *s++ = hex2ascii[pd[i]][0];
            *s++ = hex2ascii[pd[i]][1];
        }
        *s = '\0';
    }

    return s;
}

/* dump node to xml string */
static void
xdb_proto_tree_to_xml(proto_node *node, gpointer tdata)
{
    field_info	*fi = PNODE_FINFO(node);
    struct get_fields_data *pdata = (struct get_fields_data*) tdata;
    const gchar	*label_ptr;
    gchar label_str[ITEM_LABEL_LENGTH];
    char *dfilter_string;
    size_t chop_len;
    int i;
    gboolean wrap_in_fake_protocol;
    char *s = pdata->tmp;
    int len;

    g_assert(fi && "dissection with an invisible proto tree?");
    g_assert(pdata->level < 50);

    /* Will wrap up top-level field items inside a fake protocol wrapper to
       preserve the PDML schema */
    wrap_in_fake_protocol =
        (((fi->hfinfo->type != FT_PROTOCOL) ||
          (fi->hfinfo->id == proto_data)) &&
         (pdata->level == 0));

    /* Indent to the correct level */
    for (i = -1; i < pdata->level; i++) {
        s = g_stpcpy(s, "  ");
    }

    if (wrap_in_fake_protocol) {
        /* Open fake protocol wrapper */
        s = g_stpcpy(s, "<proto name=\"fake-field-wrapper\">\n");

        /* Indent to increased level before writint out field */
        pdata->level++;
        for (i = -1; i < pdata->level; i++) {
            s = g_stpcpy(s, "  ");
        }
    }

    /* Text label. It's printed as a field with no name. */
    if (fi->hfinfo->id == hf_text_only) {
        /* Get the text */
        if (fi->rep) {
            label_ptr = fi->rep->representation;
        }
        else {
            label_ptr = "";
        }

        /* Show empty name since it is a required field */
        s = g_stpcpy(s, "<field name=\"");
        s = g_stpcpy(s, "\" show=\"");
        s = xdb_escaped_xml(s, label_ptr);

        len = g_sprintf(s, "\" size=\"%d", fi->length); s += len;
        len = g_sprintf(s, "\" pos=\"%d", fi->start); s+= len;

        s = g_stpcpy(s, "\" value=\"");
        s = xdb_field_to_hex_value(s, pdata, fi);

        if (node->first_child != NULL) {
            s = g_stpcpy(s, "\">\n");
        }
        else {
            s = g_stpcpy(s, "\"/>\n");
        }
    }

    /* Uninterpreted data, i.e., the "Data" protocol, is
     * printed as a field instead of a protocol. */
    else if (fi->hfinfo->id == proto_data) {

        /* Write out field with data */
        s = g_stpcpy(s, "<field name=\"data\" value=\"");
        s = xdb_field_to_hex_value(s, pdata, fi);
        s = g_stpcpy(s, "\"/>\n");
    }
    /* Normal protocols and fields */
    else {
        if (fi->hfinfo->type == FT_PROTOCOL) {
            s = g_stpcpy(s, "<proto name=\"");
        }
        else {
            s = g_stpcpy(s, "<field name=\"");
        }
        s = xdb_escaped_xml(s, fi->hfinfo->abbrev);

        if (fi->rep) {
            s = g_stpcpy(s, "\" showname=\"");
            s = xdb_escaped_xml(s, fi->rep->representation);
        }
        else {
            label_ptr = label_str;
            proto_item_fill_label(fi, label_str);
            s = g_stpcpy(s, "\" showname=\"");
            s = xdb_escaped_xml(s, label_ptr);
        }

        if (PROTO_ITEM_IS_HIDDEN(node))
            s = g_stpcpy(s, "\" hide=\"yes");

        len = g_sprintf(s, "\" size=\"%d", fi->length); s += len;
        len = g_sprintf(s, "\" pos=\"%d", fi->start);   s += len;
        /* fprintf(pdata->fh, "\" id=\"%d", fi->hfinfo->id);*/

        /* show, value, and unmaskedvalue attributes */
        switch (fi->hfinfo->type)
        {
            case FT_PROTOCOL:
                break;
            case FT_NONE:
                s = g_stpcpy(s, "\" show=\"\" value=\"");
                break;
            default:
                /* XXX - this is a hack until we can just call
                 * fvalue_to_string_repr() for *all* FT_* types. */
                dfilter_string = proto_construct_match_selected_string(fi,
                        pdata->edt);
                if (dfilter_string != NULL) {
                    chop_len = strlen(fi->hfinfo->abbrev) + 4; /* for " == " */

                    /* XXX - Remove double-quotes. Again, once we
                     * can call fvalue_to_string_repr(), we can
                     * ask it not to produce the version for
                     * display-filters, and thus, no
                     * double-quotes. */
                    if (dfilter_string[strlen(dfilter_string)-1] == '"') {
                        dfilter_string[strlen(dfilter_string)-1] = '\0';
                        chop_len++;
                    }

                    s = g_stpcpy(s, "\" show=\"");
                    s = xdb_escaped_xml(s, &dfilter_string[chop_len]);
                }

                /*
                 * XXX - should we omit "value" for any fields?
                 * What should we do for fields whose length is 0?
                 * They might come from a pseudo-header or from
                 * the capture header (e.g., time stamps), or
                 * they might be generated fields.
                 */
                if (fi->length > 0) {
                    s = g_stpcpy(s, "\" value=\"");

                    if (fi->hfinfo->bitmask!=0) {
                        len = g_sprintf(s, "%X", fvalue_get_uinteger(&fi->value)); s += len;
                        s = g_stpcpy(s, "\" unmaskedvalue=\"");
                        s = xdb_field_to_hex_value(s, pdata, fi);
                    }
                    else {
                        s = xdb_field_to_hex_value(s, pdata, fi);
                    }
                }
        }

        if (node->first_child != NULL) {
            s = g_stpcpy(s, "\">\n");
        }
        else if (fi->hfinfo->id == proto_data) {
            s = g_stpcpy(s, "\">\n");
        }
        else {
            s = g_stpcpy(s, "\"/>\n");
        }
    }

    /* We always print all levels for PDML. Recurse here. */
    if (node->first_child != NULL) {
        pdata->level++;
        pdata->tmp = s; /* store  */
        proto_tree_children_foreach(node,
                xdb_proto_tree_to_xml, pdata);
        pdata->level--;
        s = pdata->tmp; /* back */
    }

    /* Take back the extra level we added for fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        pdata->level--;
    }

    if (node->first_child != NULL) {
        /* Indent to correct level */
        for (i = -1; i < pdata->level; i++) {
            s = g_stpcpy(s, "  ");
        }
        /* Close off current element */
        if (fi->hfinfo->id != proto_data) {   /* Data protocol uses simple tags */
            if (fi->hfinfo->type == FT_PROTOCOL) {
                s = g_stpcpy(s, "</proto>\n");
            }
            else {
                s = g_stpcpy(s, "</field>\n");
            }
        }
    }

    /* Close off fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        s = g_stpcpy(s, "</proto>\n");
    }

    pdata->tmp = s;
}

/**
 * record_idx : -1 for search
 */
static void
xdb_record_add_field(struct record_t *record,
                     GQuark node_name,
                     GQuark field_name,
                     int record_idx,
                     enum XDB_TYPE type,
                     char *str)
{
    if (record_idx == -1) {
        record_idx = *(int *)g_hash_table_lookup(g_name_idx_tbl, &field_name);
    }

    if (record->v[record_idx].str != NULL) {
        WARN("Duplicate column %s, drop it.\n", g_quark_to_string(field_name));
        g_free(str);
        return;
    }

    record->v[record_idx].name = field_name;
    record->v[record_idx].type = type;
    record->v[record_idx].str = str;

    if (record_idx > record->max_idx)
        record->max_idx = record_idx;

    DBG("Add field: %s[%d][%s]: %s\n",
         g_quark_to_string(node_name),
         record_idx,
         g_quark_to_string(field_name),
         str);
}

static gboolean g_service_name_found = FALSE;
static void
xdb_add_gsm_service_name(proto_node *node, gpointer tdata)
{
    field_info *fi = PNODE_FINFO(node);
    struct get_fields_data *pdata = (struct get_fields_data *) tdata;
    gchar	*label_ptr;

    // quick return
    if (g_service_name_found)
        return;

    /* text label */
    if (fi->hfinfo->id == hf_text_only) {
        /* get the show name */
        if (fi->rep) {
            label_ptr = fi->rep->representation;
        } else {
            label_ptr = "";
        }
        if (g_str_has_prefix(label_ptr, "Service Type:")) {
            DBG("found service name %s\n", label_ptr);
            xdb_record_add_field(&pdata->record,
                                 quark_gsm_service_name,
                                 quark_gsm_service_name,
                                 -1,
                                 TYPE_STR,
                                 g_strdup(label_ptr));
            g_service_name_found = TRUE;
        }
    } else if (fi->hfinfo->id == proto_data) {
        //ignore
    } else {
        //ignore
    }

    if (node->first_child != NULL) {
        proto_tree_children_foreach(node, xdb_add_gsm_service_name, pdata);
    }
}
static void
xdb_add_application_params(proto_node *node, gpointer tdata)
{
    struct get_fields_data *pdata = (struct get_fields_data *) tdata;

    pdata->proto_level++;
    if (pdata->proto_level >= 9) {
        xdb_proto_tree_to_xml(node, pdata);
    }
}
static void
xdb_add_ranap_sai_strings(proto_node *node, gpointer tdata)
{
    field_info *fi = PNODE_FINFO(node);
    struct get_fields_data *pdata = (struct get_fields_data *) tdata;

    /* text label */
    if (fi->hfinfo->id == hf_text_only) {
        //ignore.
    } else if (fi->hfinfo->id == proto_data) {
        //ignore
    } else {
        GQuark name = g_quark_from_string(fi->hfinfo->abbrev);
        GQuark search_name;
        struct key_t key;
        struct attr_t *attr;
        char *dfilter_string;
        size_t chop_len;

        if (name == quark_ranap_sai_plMNidentity)
            search_name = quark_ranap_sai_plMNidentity_hide;
        else if (name == quark_ranap_sai_lac)
            search_name = quark_ranap_sai_lac_hide;
        else if (name ==quark_ranap_sai_sac)
            search_name = quark_ranap_sai_sac_hide;
        else if (name == quark_ranap_sai_mcc)
            search_name = quark_ranap_sai_mcc_hide;
        else if (name == quark_ranap_sai_mnc)
            search_name = quark_ranap_sai_mnc_hide;
        else
            goto out;

        key.name = search_name;
        key.in_gtp = pdata->record.gtp_parsed;
        attr = (struct attr_t *) g_hash_table_lookup(g_tbl, &key);
        g_assert(attr != NULL);
        switch(attr->type) {
            case TYPE_SHORT:
                xdb_record_add_field(&pdata->record,
                        search_name,
                        attr->xdb_field_name,
                        attr->field_idx,
                        attr->type,
                        g_strdup_printf("%u", fvalue_get_uinteger(&fi->value))
                        );
                break;
            case TYPE_STR:
                dfilter_string = proto_construct_match_selected_string(fi, pdata->edt);
                if (dfilter_string != NULL) {
                    chop_len = strlen(fi->hfinfo->abbrev) + 4; /* for " == " */
                    if (dfilter_string[strlen(dfilter_string)-1] == '"') {
                        dfilter_string[strlen(dfilter_string)-1] = '\0';
                        chop_len++;
                    }
                    xdb_record_add_field(&pdata->record,
                            search_name,
                            attr->xdb_field_name,
                            attr->field_idx,
                            attr->type,
                            g_strescape(&dfilter_string[chop_len], NULL)
                            );
                }
                break;
            default:
                ERR("Unexpected type in xdb_add_ranap_sai_strings \n");
        }
    }
out:
    if (node->first_child != NULL) {
        proto_tree_children_foreach(node, xdb_add_ranap_sai_strings, pdata);
    }
}

static void
xdb_add_ranap_procedure_string(proto_node *node, gpointer tdata)
{
    field_info *fi = PNODE_FINFO(node);
    struct get_fields_data *pdata = (struct get_fields_data *) tdata;
    gchar label_str[ITEM_LABEL_LENGTH];
    const gchar	*label_ptr;

    /* text label */
    if (fi->hfinfo->id == hf_text_only) {
        //ignore.
    } else if (fi->hfinfo->id == proto_data) {
        //ignore
    } else {
        GQuark name = g_quark_from_string(fi->hfinfo->abbrev);

        if (name == quark_ranap_value) {
            /* get first child element */
            pdata->record.ranap_value_parsed = TRUE;
        } else {
            /* child element */
            if (pdata->record.ranap_value_parsed) {
                /* save the show name */
                if (fi->rep) {
                    label_ptr = fi->rep->representation;
                } else {
                    label_ptr = label_str;
                    proto_item_fill_label(fi, label_str);
                }
                DBG("Found ranap.value name:%s showname: %s\n",
                        g_quark_to_string(name),
                        label_ptr);
                xdb_record_add_field(&pdata->record,
                                     name,
                                     quark_procedure,
                                     -1,
                                     TYPE_STR,
                                     g_strdup(label_ptr)
                                    );
                return;
            }
        }
    }

    if (node->first_child != NULL) {
        proto_tree_children_foreach(node, xdb_add_ranap_procedure_string, pdata);
    }
}

static void
proto_tree_get_fields(proto_node *node, gpointer tdata)
{
    field_info *fi = PNODE_FINFO(node);
    struct get_fields_data *pdata = (struct get_fields_data *) tdata;
    char *dfilter_string;
    size_t chop_len;

    if (pdata->record.db == DB_DROP)
        return;

    /* text label */
    if (fi->hfinfo->id == hf_text_only) {
        //ignore.
    } else if (fi->hfinfo->id == proto_data) {
        /* uninterpreted data, add to DataParams field */
#if 1
        if (pdata->record.db == DB_DATA && pdata->proto_level <= 9) {
            pdata->tmp = &pdata->xml_buffer[0];
            xdb_proto_tree_to_xml(node, pdata);
            xdb_record_add_field(&pdata->record,
                                 quark_data,
                                 quark_data,
                                 -1,
                                 TYPE_XML,
                                 g_strdup(pdata->xml_buffer)
                                );
        }
#endif
    } else {
        GQuark name = g_quark_from_string(fi->hfinfo->abbrev);

        /* normal protocols and fields */
        if (fi->hfinfo->type == FT_PROTOCOL) {
            struct attr_t *attr;
            struct key_t key;
            //proto_node *t_node;

            pdata->proto_level++;
#if 0
            if (pdata->proto_level == 9 && pdata->record.db == DB_DATA) {
                /* frame:eth:vlan:ip:udp:gtp:ip:tcp */
                /* frame:eth:vlan:ip:udp:gtp:ip:utp */
                /* save all other data as Application data in xml node */
                /* retrive the proto to xml string */
                if (opt_add_application_params) {
                    pdata->tmp = &pdata->xml_buffer[0];
                    t_node = node;
                    while (t_node) {
                        xdb_proto_tree_to_xml(t_node, pdata);
                        t_node = t_node->next;
                    }
                    xdb_record_add_field(&pdata->record,
                            name,
                            quark_application,
                            -1,
                            TYPE_XML,
                            g_strdup(pdata->xml_buffer)
                            );
                }
            }
#endif

            /* deal with protol gtp */
            if (name == quark_gtp) {
                pdata->record.gtp_parsed = TRUE;
            } else if (name == quark_m3ua) {

                if (pdata->record.m3ua_level > 0) {
                    DBG("M3UA wrapper index: %d\n", pdata->record.m3ua_level);
                    /* save current fields */
                    if (xdb_save_to_odbc) {
                        if (xdb_save_packet(pdata, FALSE)!= 0) {
                            xdb_record_release(&pdata->record, 0);
                            return;
                        }
                    }

                    /* release m3ua wrapped fields */
                    xdb_record_release(&pdata->record, pdata->record.fields_idx_before_m3ua);
                } else {
                    /* set up the shared fields boundary */
                    pdata->record.fields_idx_before_m3ua = pdata->record.max_idx;
                }
                ++pdata->record.m3ua_level;
            } else if (name == quark_gsm) {
#if 0
                //TODO: what is the actual field name ?
                /* find the service name - */
                if (node->first_child != NULL) {
                    g_service_name_found = FALSE;
                    proto_tree_children_foreach(node, xdb_add_gsm_service_name, pdata);
                }
#endif
            }

            key.name = name;
            key.in_gtp = pdata->record.gtp_parsed;

            attr = (struct attr_t *) g_hash_table_lookup(g_tbl, &key);
            if (attr) {
                /* At present, XML data seems always is the proto. */
                BUG_ON(attr->type != TYPE_XML);

                if (name == quark_http) {
                    if (pdata->record.http_parsed)
                        goto out;
                    else
                        pdata->record.http_parsed = TRUE;
                }
                /* retrive the proto to xml string */
                pdata->tmp = &pdata->xml_buffer[0];
                xdb_proto_tree_to_xml(node, pdata);
                xdb_record_add_field(&pdata->record,
                                     name,
                                     attr->xdb_field_name,
                                     attr->field_idx,
                                     attr->type,
                                     g_strdup(pdata->xml_buffer)
                                    );
            }
        } else {
            /* Deal with protocol fields */
            struct key_t key;
            struct attr_t *attr;
            nstime_t *timestamp;

            /* Before we process this packet, check the protocol pattern
             * first, this will drop packets we do not care about.*/
            if (name == quark_frame_protocols) {
                dfilter_string = proto_construct_match_selected_string(fi, pdata->edt);
                if (dfilter_string != NULL) {
                    chop_len = strlen(fi->hfinfo->abbrev) + 4; /* for " == " */
                    if (dfilter_string[strlen(dfilter_string)-1] == '"') {
                        dfilter_string[strlen(dfilter_string)-1] = '\0';
                        chop_len++;
                    }
                    pdata->record.protocol = g_quark_from_string(&dfilter_string[chop_len]);
                    INFO("%s: %s\n", g_quark_to_string(name), &dfilter_string[chop_len]);
                    if (g_str_has_prefix(&dfilter_string[chop_len], "eth:vlan:ip:udp:gtp:ip")) {
                        if (strstr(&dfilter_string[chop_len], ":icmp")) {
                            /* drop icmp packet */
                            pdata->record.db = DB_DROP;
                            ++xstats.packet_dropped;
                            return;
                        }
                        pdata->record.db = DB_DATA;
                    } else if (g_str_has_prefix(&dfilter_string[chop_len], "eth:vlan:ip:sctp:m3ua:sccp")) {
                        pdata->record.db = DB_SIGNAL;
                    } else {
                        /* drop this packet */
                        INFO("drop packet pattern %s: %s\n", g_quark_to_string(name), &dfilter_string[chop_len]);
                        pdata->record.db = DB_DROP;
                        ++xstats.packet_dropped;
                        return;
                    }
                }
            } else if (name == quark_ranap_sai) {
                xdb_add_ranap_sai_strings(node, pdata);
            } else {
                /* Check and save the field if required. */
                key.name = name;
                key.in_gtp = pdata->record.gtp_parsed;

                attr = (struct attr_t *) g_hash_table_lookup(g_tbl, &key);
                if (attr) {
                    /* try insert to record */
                    switch (attr->type) {
                        case TYPE_DATE:
                            timestamp = (nstime_t *) fvalue_get(&fi->value);
                            xdb_record_add_field(&pdata->record,
                                                 name,
                                                 attr->xdb_field_name,
                                                 attr->field_idx,
                                                 attr->type,
                                                 xdb_abs_time_to_str(timestamp)
                                                );
                            /* add timestamp.ns field */
                            xdb_record_add_field(&pdata->record,
                                                 name,
                                                 quark_gnsecs,
                                                 -1,
                                                 TYPE_INT,
                                                 g_strdup_printf("%09ld", (long)timestamp->nsecs)
                                                );
                            break;
                        case TYPE_SHORT:
                        case TYPE_INT:
                        case TYPE_BIGINT:
                            xdb_record_add_field(&pdata->record,
                                                 name,
                                                 attr->xdb_field_name,
                                                 attr->field_idx,
                                                 attr->type,
                                                 g_strdup_printf("%u", fvalue_get_uinteger(&fi->value))
                                                );
                            break;
                        case TYPE_STR:
                            dfilter_string = proto_construct_match_selected_string(fi, pdata->edt);
                            if (dfilter_string != NULL) {
                                chop_len = strlen(fi->hfinfo->abbrev) + 4; /* for " == " */
                                if (dfilter_string[strlen(dfilter_string)-1] == '"') {
                                    dfilter_string[strlen(dfilter_string)-1] = '\0';
                                    chop_len++;
                                }
                                if (name == quark_data_data) {
                                    /**
                                     * if the protocol marker:
                                     *  eth:vlan:ip:udp:gtp:ip:udp:data
                                     * write the 50 chars of  data.data field to the field.
                                     */
                                    if (pdata->record.protocol == quark_udp_data) {
                                        char * dup = g_strndup(&dfilter_string[chop_len], 150);
                                        xdb_record_add_field(&pdata->record,
                                                             name,
                                                             attr->xdb_field_name,
                                                             attr->field_idx,
                                                             attr->type,
                                                             g_strescape(dup, NULL)
                                                            );
                                        g_free(dup);
                                    }
                                } else {
                                    xdb_record_add_field(&pdata->record,
                                                         name,
                                                         attr->xdb_field_name,
                                                         attr->field_idx,
                                                         attr->type,
                                                         g_strescape(&dfilter_string[chop_len], NULL)
                                                        );
                                }
                            }
                            break;
                        case TYPE_XML:
                            /* add xml string to fields array */
                            pdata->tmp = &pdata->xml_buffer[0];
                            xdb_proto_tree_to_xml(node, pdata);
                            xdb_record_add_field(&pdata->record,
                                                 name,
                                                 attr->xdb_field_name,
                                                 attr->field_idx,
                                                 attr->type,
                                                 g_strdup(pdata->xml_buffer)
                                                );

                            break;
                        default:
                            ERR("Error: unknown attr->type.\n");
                            xdb_error = 1;
                            return;
                    }

                    /* check if this is a ranap field we need speical processing */
                    if (name == quark_ranap) {
                        /* add procedule string under the value field */
                        pdata->record.ranap_value_parsed = FALSE;
                        xdb_add_ranap_procedure_string(node, pdata);

                        if (opt_add_ranap_params) {
                            /* add ranap PDU as xml node */
                            pdata->tmp = &pdata->xml_buffer[0];
                            xdb_proto_tree_to_xml(node, pdata);
                            xdb_record_add_field(&pdata->record,
                                    name,
                                    quark_ranappdu,
                                    -1,
                                    TYPE_XML,
                                    g_strdup(pdata->xml_buffer)
                                    );
                            /* continue for further required fields */
                        }
                    }
                }
            }
        }
    }
out:
    if (node->first_child != NULL) {
        proto_tree_children_foreach(node, proto_tree_get_fields, pdata);
    }
}

static int
xdb_open_files(void)
{
    /* open xdb data files for write */
    f_data = fopen(DATA_FILE, "w");
    if (!f_data) {
        perror("fopen");
        return -1;
    }

    f_signal = fopen(SIGNAL_FILE, "w");
    if (!f_signal) {
        perror("fopen");
        return -1;
    }

    return 0;
}

static int
xdb_create_views(void)
{
    int ret;

    ret = xodbc_execute(bulk_create_data_view_sql);
    if (ret != 0)
        return ret;

    ret = xodbc_execute(bulk_create_signal_view_sql);

    return ret;
}

static int
xdb_drop_views(void)
{
    int ret;

    ret = xodbc_execute("DROP VIEW "BULK_DATA_VIEW);
    ret = xodbc_execute("DROP VIEW "BULK_SIGNAL_VIEW);

    return 0;
}


gpointer xdb_bulk_thread_func(gpointer p)
{
    enum XDB_NAME db = (enum XDB_NAME) p;
    int ret;

    if (db == DB_DATA) {
        g_mutex_lock(bulk_insert_data_mutex);
        ret = xodbc_execute(bulk_insert_data_sql);
        if (ret == 0)
            g_unlink(DATA_FILE_BULK);
        g_mutex_unlock(bulk_insert_data_mutex);
    } else if (db == DB_SIGNAL) {
        g_mutex_lock(bulk_insert_signal_mutex);
        ret = xodbc_execute(bulk_insert_signal_sql);
        if (ret == 0)
            g_unlink(SIGNAL_FILE_BULK);
        g_mutex_unlock(bulk_insert_signal_mutex);
    } else {
        ERR("%s\n", "Unknown thread param.");
        ret = -1;
    }

    return (gpointer)ret;
}

GThread *data_thread;
GThread *signal_thread;

static int
xdb_bulk_insert(enum XDB_NAME db, gboolean join)
{

    if (opt_show_progress) {
        fprintf(stdout, "BULK INSERT\n");
        fflush(stdout);
    }

    if (db == DB_DATA) {
        fclose(f_data);
        g_mutex_lock(bulk_insert_data_mutex);
        g_rename(DATA_FILE, DATA_FILE_BULK);
        g_mutex_unlock(bulk_insert_data_mutex);
        data_thread = g_thread_create(xdb_bulk_thread_func, (gpointer) db, join, NULL);
        if (join) {
            g_thread_join(data_thread);
        }
        f_data = fopen(DATA_FILE, "w");
        if (!f_data) {
            perror("fopen");
            return -1;
        }
        return 0;
    }

    if (db == DB_SIGNAL) {
        fclose(f_signal);
        g_mutex_lock(bulk_insert_signal_mutex);
        g_rename(SIGNAL_FILE, SIGNAL_FILE_BULK);
        g_mutex_unlock(bulk_insert_signal_mutex);
        signal_thread = g_thread_create(xdb_bulk_thread_func, (gpointer) db, join, NULL);
        if (join) {
            g_thread_join(signal_thread);
        }
        f_signal = fopen(SIGNAL_FILE, "w");
        if (!f_signal) {
            perror("fopen");
            return -1;
        }
        return 0;
    }

    return -1 ;
}

/* xdb_save_packet - save packet to database
 */
static int
xdb_save_packet(struct get_fields_data *pdata, gboolean release)
{
    int ret = 0;
    FILE *f;
    int count, i;

    if (pdata->record.db == DB_UNDEF || pdata->record.db == DB_DROP) {
        goto free_data;
    }

    if (pdata->record.db == DB_DATA) {
        ++xstats.packet_data;
        ++xstats.packet_data_interval;
        f = f_data;
        count = data_idx;
    } else {
        ++xstats.packet_signal;
        ++xstats.packet_signal_interval;
        f = f_signal;
        count = signal_idx;
        /* fake M3uaSequenceNumber insert */
        xdb_record_add_field(&pdata->record,
                quark_m3ua_index,
                quark_m3ua_index,
                -1,
                TYPE_INT,
                g_strdup_printf("%d", pdata->record.m3ua_level)
                );
    }

    if (xdb_save_to_odbc) {
        ++xstats.packet_saved;
        /* write to temp data file */
        for (i = 0; i < count; i++) {
            if (pdata->record.v[i].str) {
                fprintf(f, "%s'", pdata->record.v[i].str);
            } else {
                fprintf(f, "'");
            }
        }
        fprintf(f, "\n");
        ret = 0;

        /* call bulk insert if necessary */
        if (xstats.packet_data_interval == opt_data_bulk_insert_step) {
            xstats.packet_data_interval = 0;
            ret = xdb_bulk_insert(DB_DATA, FALSE);
        }
        else
        if (xstats.packet_signal_interval == opt_signal_bulk_insert_step) {
            xstats.packet_signal_interval = 0;
            ret = xdb_bulk_insert(DB_SIGNAL, FALSE);
        }
    }

    /* release the record */
free_data:
    if (release)
        xdb_record_release(&pdata->record, 0);

    return ret;
}
static struct get_fields_data data;
/*
 * insert packet to odbc source
 */
int xdb_process_packet(epan_dissect_t *edt)
{

    /* set up record */
    data.record.max_idx = 0;
    data.record.gtp_parsed = FALSE;
    data.record.http_parsed = FALSE;
    data.record.m3ua_level = 0;
    data.record.db = DB_UNDEF;

    /* setup tree traversal parameter */
    data.edt = edt;
    data.level = 0;
    data.proto_level = 0;
    data.tmp = &data.xml_buffer[0];
    data.xml_buffer[0] = '\0';
    data.src_list = edt->pi.data_src;
    xdb_error = 0;

    /* check protocols */
    proto_tree_children_foreach(edt->tree, proto_tree_get_fields, &data);

    /* save all nodes upon tcp/udp layer */
#if 1
    if (opt_add_application_params && data.record.db == DB_DATA) {
        data.proto_level = 0;
        data.tmp = &data.xml_buffer[0];
        data.xml_buffer[0] = '\0';
        proto_tree_children_foreach(edt->tree, xdb_add_application_params, &data);

        if (data.xml_buffer[0] != '\0') {
            xdb_record_add_field(&data.record,
                    quark_application,
                    quark_application,
                    -1,
                    TYPE_XML,
                    g_strdup(data.xml_buffer)
                    );
        }
    }
#endif

    if (xdb_error) {
        return xdb_error;
    }

    if (xdb_save_packet(&data, TRUE)!= 0)
        return -1;

    return 0;
}

static char *
xdb_ctype_to_sqltype(enum XDB_TYPE type)
{
    switch (type) {
        case TYPE_INT:
            return "SQLINT";
        case TYPE_SHORT:
            return "SQLSMALLINT";
        case TYPE_STR:
            return "SQLNVARCHAR";
        case TYPE_XML:
            return "SQLVARYCHAR";
        case TYPE_BIGINT:
            return "SQLBIGINT";
        case TYPE_DATE:
            return "SQLDATETIME";
        default:
            return "ERROR";
    }
}

static int
xdb_create_format_files(void)
{
    int i;
    int _di;
    int _si;
    FILE *f_data_format;
    FILE *f_signal_format;
    char *term;

    /* create bulk insert format file */
    f_data_format = fopen(DATA_FILE_FORMAT, "w");
    if (!f_data_format) {
        perror("fopen");
        return -1;
    }
    f_signal_format = fopen(SIGNAL_FILE_FORMAT, "w");
    if (!f_signal_format) {
        perror("fopen");
        return -1;
    }
    fprintf(f_data_format, "<?xml version=\"1.0\"?>\n");
    fprintf(f_data_format, "<BCPFORMAT xmlns=\"http://schemas.microsoft.com/"
                           "sqlserver/2004/bulkload/format\" xmlns:xsi=\"http:"
                           "//www.w3.org/2001/XMLSchema-instance\">\n");
    fprintf(f_data_format, "\t<RECORD>\n");
    fprintf(f_signal_format, "<?xml version=\"1.0\"?>\n");
    fprintf(f_signal_format, "<BCPFORMAT xmlns=\"http://schemas.microsoft.com/"
                           "sqlserver/2004/bulkload/format\" xmlns:xsi=\"http:"
                           "//www.w3.org/2001/XMLSchema-instance\">\n");
    fprintf(f_signal_format, "\t<RECORD>\n");
    for (i = 0, _di = 0, _si = 0; i < FIELDS_SIZE; i++) {
        if (xdb_fields[i].dbname == DB_BOTH) {
            _di++;
            _si++;
            term = "'";
            fprintf(f_data_format, "\t\t<FIELD ID=\"%d\" xsi:type=\"CharTerm\" "
                    "TERMINATOR=\"%s\" />\n",
                    _di,
                    term
                    );
            fprintf(f_signal_format, "\t\t<FIELD ID=\"%d\" xsi:type=\"CharTerm\" "
                    "TERMINATOR=\"%s\" />\n",
                    _si,
                    term
                    );
        } else if (xdb_fields[i].dbname == DB_DATA) {
            _di++;
            if (_di == data_idx) {
                term = "'\\r\\n";
            } else {
                term = "'";
            }
            fprintf(f_data_format, "\t\t<FIELD ID=\"%d\" xsi:type=\"CharTerm\" "
                    "TERMINATOR=\"%s\" />\n",
                    _di,
                    term
                    );
        } else if (xdb_fields[i].dbname == DB_SIGNAL) {
            _si ++;
            if (_si == signal_idx) {
                term = "'\\r\\n";
            } else {
                term = "'";
            }
            fprintf(f_signal_format, "\t\t<FIELD ID=\"%d\" xsi:type=\"CharTerm\" "
                    "TERMINATOR=\"%s\" />\n",
                    _si,
                    term
                    );
        }
    }
    fprintf(f_data_format, "\t</RECORD>\n\t<ROW>\n");
    fprintf(f_signal_format, "\t</RECORD>\n\t<ROW>\n");
    for (i = 0, _di = 0, _si = 0; i < FIELDS_SIZE; i++) {
        if (xdb_fields[i].dbname == DB_BOTH) {
            _di++;
            _si++;
            fprintf(f_data_format, "\t\t<COLUMN SOURCE=\"%d\" NAME=\"%s\" "
                    "xsi:type=\"%s\" />\n",
                    _di,
                    xdb_fields[i].xdb_field_name,
                    xdb_ctype_to_sqltype(xdb_fields[i].type)
                    );
            fprintf(f_signal_format, "\t\t<COLUMN SOURCE=\"%d\" NAME=\"%s\" "
                    "xsi:type=\"%s\" />\n",
                    _si,
                    xdb_fields[i].xdb_field_name,
                    xdb_ctype_to_sqltype(xdb_fields[i].type)
                    );
        } else if (xdb_fields[i].dbname == DB_DATA) {
            _di++;
            fprintf(f_data_format, "\t\t<COLUMN SOURCE=\"%d\" NAME=\"%s\" "
                    "xsi:type=\"%s\" />\n",
                    _di,
                    xdb_fields[i].xdb_field_name,
                    xdb_ctype_to_sqltype(xdb_fields[i].type)
                    );
        } else if (xdb_fields[i].dbname == DB_SIGNAL) {
            _si ++;
            fprintf(f_signal_format, "\t\t<COLUMN SOURCE=\"%d\" NAME=\"%s\" "
                    "xsi:type=\"%s\" />\n",
                    _si,
                    xdb_fields[i].xdb_field_name,
                    xdb_ctype_to_sqltype(xdb_fields[i].type)
                    );
        }
    }

    fprintf(f_data_format, "\t</ROW>\n</BCPFORMAT>\n");
    fprintf(f_signal_format, "\t</ROW>\n</BCPFORMAT>\n");
    fclose(f_data_format);
    fclose(f_signal_format);
    return 0;
}

/*
 * connect to odbc source
 * initialize the hash table.
 */
int xdb_init(char *dsn)
{
    int hex2ascii_len = 256;
    int i;
    int err;
    char *tmp_d, *tmp_s;

    /* Initialize field name hash table for search */
    g_tbl = g_hash_table_new_full(hash_func, equal_func, NULL, NULL);
    if (g_tbl == NULL) {
        fprintf(stderr, "ERROR: g_hash_table_new_full\n");
        return -1;
    }
    /* Initialize dabase field name hash table for sqlprepare insert */
    g_name_idx_tbl = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, NULL);
    if (g_name_idx_tbl == NULL) {
        fprintf(stderr, "ERROR: g_hash_table_new_full\n");
        return -1;
    }

    /* Initialize sql string to create data/signal view for bulk insert */
    bulk_create_data_view_sql[0] = '\0';
    bulk_create_signal_view_sql[0] = '\0';

    tmp_d = g_stpcpy(bulk_create_data_view_sql, "CREATE VIEW " BULK_DATA_VIEW " AS select ");
    tmp_s = g_stpcpy(bulk_create_signal_view_sql, "CREATE VIEW " BULK_SIGNAL_VIEW " AS select ");
    for (i = 0; i < FIELDS_SIZE; i++) {
        keys[i].name = g_quark_from_string(xdb_fields[i].xshark_field_name);
        keys[i].in_gtp = xdb_fields[i].in_gtp;
        attrs[i].xdb_field_name = g_quark_from_string(xdb_fields[i].xdb_field_name);
        attrs[i].allow_null = xdb_fields[i].allow_null;
        attrs[i].type = xdb_fields[i].type;
        if (xdb_fields[i].dbname == DB_BOTH) {
            g_assert(data_idx == signal_idx);
            attrs[i].field_idx = data_idx;
            g_hash_table_insert(g_name_idx_tbl,
                                &attrs[i].xdb_field_name, &attrs[i].field_idx);
            if (i != 0) {
                tmp_d = g_stpcpy(tmp_d, ",");
                tmp_s = g_stpcpy(tmp_s, ",");
            }
            tmp_d = g_stpcpy(tmp_d, xdb_fields[i].xdb_field_name);
            tmp_s = g_stpcpy(tmp_s, xdb_fields[i].xdb_field_name);
            data_idx++;
            signal_idx++;
        } else if (xdb_fields[i].dbname == DB_DATA) {
            attrs[i].field_idx = data_idx;
            g_hash_table_insert(g_name_idx_tbl,
                                &attrs[i].xdb_field_name, &attrs[i].field_idx);
            if (i != 0) {
                tmp_d = g_stpcpy(tmp_d, ",");
            }
            tmp_d = g_stpcpy(tmp_d, xdb_fields[i].xdb_field_name);
            data_idx++;
        } else if (xdb_fields[i].dbname == DB_SIGNAL) {
            attrs[i].field_idx = signal_idx;
            g_hash_table_insert(g_name_idx_tbl,
                                &attrs[i].xdb_field_name, &attrs[i].field_idx);
            if (i != 0) {
                tmp_s = g_stpcpy(tmp_s, ",");
            }
            tmp_s = g_stpcpy(tmp_s, xdb_fields[i].xdb_field_name);
            signal_idx++;
        }
        g_hash_table_insert(g_tbl, &keys[i], &attrs[i]);
    }

    tmp_d = g_stpcpy(tmp_d, " from dbo.tbIUPACKETDATA");
    tmp_s = g_stpcpy(tmp_s, " from dbo.tbIuPSSignalPacket");

    if (dsn) {
        xdb_save_to_odbc = TRUE;
        err = xodbc_init(dsn);
        if (err < 0)
            return err;
        /* ignore create view error */
        err = xdb_create_views();
#if 0
        if (err != 0)
            return err;
#endif
    }

    /* Initialize thread mutexes  */
    bulk_insert_data_mutex = g_mutex_new();
    bulk_insert_signal_mutex = g_mutex_new();

    /* Initialize quark ids which need special processing */
    quark_frame_protocols = g_quark_from_string("frame.protocols");
    quark_gtp = g_quark_from_string("gtp");
    quark_gnsecs = g_quark_from_string("PacketArrivalInstant");
    quark_ranap = g_quark_from_string("ranap.RANAP_PDU");
    quark_ranap_value = g_quark_from_string("ranap.value");
    quark_m3ua = g_quark_from_string("m3ua");
    quark_m3ua_index = g_quark_from_string("M3uaSequenceNumber");
    quark_http = g_quark_from_string("http");
    quark_application = g_quark_from_string("ApplicationDataParams");
    quark_data = g_quark_from_string("DataParams");
    quark_procedure = g_quark_from_string(PROCEDURENAME);
    quark_ranappdu = g_quark_from_string(RANAPPDUPARAMS);
    quark_udp_data = g_quark_from_string("eth:vlan:ip:udp:gtp:ip:udp:data");
    quark_data_data = g_quark_from_string("data.data");
    quark_ranap_sai = g_quark_from_string("ranap.SAI");
    quark_ranap_sai_plMNidentity = g_quark_from_string("ranap.pLMNidentity");
    quark_ranap_sai_plMNidentity_hide = g_quark_from_string("ranap.pLMNidentity.hide");
    quark_ranap_sai_mcc = g_quark_from_string("e212.mcc");
    quark_ranap_sai_mcc_hide = g_quark_from_string("e212.mcc.hide");
    quark_ranap_sai_mnc = g_quark_from_string("e212.mnc");
    quark_ranap_sai_mnc_hide = g_quark_from_string("e212.mnc.hide");
    quark_ranap_sai_lac = g_quark_from_string("ranap.lAC");
    quark_ranap_sai_lac_hide = g_quark_from_string("ranap.lAC.hide");
    quark_ranap_sai_sac = g_quark_from_string("ranap.sAC");
    quark_ranap_sai_sac_hide = g_quark_from_string("ranap.sAC.hide");
    quark_gsm = g_quark_from_string("gsm_a_dtap");
    quark_gsm_service_name = g_quark_from_string("GsmServiceType");

    /* initialize hex2ascii array */
    hex2ascii = malloc(hex2ascii_len*sizeof(char*));
    for(i=0; i < hex2ascii_len; i++) {
        hex2ascii[i] = malloc(3*sizeof(char));
        g_snprintf(hex2ascii[i], 3,"%02X", i);
    }


    /* create format file and open file to bulk data file write */
    xdb_create_format_files();
    xdb_open_files();

    /* Initialize bulk insert sql strings */
    g_sprintf(bulk_insert_data_sql, "BULK INSERT "BULK_DATA_VIEW" FROM '%s' WITH ( DATAFILETYPE = 'char', FORMATFILE = '%s')",
                DATA_FILE_BULK, DATA_FILE_FORMAT);
    g_sprintf(bulk_insert_signal_sql, "BULK INSERT "BULK_SIGNAL_VIEW" FROM '%s' WITH ( DATAFILETYPE = 'char', FORMATFILE = '%s')",
                SIGNAL_FILE_BULK, SIGNAL_FILE_FORMAT);
    return 0;
}

int xdb_close(void)
{
    int err;

    if (xdb_save_to_odbc) {
        if (xstats.packet_data_interval != 0) {
            err = xdb_bulk_insert(DB_DATA, TRUE);
        }
        if (xstats.packet_signal_interval != 0) {
            err = xdb_bulk_insert(DB_SIGNAL, TRUE);
        }

        err = xdb_drop_views();
        err = xodbc_close();
        /* wait thread exit */
    }

    fclose(f_data);
    fclose(f_signal);

    g_hash_table_destroy(g_tbl);

    return 0;
}
