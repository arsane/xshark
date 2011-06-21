#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <glib.h>
#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-data.h>
#include <epan/dissectors/packet-frame.h>
#include "xutils.h"
#include "xprint.h"

#define PNODE_FINFO(proto_node)  ((proto_node)->finfo)

#ifdef WIN32
#define ABS_TIME_TO_STR(x) abs_time_to_str(x, ABSOLUTE_TIME_UTC, TRUE)
#else
#define ABS_TIME_TO_STR(x) abs_time_to_str(x)
#endif

unsigned int opt_verbosity = 1;

/* Print a string, escaping out certain characters that need to
 * escaped out for XML. */
struct write_pdml_data {
    int level;
    FILE *fh;
    GSList *src_list;
    epan_dissect_t *edt;
};

static void
print_escaped_xml(FILE *fh, const char *unescaped_string)
{
    const char *p;
    char temp_str[8];

    for (p = unescaped_string; *p != '\0'; p++) {
        switch (*p) {
            case '&':
                fputs("&amp;", fh);
                break;
            case '<':
                fputs("&lt;", fh);
                break;
            case '>':
                fputs("&gt;", fh);
                break;
            case '"':
                fputs("&quot;", fh);
                break;
            case '\'':
                fputs("&apos;", fh);
                break;
            default:
                if (g_ascii_isprint(*p))
                    fputc(*p, fh);
                else {
                    g_snprintf(temp_str, sizeof(temp_str), "\\x%x", (guint8)*p);
                    fputs(temp_str, fh);
                }
        }
    }
}

/*
 * Find the data source for a specified field, and return a pointer
 * to the data in it. Returns NULL if the data is out of bounds.
 */
const guint8 *
get_field_data(GSList *src_list, field_info *fi)
{
    GSList *src_le;
    data_source *src;
    tvbuff_t *src_tvb;
    gint length, tvbuff_length;

    for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
        src = (data_source *)src_le->data;
        src_tvb = src->tvb;
        if (fi->ds_tvb == src_tvb) {
            /*
             * Found it.
             *
             * XXX - a field can have a length that runs past
             * the end of the tvbuff.  Ideally, that should
             * be fixed when adding an item to the protocol
             * tree, but checking the length when doing
             * that could be expensive.  Until we fix that,
             * we'll do the check here.
             */
            tvbuff_length = tvb_length_remaining(src_tvb,
                    fi->start);
            if (tvbuff_length < 0) {
                return NULL;
            }
            length = fi->length;
            if (length > tvbuff_length)
                length = tvbuff_length;
            return tvb_get_ptr(src_tvb, fi->start, length);
        }
    }

    g_assert_not_reached();
    return NULL;    /* not found */
}


static void
write_pdml_field_hex_value(struct write_pdml_data *pdata, field_info *fi)
{
    int i;
    const guint8 *pd;

    if (!fi->ds_tvb)
        return;

    if (fi->length > tvb_length_remaining(fi->ds_tvb, fi->start)) {
        fprintf(pdata->fh, "field length invalid!");
        return;
    }

    /* Find the data for this field. */
    pd = get_field_data(pdata->src_list, fi);

    if (pd) {
        /* Print a simple hex dump */
        for (i = 0 ; i < fi->length; i++) {
            fprintf(pdata->fh, "%02x", pd[i]);
        }
    }
}

/* Write out a tree's data, and any child nodes, as PDML */
static void
proto_tree_write_node_pdml(proto_node *node, gpointer data)
{
    field_info	*fi = PNODE_FINFO(node);
    struct write_pdml_data	*pdata = (struct write_pdml_data*) data;
    const gchar	*label_ptr;
    gchar label_str[ITEM_LABEL_LENGTH];
    char *dfilter_string;
    size_t chop_len;
    int i;
    gboolean wrap_in_fake_protocol;

    g_assert(fi && "dissection with an invisible proto tree?");

    /* Will wrap up top-level field items inside a fake protocol wrapper to
       preserve the PDML schema */
    wrap_in_fake_protocol =
        (((fi->hfinfo->type != FT_PROTOCOL) ||
          (fi->hfinfo->id == proto_data)) &&
         (pdata->level == 0));

    /* Indent to the correct level */
    for (i = -1; i < pdata->level; i++) {
        fputs("  ", pdata->fh);
    }

    if (wrap_in_fake_protocol) {
        /* Open fake protocol wrapper */
        fputs("<proto name=\"fake-field-wrapper\">\n", pdata->fh);

        /* Indent to increased level before writint out field */
        pdata->level++;
        for (i = -1; i < pdata->level; i++) {
            fputs("  ", pdata->fh);
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
        fputs("<field name=\"", pdata->fh);
        fputs("\" show=\"", pdata->fh);
        print_escaped_xml(pdata->fh, label_ptr);

        fprintf(pdata->fh, "\" size=\"%d", fi->length);
        fprintf(pdata->fh, "\" pos=\"%d", fi->start);

        fputs("\" value=\"", pdata->fh);
        write_pdml_field_hex_value(pdata, fi);

        if (node->first_child != NULL) {
            fputs("\">\n", pdata->fh);
        }
        else {
            fputs("\"/>\n", pdata->fh);
        }
    }

    /* Uninterpreted data, i.e., the "Data" protocol, is
     * printed as a field instead of a protocol. */
    else if (fi->hfinfo->id == proto_data) {

        /* Write out field with data */
        fputs("<field name=\"data\" value=\"", pdata->fh);
        write_pdml_field_hex_value(pdata, fi);
        fputs("\"/>\n", pdata->fh);
    }
    /* Normal protocols and fields */
    else {
        if (fi->hfinfo->type == FT_PROTOCOL) {
            fputs("<proto name=\"", pdata->fh);
        }
        else {
            fputs("<field name=\"", pdata->fh);
        }
        print_escaped_xml(pdata->fh, fi->hfinfo->abbrev);

        if (fi->rep) {
            fputs("\" showname=\"", pdata->fh);
            print_escaped_xml(pdata->fh, fi->rep->representation);
        }
        else {
            label_ptr = label_str;
            proto_item_fill_label(fi, label_str);
            fputs("\" showname=\"", pdata->fh);
            print_escaped_xml(pdata->fh, label_ptr);
        }

        if (PROTO_ITEM_IS_HIDDEN(node))
            fprintf(pdata->fh, "\" hide=\"yes");

        fprintf(pdata->fh, "\" size=\"%d", fi->length);
        fprintf(pdata->fh, "\" pos=\"%d", fi->start);
        /* fprintf(pdata->fh, "\" id=\"%d", fi->hfinfo->id);*/

        /* show, value, and unmaskedvalue attributes */
        switch (fi->hfinfo->type)
        {
            case FT_PROTOCOL:
                break;
            case FT_NONE:
                fputs("\" show=\"\" value=\"",  pdata->fh);
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

                    fputs("\" show=\"", pdata->fh);
                    print_escaped_xml(pdata->fh, &dfilter_string[chop_len]);
                }

                /*
                 * XXX - should we omit "value" for any fields?
                 * What should we do for fields whose length is 0?
                 * They might come from a pseudo-header or from
                 * the capture header (e.g., time stamps), or
                 * they might be generated fields.
                 */
                if (fi->length > 0) {
                    fputs("\" value=\"", pdata->fh);

                    if (fi->hfinfo->bitmask!=0) {
                        fprintf(pdata->fh, "%X", fvalue_get_uinteger(&fi->value));
                        fputs("\" unmaskedvalue=\"", pdata->fh);
                        write_pdml_field_hex_value(pdata, fi);
                    }
                    else {
                        write_pdml_field_hex_value(pdata, fi);
                    }
                }
        }

        if (node->first_child != NULL) {
            fputs("\">\n", pdata->fh);
        }
        else if (fi->hfinfo->id == proto_data) {
            fputs("\">\n", pdata->fh);
        }
        else {
            fputs("\"/>\n", pdata->fh);
        }
    }

    /* We always print all levels for PDML. Recurse here. */
    if (node->first_child != NULL) {
        pdata->level++;
        proto_tree_children_foreach(node,
                proto_tree_write_node_pdml, pdata);
        pdata->level--;
    }

    /* Take back the extra level we added for fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        pdata->level--;
    }

    if (node->first_child != NULL) {
        /* Indent to correct level */
        for (i = -1; i < pdata->level; i++) {
            fputs("  ", pdata->fh);
        }
        /* Close off current element */
        if (fi->hfinfo->id != proto_data) {   /* Data protocol uses simple tags */
            if (fi->hfinfo->type == FT_PROTOCOL) {
                fputs("</proto>\n", pdata->fh);
            }
            else {
                fputs("</field>\n", pdata->fh);
            }
        }
    }

    /* Close off fake wrapper protocol */
    if (wrap_in_fake_protocol) {
        fputs("</proto>\n", pdata->fh);
    }
}

static void
print_pdml_geninfo(proto_tree *tree, FILE *fh)
{
    guint32 num, len, caplen;
    nstime_t *timestamp;
    GPtrArray *finfo_array;
    field_info *frame_finfo;

    /* Get frame protocol's finfo. */
    finfo_array = proto_find_finfo(tree, proto_frame);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    frame_finfo = (field_info *)finfo_array->pdata[0];
    g_ptr_array_free(finfo_array, TRUE);

    /* frame.number --> geninfo.num */
    finfo_array = proto_find_finfo(tree, hf_frame_number);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    num = fvalue_get_uinteger(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    /* frame.frame_len --> geninfo.len */
    finfo_array = proto_find_finfo(tree, hf_frame_len);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    len = fvalue_get_uinteger(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    /* frame.cap_len --> geninfo.caplen */
    finfo_array = proto_find_finfo(tree, hf_frame_capture_len);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    caplen = fvalue_get_uinteger(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    /* frame.time --> geninfo.timestamp */
    finfo_array = proto_find_finfo(tree, hf_frame_arrival_time);
    if (g_ptr_array_len(finfo_array) < 1) {
        return;
    }
    timestamp = (nstime_t *)fvalue_get(&((field_info*)finfo_array->pdata[0])->value);
    g_ptr_array_free(finfo_array, TRUE);

    /* Print geninfo start */
    fprintf(fh,
            "  <proto name=\"geninfo\" pos=\"0\" showname=\"General information\" size=\"%u\">\n",
            frame_finfo->length);

    /* Print geninfo.num */
    fprintf(fh,
            "    <field name=\"num\" pos=\"0\" show=\"%u\" showname=\"Number\" value=\"%x\" size=\"%u\"/>\n",
            num, num, frame_finfo->length);

    /* Print geninfo.len */
    fprintf(fh,
            "    <field name=\"len\" pos=\"0\" show=\"%u\" showname=\"Frame Length\" value=\"%x\" size=\"%u\"/>\n",
            len, len, frame_finfo->length);

    /* Print geninfo.caplen */
    fprintf(fh,
            "    <field name=\"caplen\" pos=\"0\" show=\"%u\" showname=\"Captured Length\" value=\"%x\" size=\"%u\"/>\n",
            caplen, caplen, frame_finfo->length);

    /* Print geninfo.timestamp */
    fprintf(fh,
            "    <field name=\"timestamp\" pos=\"0\" show=\"%s\" showname=\"Captured Time\" value=\"%d.%09d\" size=\"%u\"/>\n",
            ABS_TIME_TO_STR(timestamp), (int) timestamp->secs, timestamp->nsecs, frame_finfo->length);

    /* Print geninfo end */
    fprintf(fh, "  </proto>\n");
}

void
proto_tree_write_pdml(epan_dissect_t *edt, FILE *fh)
{
    struct write_pdml_data data;

    data.level = 0;
    data.fh = fh;
    data.src_list = edt->pi.data_src;
    data.edt = edt;

    g_assert(data.src_list);
    fprintf(fh, "<packet>\n");

    print_pdml_geninfo(edt->tree, fh);

    proto_tree_children_foreach(edt->tree, proto_tree_write_node_pdml,
            &data);
    fprintf(fh, "</packet>\n\n");
}

