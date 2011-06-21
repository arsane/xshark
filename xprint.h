#ifndef XPRINT_H
#define XPRINT_H

#include <epan/epan_dissect.h>
extern void proto_tree_write_pdml(epan_dissect_t *edt, FILE *fh);
extern const guint8 * get_field_data(GSList *src_list, field_info *fi);

#endif
