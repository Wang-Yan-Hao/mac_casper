#ifndef CASPER_MAC_H
#define CASPER_MAC_H

#define SLOT(l)		 ((struct mac_casper *)mac_label_get((l), casper_slot))
#define SLOT_SET(l, val) (mac_label_set((l), casper_slot, (uintptr_t)(val)))

#define MAC_SUB_EXTATTR_NAMESPACE EXTATTR_NAMESPACE_SYSTEM
#define MAC_SUB_EXTATTR_NAME	  "casper"

static const char *MAC_CASPER_LABEL_NAME = "casper"; /* Module label */

/* Label structure - Shared by Subject and Object */
struct mac_casper {
    unsigned short type;
};

#endif // CASPER_MAC_H
