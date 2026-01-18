#ifndef CASPER_MAC_H
#define CASPER_MAC_H

#define SLOT(l)		 ((struct mac_casper *)mac_label_get((l), casper_slot))
#define SLOT_SET(l, val) (mac_label_set((l), casper_slot, (uintptr_t)(val)))

static const char *MAC_CASPER_LABEL_NAME = "casper"; /* Module label */

#endif // CASPER_MAC_H
