#include "internal.h"

static uma_zone_t zone_casper;

/* init */
void
casper_init(struct mac_policy_conf *conf)
{
	/* Check if zone_casper is already created */
	zone_casper = uma_zcreate("mac_casper", sizeof(struct mac_casper), NULL,
	    NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
	if (zone_casper == NULL)
		return;
}
void
casper_destroy(struct mac_policy_conf *mpc)
{
	if (zone_casper != NULL) {
		uma_zdestroy(zone_casper);
		zone_casper = NULL;
	}
}

/* Common label function */
void
casper_destroy_label(struct label *label)
{
	struct mac_casper *mpl;

	mpl = SLOT(label);

	if (mpl != NULL) {
		uma_zfree(zone_casper, mpl);
		SLOT_SET(label, NULL);
	}
}

/* vnode label*/
void
casper_vnode_init_label(struct label *label)
{
	struct mac_casper *c_label;

	c_label = uma_zalloc(zone_casper, M_WAITOK | M_ZERO);
	if (c_label == NULL)
		return;

	c_label->type = SUB_NONE;
	SLOT_SET(label, c_label);

	return;
}
int
casper_mpo_vnode_check_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *newlabel)
{
	return 0;
}
void
casper_mpo_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *label)
{
	struct mac_casper *src, *dst;

	src = SLOT(label);
	dst = SLOT(vplabel);

	if (src == NULL || dst == NULL)
		return;

	dst->type = src->type;
}
void
casper_mpo_vnode_copy_label(struct label *src, struct label *dest)
{
	struct mac_casper *s, *d;
	s = SLOT(src);
	d = SLOT(dest);

	if (s == NULL || d == NULL)
		return;

	*d = *s;
}
int
casper_mpo_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int attrnamespace, const char *name)
{
	return 0;
}
int
casper_mpo_vnode_setlabel_extattr(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct label *intlabel)
{
	struct mac_casper *src;
	size_t buflen;
	int error;

	src = SLOT(intlabel);
	buflen = sizeof(struct mac_casper);

	if (src == NULL)
		return (EINVAL);

	error = vn_extattr_set(vp, IO_NODELOCKED, MAC_SUB_EXTATTR_NAMESPACE,
	    MAC_SUB_EXTATTR_NAME, buflen, (char *)src, curthread);

	return (error);
}
int
casper_mpo_vnode_associate_extattr(struct mount *mp, struct label *mplabel,
    struct vnode *vp, struct label *vplabel)
{
	struct mac_casper *dest;
	int error;
	int len;

	dest = SLOT(vplabel);

	if (dest == NULL)
		return 0;

	len = sizeof(struct mac_casper);

	error = vn_extattr_get(vp, IO_NODELOCKED, MAC_SUB_EXTATTR_NAMESPACE,
	    MAC_SUB_EXTATTR_NAME, &len,
	    (char *)dest, // 直接寫入結構指標
	    curthread);

	if (error == ENOATTR || error == EOPNOTSUPP) {
		/* The file on disk has no extended attribute.
		 * We simply mark the memory label as NONE (Empty).
		 * We return 0 (Success) so the OS lets the file load normally.
		 */
		dest->type = SUB_NONE;
		return (0);
	}

	if (error)
		return (error);

	if (len != sizeof(struct mac_casper))
		/* Data on disk is wrong size? Treat as empty. */
		dest->type = SUB_NONE;

	return (0);
}
int
casper_mpo_vnode_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct mac_casper *mpl;
	enum cas_obj_label found_type = OBJ_NONE;

	if (element_data == NULL || element_name == NULL)
		return (EINVAL);

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return (0);

	for (int i = 0; cas_obj_label_map[i].name != NULL; i++) {
		if (strcmp(element_data, cas_obj_label_map[i].name) == 0) {
			found_type = cas_obj_label_map[i].type;
			break;
		}
	}

	if (found_type == OBJ_NONE)
		return (EINVAL);

	mpl = SLOT(label);

	if (mpl == NULL)
		return (ENOMEM);

	mpl->type = found_type;
	(*claimed)++;

	return (0);
}
int
casper_mpo_vnode_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct mac_casper *mpl;
	const char *result_name = NULL;

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return (0);

	mpl = SLOT(label);

	if (mpl == NULL)
		return (0);

	for (int i = 0; cas_obj_label_map[i].name != NULL; i++) {
		if (cas_obj_label_map[i].type == mpl->type) {
			result_name = cas_obj_label_map[i].name;
			break;
		}
	}

	if (result_name != NULL) {
		if (sbuf_printf(sb, "%s", result_name) == -1)
			return (ENOMEM);

		(*claimed)++;
	}

	return (0);
}

/* cred label */
void
casper_cred_init_label(struct label *label)
{
	return;
}
void
casper_cred_relabel(struct ucred *cred, struct label *newlabel)
{
	struct mac_casper *src, *dst;

	if (cred == NULL || newlabel == NULL)
		return;

	dst = SLOT(cred->cr_label);
	src = SLOT(newlabel);

	if (src == NULL)
		return;

	if (dst == NULL) {
		dst = uma_zalloc(zone_casper, M_NOWAIT | M_ZERO);
		if (dst == NULL)
			return;
		SLOT_SET(cred->cr_label, dst);
	}

	dst->type = src->type;
}
int
casper_mpo_cred_internalize_label(struct label *label, char *element_name,
    char *element_data, int *claimed)
{
	struct mac_casper *mpl;
	enum cas_sub_label found_type = SUB_NONE;

	if (element_data == NULL || element_name == NULL)
		return (EINVAL);

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return (0);

	for (int i = 0; cas_sub_label_map[i].name != NULL; i++) {
		if (strcmp(element_data, cas_sub_label_map[i].name) == 0) {
			found_type = cas_sub_label_map[i].type;
			break;
		}
	}

	if (found_type == SUB_NONE)
		return (EINVAL);

	mpl = SLOT(label);

	if (mpl == NULL) {
		mpl = uma_zalloc(zone_casper, M_NOWAIT | M_ZERO);

		if (mpl == NULL)
			return (ENOMEM);

		SLOT_SET(label, mpl);
	}

	mpl->type = found_type;
	(*claimed)++;

	return (0);
}
int
casper_mpo_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct mac_casper *mpl;
	const char *result_name = NULL;

	if (strcmp(MAC_CASPER_LABEL_NAME, element_name) != 0)
		return (0);

	mpl = SLOT(label);

	if (mpl == NULL)
		return (0);

	for (int i = 0; cas_sub_label_map[i].name != NULL; i++) {
		if (cas_sub_label_map[i].type == mpl->type) {
			result_name = cas_sub_label_map[i].name;
			break;
		}
	}

	if (result_name != NULL) {
		if (sbuf_printf(sb, "%s", result_name) == -1)
			return (ENOMEM);

		(*claimed)++;
	}

	return (0);
}
