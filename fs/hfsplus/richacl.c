/*
 * linux/fs/hfsplus/richacl.c
 *
 * Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Handler for NFSv4 Access Control Lists (ACLs) support.
 */

#include <linux/uuid.h>

#include "hfsplus_fs.h"
#include "xattr.h"
#include "richacl.h"

#define HFSPLUS_ACE_ID_MASK 0xFFFFFFFF

static unsigned char hfsplus_group_fingerprint[] = {0xab, 0xcd, 0xef,
						    0xab, 0xcd, 0xef,
						    0xab, 0xcd, 0xef,
						    0xab, 0xcd, 0xef};

static unsigned char hfsplus_user_fingerprint[] = {0xff, 0xff,
						   0xee, 0xee,
						   0xdd, 0xdd,
						   0xcc, 0xcc,
						   0xbb, 0xbb,
						   0xaa, 0xaa};

#define HFSPLUS_FINGERPRINT_SIZE \
	(HFSPLUS_GUID_SIZE - sizeof(HFSPLUS_ACE_ID_MASK))

#define HFSPLUS_EVERYBODY_ID 0xc

static unsigned char empty_guid[HFSPLUS_GUID_SIZE] = {0};

static inline int empty_ace(const struct hfsplus_acl_entry *ace)
{
	return memcmp(empty_guid, ace->ace_applicable, HFSPLUS_GUID_SIZE) == 0;
}

#define IS_GROUP_FINGERPRINT(ace_applicable) \
	(memcmp(ace_applicable, \
		hfsplus_group_fingerprint, HFSPLUS_FINGERPRINT_SIZE) == 0)

#define IS_USER_FINGERPRINT(ace_applicable) \
	(memcmp(ace_applicable, \
		hfsplus_user_fingerprint, HFSPLUS_FINGERPRINT_SIZE) == 0)

static bool is_owner_ace(const struct hfsplus_acl_entry *ace)
{
	hfs_dbg(ACL_MOD, "[%s]: ace %p\n", __func__, ace);

	if (!IS_GROUP_FINGERPRINT(ace->ace_applicable) &&
			!IS_USER_FINGERPRINT(ace->ace_applicable) &&
			!empty_ace(ace)) {
		hfs_dbg(ACL_MOD, "[%s]: found owner ACE\n", __func__);
		return true;
	} else
		return false;
}

static bool is_group_owner_ace(struct inode *inode,
				const struct hfsplus_acl_entry *ace)
{
	int size = HFSPLUS_FINGERPRINT_SIZE;
	__be32 *raw_gid_ptr;

	hfs_dbg(ACL_MOD, "[%s]: inode %p, ace %p\n", __func__, inode, ace);

	if (IS_GROUP_FINGERPRINT(ace->ace_applicable)) {
		raw_gid_ptr = (__be32 *)&ace->ace_applicable[size];
		if (gid_eq(be32_to_cpu(*raw_gid_ptr), i_gid_read(inode))) {
			hfs_dbg(ACL_MOD, "[%s]: found group owner ACE\n",
								__func__);
			return true;
		}
	}

	return false;
}

static bool is_other_ace(struct inode *inode,
				const struct hfsplus_acl_entry *ace)
{
	int size = HFSPLUS_FINGERPRINT_SIZE;
	__be32 *raw_id_ptr;

	hfs_dbg(ACL_MOD, "[%s]: inode %p, ace %p\n", __func__, inode, ace);

	if (IS_GROUP_FINGERPRINT(ace->ace_applicable)) {
		raw_id_ptr = (__be32 *)&ace->ace_applicable[size];
		if (be32_to_cpu(*raw_id_ptr) == HFSPLUS_EVERYBODY_ID) {
			hfs_dbg(ACL_MOD, "[%s]: found other ACE\n", __func__);
			return true;
		}
	}

	return false;
}

static bool is_user_ace(const struct hfsplus_acl_entry *ace)
{
	int size = HFSPLUS_FINGERPRINT_SIZE;
	__be32 *raw_id_ptr;

	hfs_dbg(ACL_MOD, "[%s]: ace %p\n", __func__, ace);

	if (IS_USER_FINGERPRINT(ace->ace_applicable)) {
		raw_id_ptr = (__be32 *)&ace->ace_applicable[size];
		if (be32_to_cpu(*raw_id_ptr) != HFSPLUS_EVERYBODY_ID) {
			hfs_dbg(ACL_MOD, "[%s]: found user %#x ACE\n",
					__func__, be32_to_cpu(*raw_id_ptr));
			return true;
		}
	}

	return false;
}

static bool is_group_ace(const struct hfsplus_acl_entry *ace)
{
	int size = HFSPLUS_FINGERPRINT_SIZE;
	__be32 *raw_id_ptr;

	hfs_dbg(ACL_MOD, "[%s]: ace %p\n", __func__, ace);

	if (IS_GROUP_FINGERPRINT(ace->ace_applicable)) {
		raw_id_ptr = (__be32 *)&ace->ace_applicable[size];
		if (be32_to_cpu(*raw_id_ptr) != HFSPLUS_EVERYBODY_ID) {
			hfs_dbg(ACL_MOD, "[%s]: found group %#x ACE\n",
					__func__, be32_to_cpu(*raw_id_ptr));
			return true;
		}
	}

	return false;
}

#define HFSPLUS_ACE_SET_OWNER_USER_ID(ace_applicable) \
	do { \
		uuid_be generated_uuid; \
		uuid_be_gen(&generated_uuid); \
		memcpy(ace_applicable, \
			generated_uuid.b, sizeof(generated_uuid)); \
	} while (0)

#define HFSPLUS_ACE_SET_USER_ID(ace_applicable, id) \
	do { \
		memset(ace_applicable, 0, HFSPLUS_GUID_SIZE); \
		memcpy(&ace_applicable[0], \
			&hfsplus_user_fingerprint[0], \
			HFSPLUS_FINGERPRINT_SIZE); \
		(*((__be32 *)&ace_applicable[HFSPLUS_FINGERPRINT_SIZE]) = \
			cpu_to_be32(id)); \
	} while (0)

#define HFSPLUS_ACE_SET_GROUP_ID(ace_applicable, id) \
	do { \
		memset(ace_applicable, 0, HFSPLUS_GUID_SIZE); \
		memcpy(&ace_applicable[0], \
			&hfsplus_group_fingerprint[0], \
			HFSPLUS_FINGERPRINT_SIZE); \
		(*((__be32 *)&ace_applicable[HFSPLUS_FINGERPRINT_SIZE]) = \
			cpu_to_be32(id)); \
	} while (0)

static struct hfsplus_acl_record *hfsplus_acl_record_from_xattr(
							void *value,
							size_t size)
{
	struct hfsplus_filesec *filesec_ptr =
			(struct hfsplus_filesec *)value;
	struct hfsplus_acl_record *acl_record_ptr = NULL;
	size_t filesec_hdr_size = offsetof(struct hfsplus_filesec, fsec_acl);
	size_t acl_record_hdr_size =
		offsetof(struct hfsplus_acl_record, acl_ace);
	size_t known_size = filesec_hdr_size;
	u32 acl_entries_count = 0;
	u32 acl_entries_size = 0;

	hfs_dbg(ACL_MOD,
		"[%s]: value %p, size %zu\n",
		__func__, value, size);

	if (unlikely(size < known_size)) {
		pr_err("filesec hdr corrupted\n");
		return ERR_PTR(HFS_ERR_DBG(ACL_MOD, -EINVAL));
	}

	if (unlikely(be32_to_cpu(filesec_ptr->fsec_magic) !=
				HFSPLUS_FILESEC_MAGIC)) {
		pr_err("invalid fsec_magic\n");
		return ERR_PTR(HFS_ERR_DBG(ACL_MOD, -EINVAL));
	}

	known_size += acl_record_hdr_size;

	if (unlikely(size < known_size)) {
		pr_err("acl record hdr corrupted\n");
		return ERR_PTR(HFS_ERR_DBG(ACL_MOD, -EINVAL));
	}

	acl_record_ptr = &(filesec_ptr->fsec_acl);
	acl_entries_count = be32_to_cpu(acl_record_ptr->acl_entrycount);
	acl_entries_size =
		acl_entries_count * sizeof(struct hfsplus_acl_entry);
	known_size += acl_entries_size;

	if (unlikely(size < known_size)) {
		pr_err("acl entries array corrupted\n");
		return ERR_PTR(HFS_ERR_DBG(ACL_MOD, -EINVAL));
	}

	return acl_record_ptr;
}

static uid_t extract_uid_from_ace(struct hfsplus_acl_entry *ace)
{
	int size = HFSPLUS_FINGERPRINT_SIZE;
	__be32 *raw_id_ptr;
	uid_t uid;

	hfs_dbg(ACL_MOD, "[%s]: ace %p\n", __func__, ace);

	if (IS_GROUP_FINGERPRINT(ace->ace_applicable) ||
			IS_USER_FINGERPRINT(ace->ace_applicable)) {
		raw_id_ptr = (__be32 *)&ace->ace_applicable[size];
		uid = be32_to_cpu(*raw_id_ptr);
		hfs_dbg(ACL_MOD, "[%s]: uid/gid %#x\n", __func__, uid);
	} else {
		hfs_dbg(ACL_MOD, "[%s]: uid/gid %#x\n",
				__func__, ACL_UNDEFINED_ID);
		return ACL_UNDEFINED_ID;
	}

	return uid;
}

/* It is expected that ace is not empty */
static int compare_ace_type(struct hfsplus_acl_entry *left_ace,
				struct hfsplus_acl_entry *right_ace)
{
	u32 left_ace_flags = be32_to_cpu(left_ace->ace_flags);
	u32 left_ace_type = left_ace_flags & HFSPLUS_ACE_KINDMASK;
	u32 right_ace_flags = be32_to_cpu(right_ace->ace_flags);
	u32 right_ace_type = right_ace_flags & HFSPLUS_ACE_KINDMASK;

	if (left_ace_type == HFSPLUS_ACE_DENY &&
			right_ace_type == HFSPLUS_ACE_DENY)
		return 0;
	else if (left_ace_type == HFSPLUS_ACE_PERMIT &&
			right_ace_type == HFSPLUS_ACE_PERMIT)
		return 0;
	else if (left_ace_type == HFSPLUS_ACE_DENY)
		return -1;
	else if (left_ace_type == HFSPLUS_ACE_PERMIT) {
		if (right_ace_type == HFSPLUS_ACE_DENY)
			return 1;
		else
			return -1;
	} else if (right_ace_type == HFSPLUS_ACE_DENY ||
			right_ace_type == HFSPLUS_ACE_PERMIT)
		return -1;

	return 0;
}

static int compare_ace(struct inode *inode,
			struct hfsplus_acl_entry *left_ace,
			struct hfsplus_acl_entry *right_ace)
{
	uid_t left_uid, right_uid;

	if (empty_ace(left_ace) && empty_ace(right_ace))
		return 0;

	if (is_owner_ace(left_ace)) {
		if (is_owner_ace(right_ace))
			return compare_ace_type(left_ace, right_ace);
		else
			return -1;
	} else if (is_owner_ace(right_ace))
		return 1;

	if (is_group_owner_ace(inode, left_ace)) {
		if (is_group_owner_ace(inode, right_ace))
			return compare_ace_type(left_ace, right_ace);
		else
			return -1;
	} else if (is_group_owner_ace(inode, right_ace))
		return 1;

	if (is_other_ace(inode, left_ace)) {
		if (is_other_ace(inode, right_ace))
			return compare_ace_type(left_ace, right_ace);
		else
			return -1;
	} else if (is_other_ace(inode, right_ace))
		return 1;

	left_uid = extract_uid_from_ace(left_ace);
	right_uid = extract_uid_from_ace(right_ace);

	/* ACL_UNDEFINED_ID is greater always */
	if (left_uid == ACL_UNDEFINED_ID) {
		if (right_uid == ACL_UNDEFINED_ID)
			return 0;
		else
			return 1;
	} else if (right_uid == ACL_UNDEFINED_ID)
		return 1;

	if (left_uid == right_uid)
		return compare_ace_type(left_ace, right_ace);

	return left_uid < right_uid ? -1 : 1;
}

/*
 * Insertion sort.
 * Algorithm of the method is based on psevdocode from:
 * http://en.wikipedia.org/wiki/Insertion_sort
 */
static int sort_hfsplus_ace(struct inode *inode,
				struct hfsplus_filesec *filesec,
				ssize_t size)
{
	struct hfsplus_acl_entry *ace = fsec_acl->acl_ace;
	struct hfsplus_acl_entry temp_buf;
	int entries_count = be32_to_cpu(fsec_acl->acl_entrycount);
	ssize_t calculated_size = sizeof(struct hfsplus_filesec) +
			(entries_count * sizeof(struct hfsplus_acl_entry));
	int i;

	if (entries_count == 0)
		return 0;

	hfs_dbg(ACL_MOD, "[%s]: fsec_acl (%p)\n",
			__func__, fsec_acl);
	hfs_dbg(ACL_MOD, "[%s]: calculated_size (%zu)\n",
			__func__, calculated_size);
	hfs_dbg_hexdump(ACL_MOD, "unsorted composed_filesec: ",
				fsec_acl, calculated_size);

	if (calculated_size != size)
		return HFS_ERR_DBG(ACL_MOD, -EINVAL);

	for (i = 1; i < entries_count; i++) {
		int hole_index = i;
		memcpy(&temp_buf, &ace[i], sizeof(struct hfsplus_acl_entry));

		while (hole_index > 0 &&
				(compare_ace(inode,
						&ace[hole_index - 1],
						&temp_buf) > 0)) {
			/* move hole to next smaller index */
			memcpy(&ace[hole_index], &ace[hole_index - 1],
					sizeof(struct hfsplus_acl_entry));
			hole_index -= 1;
		}

		memcpy(&ace[hole_index], &temp_buf,
				sizeof(struct hfsplus_acl_entry));
	}

	hfs_dbg_hexdump(ACL_MOD, "sorted composed_filesec: ",
				fsec_acl, calculated_size);

	return 0;
}





static inline
uint32_t hfsplus_ace_extract_nfsv4_type(struct hfsplus_acl_entry *hfs_ace)
{
	u32 ace_flags = be32_to_cpu(hfs_ace->ace_flags);
	u32 ace_type = ace_flags & HFSPLUS_ACE_KINDMASK;

	switch (ace_type) {
	case HFSPLUS_ACE_PERMIT:
		return NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE;

	case HFSPLUS_ACE_DENY:
		return NFS4_ACE_ACCESS_DENIED_ACE_TYPE;

	case HFSPLUS_ACE_AUDIT:
		return NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE;

	case HFSPLUS_ACE_ALARM:
		return NFS4_ACE_SYSTEM_ALARM_ACE_TYPE;
	}

	BUG();
	return -1;
}

static uint32_t convert_rights[32] = {
		0,
		NFS4_ACE_READ_DATA,
		NFS4_ACE_WRITE_DATA,
		NFS4_ACE_EXECUTE,
		NFS4_ACE_DELETE,
		NFS4_ACE_APPEND_DATA,
		NFS4_ACE_DELETE_CHILD,
		NFS4_ACE_READ_ATTRIBUTES,
		NFS4_ACE_WRITE_ATTRIBUTES,
		NFS4_ACE_READ_NAMED_ATTRS,
		NFS4_ACE_WRITE_NAMED_ATTRS,
		NFS4_ACE_READ_ACL,
		NFS4_ACE_WRITE_ACL,
		NFS4_ACE_WRITE_OWNER,
		
};

static inline
uint32_t hfsplus_ace_rights_to_nfsv4(struct hfsplus_acl_entry *hfs_ace)
{
	u32 rights = be32_to_cpu(hfs_ace->ace_rights);
	uint32_t access_mask = 0;








}





static struct nfs4_acl *hfsplus_acl_to_nfsv4(struct hfsplus_filesec *filesec)
{
	struct nfs4_acl *acl;
	struct nfs4_ace *ace;
	u32 acl_entries_count = be32_to_cpu(fsec_acl->acl_entrycount);
	struct hfsplus_acl_entry *hfs_ace = fsec_acl->acl_ace;
	struct hfsplus_acl_entry *end = hfs_ace + acl_entries_count;

	hfs_dbg(ACL_MOD, "[%s]: filesec %p, entries_count %u\n",
			__func__, filesec, entries_count);

	acl = nfs4_acl_new(acl_entries_count);
	if (acl == NULL)
		return ERR_PTR(HFS_ERR_DBG(ACL_MOD, -ENOMEM));

	ace = acl->aces;
	for (; hfs_ace < end; hfs_ace++) {
		ace->type = hfsplus_ace_extract_nfsv4_type(hfs_ace);
		ace->access_mask = hfsplus_ace_rights_to_nfsv4(hfs_ace);
		ace->flag = hfsplus_ace_flags_to_nfsv4(hfs_ace);
		ace->whotype = hfsplus_ace_extract_nfsv4_whotype(hfs_ace);
		hfsplus_ace_extract_id(hfs_ace, ace);
		ace++;
		acl->naces++;
	}
	return acl;
}






static struct richacl *hfsplus_richacl_from_xattr(struct inode *inode,
					struct user_namespace *user_ns,
					void *value,
					size_t size)
{
	int err = 0;
	struct richacl *acl = NULL;
	struct hfsplus_filesec *filesec =
			(struct hfsplus_filesec *)value;
	const struct hfsplus_acl_record *raw_acl_rec;
	const struct hfsplus_acl_entry *ace;
	u32 acl_entries_count = 0;
	ssize_t calculated_size = 0;
	unsigned int flags = 0;

	hfs_dbg(ACL_MOD,
		"[%s]: ino %lu, value %p, size %zu\n",
		__func__, inode->i_ino, value, size);

	if (!value)
		return NULL;

	raw_acl_rec = hfsplus_acl_record_from_xattr(value, size);
	if (unlikely(IS_ERR(raw_acl_rec))) {
		HFS_ERR_DBG(ACL_MOD, (int)PTR_ERR(raw_acl_rec));
		return NULL;
	}

	acl_entries_count = be32_to_cpu(raw_acl_rec->acl_entrycount);

	calculated_size = sizeof(struct hfsplus_filesec) +
		(acl_entries_count * sizeof(struct hfsplus_acl_entry));
	err = sort_hfsplus_ace(inode, filesec, calculated_size);
	if (unlikely(err))
		return ERR_PTR(HFS_ERR_DBG(ACL_MOD, err));



failed_conversion:
	if (acl)
		posix_acl_release(pacl);


	return ERR_PTR(err);
}












static int hfsplus_compose_filesec_from_richacl(struct inode *inode,
						struct user_namespace *user_ns,
						struct richacl *acl,
						struct hfsplus_filesec *filesec,
						size_t allocated_size)
{
	struct hfsplus_acl_record *fsec_acl = &(filesec->fsec_acl);
	struct hfsplus_acl_entry *ace = fsec_acl->acl_ace;
	const struct richace *ace;
	u8 ace_applicable[HFSPLUS_GUID_SIZE];
	size_t calculated_size = 0;
	size_t filesec_hdr_size = sizeof(struct hfsplus_filesec);
	size_t ace_size = sizeof(struct hfsplus_acl_entry);
	unsigned int flags = 0;
	int err;

	hfs_dbg(ACL_MOD,
		"[%s]: ino %lu, pacl %p, filesec %p, alloc_sz %zu\n",
		__func__, inode->i_ino, pacl, filesec, allocated_size);

	if ((calculated_size + filesec_hdr_size) > allocated_size)
		return HFS_ERR_DBG(ACL_MOD, -ENOMEM);

	memset(filesec, 0, sizeof(struct hfsplus_filesec));
	filesec->fsec_magic = cpu_to_be32(HFSPLUS_FILESEC_MAGIC);
	calculated_size += filesec_hdr_size;

	richacl_for_each_entry(ace, acl) {






	}










	err = sort_hfsplus_ace(&acl_info);
	if (unlikely(err)) {
		hfs_dbg(ACL_MOD,
			"(%s, %d): %s: err %d\n",
			__FILE__, __LINE__, __func__, err);
		return err;
	}

	return 0;
}

static struct hfsplus_filesec *hfsplus_richacl_to_filesec(struct inode *inode,
						struct user_namespace *user_ns,
						struct richacl *acl)
{
	int err = 0;
	struct hfsplus_filesec *composed_filesec = NULL;

	hfs_dbg(ACL_MOD,
		"[%s]: ino %lu, acl %p\n", __func__, inode->i_ino, acl);

	/*
	 * Mac OS X supports only inline xattr.
	 * The online xattr can't be greater than
	 * HFSPLUS_MAX_INLINE_DATA_SIZE (3802) bytes
	 * in size.
	 */
	composed_filesec = kzalloc(HFSPLUS_MAX_INLINE_DATA_SIZE, GFP_KERNEL);
	if (unlikely(!composed_filesec))
		return ERR_PTR(HFS_ERR_DBG(ACL_MOD, -ENOMEM));

	err = hfsplus_compose_filesec_from_richacl(inode, user_ns,
						acl, composed_filesec,
						HFSPLUS_MAX_INLINE_DATA_SIZE);
	if (err) {
		HFS_ERR_DBG(ACL_MOD, err);
		goto failed_conversion;
	}

	return composed_filesec;

failed_conversion:
	kfree(composed_filesec);
	return ERR_PTR(err);
}

struct richacl *hfsplus_get_richacl(struct inode *inode)
{
	struct richacl *acl;
	char *xattr_name = HFSPLUS_XATTR_ACL_NAME;
	char *value = NULL;
	ssize_t size;

	hfs_dbg(ACL_MOD, "[%s]: ino %lu\n", __func__, inode->i_ino);

	if (!IS_RICHACL(inode))
		return ERR_PTR(HFS_ERR_DBG(ACL_MOD, -EOPNOTSUPP));
	acl = get_cached_richacl(inode);
	if (acl != ACL_NOT_CACHED)
		return acl;

	size = __hfsplus_getxattr(inode, xattr_name, NULL, 0);

	if (size > 0) {
		value = kzalloc(size, GFP_NOFS);
		if (unlikely(!value))
			return ERR_PTR(HFS_ERR_DBG(ACL_MOD, -ENOMEM));
		size = __hfsplus_getxattr(inode, xattr_name, value, size);
	}

	if (size > 0)
		acl = hfsplus_richacl_from_xattr(inode,
					&init_user_ns, value, size);
	else if (size == -ENODATA)
		acl = NULL;
	else
		acl = ERR_PTR(HFS_ERR_DBG(ACL_MOD, (int)size));

	kfree(value);

	if (!IS_ERR_OR_NULL(acl))
		set_cached_richacl(inode, acl);

	return acl;
}

static int hfsplus_set_richacl(struct inode *inode, struct richacl *acl)
{
	char *xattr_name = HFSPLUS_XATTR_ACL_NAME;
	struct hfsplus_filesec *filesec = NULL;
	size_t size = 0;
	size_t ace_size = sizeof(struct hfsplus_acl_entry);
	int err;

	hfs_dbg(ACL_MOD,
		"[%s]: ino %lu, acl %p\n",
		__func__, inode->i_ino, acl);

	if (S_ISLNK(inode->i_mode))
		return HFS_ERR_DBG(ACL_MOD, -EOPNOTSUPP);

	if (acl) {
		mode_t mode = inode->i_mode;
		if (richacl_equiv_mode(acl, &mode) == 0) {
			inode->i_mode = mode;
			mark_inode_dirty(inode);
			acl = NULL;
		}
	}

	if (acl) {
		filesec = hfsplus_richacl_to_filesec(inode,
						&init_user_ns, acl);
		if (unlikely(!filesec)) {
			err = HFS_ERR_DBG(ACL_MOD, -ENOMEM);
			goto end_set_acl;
		} else if (IS_ERR(filesec)) {
			err = HFS_ERR_DBG(ACL_MOD, (int)PTR_ERR(filesec));
			goto end_set_acl;
		}

		size = sizeof(struct hfsplus_filesec) +
			(be32_to_cpu(filesec->fsec_acl.acl_entrycount) *
				ace_size);
		if (unlikely(size > HFSPLUS_MAX_INLINE_DATA_SIZE)) {
			err = HFS_ERR_DBG(ACL_MOD, -ENOMEM);
			goto end_set_acl;
		}
	}

	err = __hfsplus_setxattr(inode, xattr_name, filesec, size, 0);
	if (unlikely(err))
		HFS_ERR_DBG(ACL_MOD, err);

end_set_acl:
	kfree(filesec);

	if (!err)
		set_cached_richacl(inode, acl);

	return err;
}

int hfsplus_init_richacl(struct inode *inode, struct inode *dir)
{
	struct richacl *dir_acl = NULL;

	hfs_dbg(ACL_MOD,
		"[%s]: ino %lu, dir->ino %lu\n",
		__func__, inode->i_ino, dir->i_ino);

	if (!S_ISLNK(inode->i_mode)) {
		dir_acl = hfsplus_get_richacl(dir);
		if (IS_ERR(dir_acl))
			return HFS_ERR_DBG(ACL_MOD, (int)PTR_ERR(dir_acl));
	}
	if (dir_acl) {
		struct richacl *acl;
		int err;

		acl = richacl_inherit_inode(dir_acl, inode);
		richacl_put(dir_acl);

		err = PTR_ERR(acl);
		if (unlikely(err))
			HFS_ERR_DBG(ACL_MOD, err)

		if (acl && !IS_ERR(acl)) {
			err = hfsplus_set_richacl(inode, acl);
			richacl_put(acl);
		}
		return err;
	} else {
		inode->i_mode &= ~current_umask();
		return 0;
	}
}

int hfsplus_richacl_chmod(struct inode *inode)
{
	struct richacl *acl;
	int err;

	hfs_dbg(ACL_MOD, "[%s]: ino %lu\n", __func__, inode->i_ino);

	if (S_ISLNK(inode->i_mode))
		return HFS_ERR_DBG(ACL_MOD, -EOPNOTSUPP);
	acl = hfsplus_get_richacl(inode);
	if (IS_ERR_OR_NULL(acl))
		return HFS_ERR_DBG(ACL_MOD, (int)PTR_ERR(acl));
	acl = richacl_chmod(acl, inode->i_mode);
	if (IS_ERR(acl))
		return HFS_ERR_DBG(ACL_MOD, (int)PTR_ERR(acl));
	err = hfsplus_set_richacl(inode, acl);
	if (unlikely(err))
		HFS_ERR_DBG(ACL_MOD, err);
	richacl_put(acl);

	return err;
}

static int hfsplus_xattr_get_richacl(struct dentry *dentry,
					const char *name,
					void *buffer,
					size_t buffer_size,
					int type)
{
	struct richacl *acl;
	size_t size;

	hfs_dbg(ACL_MOD,
		"[%s]: ino %lu, buffer %p, size %zu, type %#x\n",
		__func__, dentry->d_inode->i_ino, buffer, size, type);

	if (strcmp(name, "") != 0)
		return HFS_ERR_DBG(ACL_MOD, -EINVAL);

	acl = hfsplus_get_richacl(dentry->d_inode);
	if (IS_ERR(acl))
		return HFS_ERR_DBG(ACL_MOD, PTR_ERR(acl));
	if (acl == NULL)
		return HFS_ERR_DBG(ACL_MOD, -ENODATA);

	size = richacl_xattr_size(acl);
	if (buffer) {
		if (size > buffer_size)
			return HFS_ERR_DBG(ACL_MOD, -ERANGE);
		richacl_to_xattr(acl, buffer);
	}
	richacl_put(acl);

	return size;
}

static int hfsplus_xattr_set_richacl(struct dentry *dentry,
					const char *name,
					const void *value,
					size_t size,
					int flags,
					int type)
{
	struct richacl *acl = NULL;
	struct inode *inode = dentry->d_inode;
	int err = 0;

	hfs_dbg(ACL_MOD,
		"[%s]: ino %lu, value %p, size %zu, flags %#x, type %#x\n",
		__func__, inode->i_ino, value, size, flags, type);

	if (!IS_RICHACL(inode))
		return HFS_ERR_DBG(ACL_MOD, -EOPNOTSUPP);
	if (S_ISLNK(inode->i_mode))
		return HFS_ERR_DBG(ACL_MOD, -EOPNOTSUPP);
	if (strcmp(name, "") != 0)
		return HFS_ERR_DBG(ACL_MOD, -EINVAL);

	if (!uid_eq(current_fsuid(), inode->i_uid) &&
			richacl_check_acl(inode, ACE4_WRITE_ACL) &&
				!capable(CAP_FOWNER))
		return HFS_ERR_DBG(ACL_MOD, -EPERM);

	if (value) {
		acl = richacl_from_xattr(value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);

		inode->i_mode &= ~S_IRWXUGO;
		inode->i_mode |= richacl_masks_to_mode(acl);
	}

	err = hfsplus_set_richacl(inode, type, acl);
	if (unlikely(err))
		HFS_ERR_DBG(ACL_MOD, err);

	richacl_put(acl);
	return err;
}

static size_t hfsplus_xattr_list_richacl(struct dentry *dentry, char *list,
		size_t list_size, const char *name, size_t name_len, int type)
{
	/*
	 * This method is not used.
	 * It is used hfsplus_listxattr() instead of generic_listxattr().
	 */
	return HFS_ERR_DBG(ACL_MOD, -EOPNOTSUPP);
}

const struct xattr_handler hfsplus_xattr_richacl_handler = {
	.prefix	= RICHACL_XATTR,
	.list	= hfsplus_xattr_list_richacl,
	.get	= hfsplus_xattr_get_richacl,
	.set	= hfsplus_xattr_set_richacl,
};
