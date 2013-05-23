/*
 * Copyright (C) 2006, 2010  Novell, Inc.
 * Written by Andreas Gruenbacher <agruen@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/richacl.h>

/**
 * struct richacl_alloc  -  remember how many entries are actually allocated
 * @acl:	acl with a_count <= @count
 * @count:	the actual number of entries allocated in @acl
 *
 * We pass around this structure while modifying an acl, so that we do
 * not have to reallocate when we remove existing entries followed by
 * adding new entries.
 */
struct richacl_alloc {
	struct richacl *acl;
	unsigned int count;
};

/**
 * richacl_delete_entry  -  delete an entry in an acl
 * @x:		acl and number of allocated entries
 * @ace:	an entry in @x->acl
 *
 * Updates @ace so that it points to the entry before the deleted entry
 * on return. (When deleting the first entry, @ace will point to the
 * (non-existant) entry before the first entry). This behavior is the
 * expected behavior when deleting entries while forward iterating over
 * an acl.
 */
static void
richacl_delete_entry(struct richacl_alloc *x, struct richace **ace)
{
	void *end = x->acl->a_entries + x->acl->a_count;

	memmove(*ace, *ace + 1, end - (void *)(*ace + 1));
	(*ace)--;
	x->acl->a_count--;
}

/**
 * richacl_insert_entry  -  insert an entry in an acl
 * @x:		acl and number of allocated entries
 * @ace:	entry before which the new entry shall be inserted
 *
 * Insert a new entry in @x->acl at position @ace, and zero-initialize
 * it.  This may require reallocating @x->acl.
 */
static int
richacl_insert_entry(struct richacl_alloc *x, struct richace **ace)
{
	if (x->count == x->acl->a_count) {
		int n = *ace - x->acl->a_entries;
		struct richacl *acl2;

		acl2 = richacl_alloc(x->acl->a_count + 1);
		if (!acl2)
			return -1;
		acl2->a_flags = x->acl->a_flags;
		acl2->a_owner_mask = x->acl->a_owner_mask;
		acl2->a_group_mask = x->acl->a_group_mask;
		acl2->a_other_mask = x->acl->a_other_mask;
		memcpy(acl2->a_entries, x->acl->a_entries,
		       n * sizeof(struct richace));
		memcpy(acl2->a_entries + n + 1, *ace,
		       (x->acl->a_count - n) * sizeof(struct richace));
		kfree(x->acl);
		x->acl = acl2;
		x->count = acl2->a_count;
		*ace = acl2->a_entries + n;
	} else {
		void *end = x->acl->a_entries + x->acl->a_count;

		memmove(*ace + 1, *ace, end - (void *)*ace);
		x->acl->a_count++;
	}
	memset(*ace, 0, sizeof(struct richace));
	return 0;
}

/**
 * richace_change_mask  -  set the mask of @ace to @mask
 * @x:		acl and number of allocated entries
 * @ace:	entry to modify
 * @mask:	new mask for @ace
 *
 * If @ace is inheritable, a inherit-only ace is inserted before @ace which
 * includes the inheritable permissions of @ace, and the inheritance flags of
 * @ace are cleared before changing the mask.
 *
 * If @mode is 0, the original ace is turned into an inherit-only entry if
 * there are any inheritable permissions, and removed otherwise.
 *
 * The returned @ace points to the modified or inserted effective-only acl
 * entry if that entry exists, to the entry that has become inheritable-only,
 * or else to the previous entry in the acl.
 */
static int
richace_change_mask(struct richacl_alloc *x, struct richace **ace,
			   unsigned int mask)
{
	if (mask && (*ace)->e_mask == mask)
		return 0;
	if (mask & ~ACE4_POSIX_ALWAYS_ALLOWED) {
		if (richace_is_inheritable(*ace)) {
			if (richacl_insert_entry(x, ace))
				return -1;
			memcpy(*ace, *ace + 1, sizeof(struct richace));
			(*ace)->e_flags |= ACE4_INHERIT_ONLY_ACE;
			(*ace)++;
			richace_clear_inheritance_flags(*ace);
		}
		(*ace)->e_mask = mask;
	} else {
		if (richace_is_inheritable(*ace))
			(*ace)->e_flags |= ACE4_INHERIT_ONLY_ACE;
		else
			richacl_delete_entry(x, ace);
	}
	return 0;
}

/**
 * richacl_move_everyone_aces_down  -  move everyone@ aces to the end of the acl
 * @x:		acl and number of allocated entries
 *
 * Move all everyone aces to the end of the acl so that only a single everyone@
 * allow ace remains at the end, and update the mask fields of all aces on the
 * way.  The last ace of the resulting acl will be an everyone@ allow ace only
 * if @acl grants any permissions to @everyone.
 *
 * Having at most one everyone@ allow ace at the end of the acl helps us in the
 * following algorithms.
 *
 * This transformation does not alter the permissions that the acl grants.
 */
static int
richacl_move_everyone_aces_down(struct richacl_alloc *x)
{
	struct richace *ace;
	unsigned int allowed = 0, denied = 0;

	richacl_for_each_entry(ace, x->acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_everyone(ace)) {
			if (richace_is_allow(ace))
				allowed |= (ace->e_mask & ~denied);
			else if (richace_is_deny(ace))
				denied |= (ace->e_mask & ~allowed);
			else
				continue;
			if (richace_change_mask(x, &ace, 0))
				return -1;
		} else {
			if (richace_is_allow(ace)) {
				if (richace_change_mask(x, &ace, allowed |
						(ace->e_mask & ~denied)))
					return -1;
			} else if (richace_is_deny(ace)) {
				if (richace_change_mask(x, &ace, denied |
						(ace->e_mask & ~allowed)))
					return -1;
			}
		}
	}
	if (allowed & ~ACE4_POSIX_ALWAYS_ALLOWED) {
		struct richace *last_ace = ace - 1;

		if (x->acl->a_entries &&
		    richace_is_everyone(last_ace) &&
		    richace_is_allow(last_ace) &&
		    richace_is_inherit_only(last_ace) &&
		    last_ace->e_mask == allowed)
			last_ace->e_flags &= ~ACE4_INHERIT_ONLY_ACE;
		else {
			if (richacl_insert_entry(x, &ace))
				return -1;
			ace->e_type = ACE4_ACCESS_ALLOWED_ACE_TYPE;
			ace->e_flags = ACE4_SPECIAL_WHO;
			ace->e_mask = allowed;
			ace->u.e_who = richace_everyone_who;
		}
	}
	return 0;
}
