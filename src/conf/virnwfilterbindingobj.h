/*
 * virnwfilterbindingobj.h: network filter binding object processing
 *
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */
#ifndef VIR_NWFILTER_BINDING_OBJ_H
# define VIR_NWFILTER_BINDING_OBJ_H

# include "internal.h"
# include "virnwfilterbindingdef.h"
# include "virobject.h"

typedef struct _virNWFilterBindingObj virNWFilterBindingObj;
typedef virNWFilterBindingObj *virNWFilterBindingObjPtr;

virNWFilterBindingObjPtr
virNWFilterBindingObjNew(void);

virNWFilterBindingDefPtr
virNWFilterBindingObjGetDef(virNWFilterBindingObjPtr obj);

void
virNWFilterBindingObjSetDef(virNWFilterBindingObjPtr obj,
                            virNWFilterBindingDefPtr def);

virNWFilterBindingDefPtr
virNWFilterBindingObjStealDef(virNWFilterBindingObjPtr obj);

bool
virNWFilterBindingObjGetRemoving(virNWFilterBindingObjPtr obj);

void
virNWFilterBindingObjSetRemoving(virNWFilterBindingObjPtr obj,
                                 bool removing);

void
virNWFilterBindingObjEndAPI(virNWFilterBindingObjPtr *obj);

char *
virNWFilterBindingObjConfigFile(const char *dir,
                                const char *name);

int
virNWFilterBindingObjSave(const virNWFilterBindingObj *obj,
                          const char *statusDir);

int
virNWFilterBindingObjDelete(const virNWFilterBindingObj *obj,
                            const char *statusDir);

virNWFilterBindingObjPtr
virNWFilterBindingObjParseFile(const char *filename);

char *
virNWFilterBindingObjFormat(const virNWFilterBindingObj *obj);

#endif /* VIR_NWFILTER_BINDING_OBJ_H */
