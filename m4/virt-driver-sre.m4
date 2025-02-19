dnl The SRE-SRE driver check
dnl
dnl Copyright (C) 2016 Red Hat, Inc.
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library.  If not, see
dnl <http://www.gnu.org/licenses/>.
dnl

AC_DEFUN([LIBVIRT_DRIVER_ARG_SRE], [
  LIBVIRT_ARG_WITH_FEATURE([SRE], [SRE-SRE], [yes])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_SRE], [
  if test "$with_sre" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_SRE], 1, [whether SRE-SRE driver is enabled])
  fi
  AM_CONDITIONAL([WITH_SRE], [test "$with_sre" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_SRE], [
  LIBVIRT_RESULT([SRE-SRE], [$with_sre])
])
