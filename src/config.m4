PHP_ARG_ENABLE(hp_uploadprogress_guard, whether to enable hp_uploadprogress_guard,
[  --enable-hp-uploadprogress-guard   Enable hp_uploadprogress_guard], yes)
if test "$PHP_HP_UPLOADPROGRESS_GUARD" != "no"; then
  dnl The carried multipart parser is one copy of main/rfc1867.c per PHP branch (rfc1867/rfc1867_copy-X.Y.c).
  dnl Always select from the canonical directory. A leftover flat copy may belong to another ABI.
  HP_UPG_SRCDIR="${srcdir:-.}"
  HP_UPG_PHP_BRANCH=`$PHP_CONFIG --version | cut -d. -f1,2`
  dnl 5.4 and 5.5 build with the 5.6 copy (same rfc1867.c, same API)
  case "$HP_UPG_PHP_BRANCH" in
    5.4|5.5) AC_MSG_NOTICE([PHP $HP_UPG_PHP_BRANCH: using the 5.6 parser copy]); HP_UPG_PHP_BRANCH=5.6 ;;
  esac
  if test ! -f "$HP_UPG_SRCDIR/rfc1867/rfc1867_copy-$HP_UPG_PHP_BRANCH.c"; then
    AC_MSG_ERROR([no carried parser for PHP $HP_UPG_PHP_BRANCH (rfc1867/rfc1867_copy-$HP_UPG_PHP_BRANCH.c)])
  fi
  AC_MSG_NOTICE([using rfc1867/rfc1867_copy-$HP_UPG_PHP_BRANCH.c])
  cp "$HP_UPG_SRCDIR/rfc1867/rfc1867_copy-$HP_UPG_PHP_BRANCH.c" "$HP_UPG_SRCDIR/rfc1867_copy.c"
  PHP_NEW_EXTENSION(hp_uploadprogress_guard, hp_uploadprogress_guard.c rfc1867_copy.c, $ext_shared)
fi
