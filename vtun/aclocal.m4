
AC_DEFUN( AC_TEST_FILES,
[
    ac_file_found=yes
    for f in $1; do
	if test ! -f $2/$f; then
    	   ac_file_found=no
	   break;
	fi
    done

    if test "$ac_file_found" = "yes" ; then
	ifelse([$3], , :,[$3])
    else
	ifelse([$4], , :,[$4])
    fi
])

dnl Search for headers, add path to CPPFLAGS if found 
AC_DEFUN( AC_SEARCH_HEADERS, 
[
    AC_MSG_CHECKING("for $1") 
    ac_hdr_found=no
    for p in $2; do
	AC_TEST_FILES($1, $p, 
	    [ 
     	       ac_hdr_found=yes
	       break
	    ]
	)
    done 
    if test "$ac_hdr_found" = "yes" ; then
	CPPFLAGS="$CPPFLAGS -I$p"
        AC_MSG_RESULT( [($p) yes] ) 
	ifelse([$3], , :,[$3])
    else
        AC_MSG_RESULT("no") 
	ifelse([$4], , :,[$4])
    fi
])
