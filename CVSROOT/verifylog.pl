#!/usr/bin/perl -w

#*****************************************************************************
#!
#! FILE NAME  : verifylog.pl
#!
#! PARAMETERS : Name of the log message file.
#!
#! DESCRIPTION: Verify that a log message is correct before performing a
#!              commit. Currently this just means that there must be a
#!              message...
#!
#! FUNCTIONS  : None
#!
#!----------------------------------------------------------------------------
#! HISTORY
#!
#! $Log$
#! Revision 1.1  2001/09/26 07:16:53  pkj
#! Make sure log messages are always given.
#!
#!----------------------------------------------------------------------------
#! Copyright (C) 2000-2001, Axis Communications AB, LUND, SWEDEN
#!****************************************************************************
# $Id$

#****************** INCLUDE FILES SECTION ************************************

use strict;

#****************** VARIABLE DECLARATION SECTION *****************************

use vars qw($log);

#****************** CONSTANT SECTION *****************************************

#****************** MAIN PROGRAM SECTION *************************************

if (!$#ARGV && open(INFILE, "<$ARGV[0]"))
{
  while (<INFILE>)
  {
    $log .= $_ unless (/^\s*$/);
  }
  close(INFILE);
}

if (!$log)
{
  print "You must specify a log message!\n";
  exit 1;
}

exit 0;

#****************** FUNCTION DEFINITION SECTION ******************************

#****************** END OF FILE verifylog.pl *********************************
