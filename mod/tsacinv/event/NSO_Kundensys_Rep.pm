package tsacinv::event::NSO_Kundensys_Rep;
#  W5Base Framework
#  Copyright (C) 2006  Hartmut Vogler (it@guru.de)
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
use strict;
use vars qw(@ISA);
use kernel;
use kernel::Event;
use kernel::XLSReport;

@ISA=qw(kernel::Event);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   return($self);
}

#
# Request ...
# https://darwin.telekom.de/darwin/auth/base/workflow/ById/13342204470001
#

sub NSO_Kundensys_Rep
{
   my $self=shift;
   my %param=@_;
   my %flt;
   my @userid=qw(-1);
   $ENV{LANG}="de";
   $param{'defaultFilenamePrefix'}=
         "webfs:/Reports/NSO_Kundensys/NSO_Kundensysteme";
   msg(INFO,"start Report to $param{'filename'}");
   my $t0=time();
 
   $flt{'status'}='"!out of operation"';
   $flt{'systemid'}="S09338353 S09340929 S09505355 S09505253 S09505304 S09319025 S09311363 S09314308 S09317724 S09317925 S09317766 S09317982 S09317814 S09318030 S09317868 S09318081";

   %param=kernel::XLSReport::StdReportParamHandling($self,%param);
   my $out=new kernel::XLSReport($self,$param{'filename'});
   
   $out->initWorkbook();

   my @view=qw(systemname systemid status 
               systemos
               assetassetid assetmodelname tsacinv_locationfullname
               acmdbcontract acmdbcontractnumber
               applicationnames
               dynservices);


   my @control;
   foreach my $conumber (qw(9100011982 1300002400 9100014541)){
      push(@control,{
         sheet=>$conumber,
         DataObj=>'tsacinv::system',
         filter=>{%flt,conumber=>\$conumber},
         view=>[@view]
      });
   }
   $out->Process(@control);
   my $trep=time()-$t0;
   msg(INFO,"end Report to $param{'filename'} ($trep sec)");
   return({exitcode=>0,msg=>'OK'});
}





1;
