package BCBS::event::loaddata;
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
@ISA=qw(kernel::Event);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   return($self);
}

sub Init
{
   my $self=shift;


   $self->RegisterEvent("loadbcbs","LoadBCBS");
   return(1);
}

sub LoadBCBS
{
   my $self=shift;

   msg(INFO,"loading data for BCBS from AssetCenter to W5Base");


   my $man=getModuleObject($self->Config,"base::mandator");
   $man->SetFilter({name=>\'AL T-Com'});
   my ($manrec,$msg)=$man->getOnlyFirst("grpid");
   my $mandatorid=$manrec->{grpid};

   my $aappl=getModuleObject($self->Config,"tsacinv::appl");
   my $appl=getModuleObject($self->Config,"AL_TCom::appl");
   $aappl->SetFilter({assignmentgroup=>\'BPO.BCBS'});
   $aappl->SetCurrentView(qw(ALL));
   if (my ($rec,$msg)=$aappl->getFirst()){
      do{
         last if (!defined($rec));
         msg(INFO,"load name=$rec->{name} id=$rec->{id}");
         my $databoss=$self->getUseridByPosix('hvogler');
         my $newrec={name=>$rec->{name},
                     mandatorid=>$mandatorid,
                     conumber=>$rec->{conumber},
                     cistatusid=>4,
                     srcid=>$rec->{id},
                     srcsys=>'AC_BCBS',
                     databossid=>$databoss};
         $newrec->{name}=~s/\s+/_/g;
         $newrec->{conumber}=~s/^0+//g;
         $appl->ValidatedInsertOrUpdateRecord($newrec,
                 {srcid=>\$newrec->{srcid},srcsys=>\$newrec->{srcsys}});
     
         ($rec,$msg)=$aappl->getNext();
      } until(!defined($rec));
   }


   return({exitcode=>0});
}


sub getUseridByPosix
{
   my $self=shift;
   my $posix=shift;

   my $u=getModuleObject($self->Config,"base::user");
   $u->SetFilter({posix=>\$posix});
   my ($urec,$msg)=$u->getOnlyFirst("userid");
   if (!defined($urec)){
      msg(ERROR,"uiserid not found");
      exit(1);
   }
   return($urec->{userid}); 
}


1;
