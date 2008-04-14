package base::event::QualityCheck;
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
use Data::Dumper;
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


   $self->RegisterEvent("QualityCheck","QualityCheck",timeout=>10800); #3h
   return(1);
}

sub QualityCheck
{
   my $self=shift;
   my $dataobj=shift;
   msg(DEBUG,"starting QualityCheck");
   my $lnkq=getModuleObject($self->Config,"base::lnkqrulemandator");
   my %dataobjtocheck;
   if ($dataobj eq ""){
      $lnkq->ResetFilter();
      $lnkq->SetCurrentView("dataobj");
      my ($rec,$msg)=$lnkq->getFirst();
      if (defined($rec)){
         do{
            $dataobjtocheck{$rec->{dataobj}}++;
            ($rec,$msg)=$lnkq->getNext();
         }until(!defined($rec));
      }
   }
   else{
      my $obj=getModuleObject($self->Config,$dataobj);
      if (defined($obj)){
         return($self->doQualityCheck($obj));
      }
      else{
         return({exitcode=>1,msg=>"invalid dataobject '$dataobj' specified"});
      }
   }
   foreach my $dataobj (sort(keys(%dataobjtocheck))){
      if ($dataobj ne ""){
         msg(INFO,"calling QualityCheck for '$dataobj'");
         my $bk=$self->W5ServerCall("rpcCallEvent","QualityCheck",$dataobj);
         if (!defined($bk->{AsyncID})){
            msg(ERROR,"can't call QualityCheck for dataobj '$dataobj' Event");
         }
      }
   }
   
   return({exitcode=>0,msg=>'ok'});
}

sub doQualityCheck
{
   my $self=shift;
   my $dataobj=shift;
 
   msg(INFO,"doQualityCheck in Object $dataobj");
   $dataobj->ResetFilter();
   my @flt;
   my @view=("id","qcok");
   if (my $cistatusid=$dataobj->getField("cistatusid")){
      $flt[0]->{cistatusid}=[3,4,5];
   }
   if (my $lastqcheck=$dataobj->getField("lastqcheck")){
      unshift(@view,"lastqcheck");
   }
   my $idfieldobj=$dataobj->IdField();
   if (defined($idfieldobj)){
      push(@view,$idfieldobj->Name());
   }
   #@view=("ALL");

   $dataobj->SetFilter(\@flt);
   $dataobj->SetCurrentView(@view);

   my ($rec,$msg)=$dataobj->getFirst();
   my $time=time();
   if (defined($rec)){
      do{
         my $qcokobj=$dataobj->getField("qcok");
         if (defined($qcokobj)){
            my $qcok=$qcokobj->RawValue($rec); 
            msg(DEBUG,"qcok=$rec->{qcok}");
         }
         else{
            msg(DEBUG,"no qcok field");
         }
         ($rec,$msg)=$dataobj->getNext();
         last if (time()-$time>3600); # 1 hours quality check
      }until(!defined($rec));
   }


   return({exitcode=>0,msg=>'ok'});
}
1;
