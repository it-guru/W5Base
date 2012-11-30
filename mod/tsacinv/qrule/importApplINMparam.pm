package tsacinv::qrule::importApplINMparam;
#######################################################################
=pod

=head3 PURPOSE

This Rule compares the Incident-Managemtn relevant paramters of an
application against AssetManager.

=head3 IMPORTS

Checked parameters are Criticality, Priority and operation Mode.

=cut
#######################################################################
#
#  W5Base Framework
#  Copyright (C) 2012  Hartmut Vogler (it@guru.de)
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
use kernel::QRule;
@ISA=qw(kernel::QRule);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   return($self);
}

sub getPosibleTargets
{
   return(["itil::appl"]);
}

sub qcheckRecord
{
   my $self=shift;
   my $dataobj=shift;
   my $rec=shift;
   my $autocorrect=shift;

   my $wfrequest={};
   my $forcedupd={};
   my @qmsg;
   my @dataissue;
   my $errorlevel=0;

   return(0,undef) if ($rec->{cistatusid}!=4 &&
                       $rec->{cistatusid}!=5); # ist notwendig, damit CIs
                                               # auch wieder aktiviert
                                               # werden.
   if ($rec->{applid} ne ""){
      my $par=getModuleObject($self->getParent->Config(),"tsacinv::appl");
      $par->SetFilter({applid=>\$rec->{applid}});
      my ($parrec,$msg)=$par->getOnlyFirst(qw(ALL));
      return(undef,undef) if (!$par->Ping());
      if (!defined($parrec)){
         push(@qmsg,'given applicationid not found as active in AssetManager');
         $errorlevel=3 if ($errorlevel<3);
      }
      else{
         my $modrec={criticality=>"CR".lc($parrec->{criticality})};
         $self->IfaceCompare($dataobj,
                             $rec,"criticality",
                             $modrec,"criticality",
                             $forcedupd,$wfrequest,\@qmsg,\$errorlevel,
                             mode=>'native');
         $self->IfaceCompare($dataobj,
                             $rec,"customerprio",
                             $parrec,"customerprio",
                             $forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'integer');
         my $modrec={opmode=>lc($parrec->{usage})};
         if ($modrec->{opmode} eq "production"){
            $modrec->{opmode}="prod";
         }
         elsif ($modrec->{opmode} eq "test"){
            $modrec->{opmode}="test";
         }
         elsif ($modrec->{opmode} eq "development"){
            $modrec->{opmode}="devel";
         }
         elsif ($modrec->{opmode} eq "training"){
            $modrec->{opmode}="education";
         }
         else{
            $modrec->{opmode}="pilot";
         }
         $self->IfaceCompare($dataobj,
                             $rec,"opmode",
                             $modrec,"opmode",
                             $forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'string');
      #   $self->IfaceCompare($dataobj,  # dies wird durch die "normale"
      #                       $rec,"acinmassingmentgroup",  # quality rule
      #                       $parrec,"iassignmentgroup",   # bereits gesynct
      #                       $forcedupd,$wfrequest,
      #                       \@qmsg,\@dataissue,\$errorlevel,
      #                       mode=>'string');
      }
   }

   if (keys(%$forcedupd)>0){
      msg(INFO,sprintf("forceupd=%s\n",Dumper($forcedupd)));
      if ($dataobj->ValidatedUpdateRecord($rec,$forcedupd,{id=>\$rec->{id}})){
         push(@qmsg,"all desired fields has been updated: ".
                    join(", ",keys(%$forcedupd)));
      }
      else{
         push(@qmsg,$self->getParent->LastMsg());
         $errorlevel=3 if ($errorlevel<3);
      }
   }
   if (keys(%$wfrequest)){
      my $msg="different values stored in AssetManager: ";
      push(@qmsg,$msg);
      push(@dataissue,$msg);
      $errorlevel=3 if ($errorlevel<3);
   }
   return($self->HandleWfRequest($dataobj,$rec,
                                 \@qmsg,\@dataissue,\$errorlevel,$wfrequest));
}



1;
