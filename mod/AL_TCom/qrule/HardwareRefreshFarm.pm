package AL_TCom::qrule::HardwareRefreshFarm;
#######################################################################
=pod

=encoding latin1

=head3 PURPOSE

Checking the age of hardware/asset items. This quality rules controles
the refresh of hardware items. The handling is aligned to a maximum
age of 84 months.

=head3 IMPORTS

NONE

=head3 HINTS

[en:]

This QualityRule is effective if the start of depreciation is 
after 2011-06-30.

The refresh quality rule is focused on the fact that the 
hardware asset is to be in use 84 months at the maximum. 
The counting is based on the start date of depreciation/amortization. 
Therefore it applies  for/to:

  DeadLine = start of depreciation + 84 months

  RefreshData = DeadLine or denyupdvalidto if denyupdvalidto is valid.

A DataIssue are not generated, because responsibility of ServerFarm 
managers.

Further information or contacts can be found at ...
https://darwin.telekom.de/darwin/auth/faq/article/ById/14007521580001

[de:]

Diese QualityRule greift, wenn der Abschreibungsbeginn 
nach dem 30.06.2011 liegt.

Die Refresh QualityRule ist darauf ausgerichtet, dass ein 
Hardware-Asset max. 84 Monate im Einsatz sein darf. Die Berechnung
erfolgt auf Basis des Abschreibungsbeginns.
Somit gilt:

 DeadLine = Abschreibungsbeginn + 84 Monate

 RefreshData = DeadLine oder denyupdvalidto falls denyupdvalidto g�ltig ist.

Weitere Infos bzw. Ansprechpartner finden Sie unter ...
https://darwin.telekom.de/darwin/auth/faq/article/ById/14007521580001


=cut
#######################################################################
#  W5Base Framework
#  Copyright (C) 2015  Hartmut Vogler (it@guru.de)
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
use AL_TCom::qrule::HardwareRefresh;
@ISA=qw(AL_TCom::qrule::HardwareRefresh);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   return($self);
}

sub checkServerfarmConsideration
{
   my $self=shift;
   my $rec=shift;

   return(0) if ($rec->{itfarm} ne "");

   return(1);
}


sub getDefaultDeadline
{
   my $self=shift;
   my $dataobj=shift;
   my $rec=shift;

   my $deprstart=$rec->{deprstart};
   my $deadline;
   if ($deprstart ne ""){
      $deadline=$self->getParent->ExpandTimeExpression($deprstart."+84M");
   }
   return($deadline);
}




sub allowDataIssueWorkflowCreation
{
   my $self=shift;
   my $rec=shift;

   return(0);
}


sub getFarmUserIds
{
   my $self=shift;
   my $rec=shift;

   my $farmid=$rec->{itfarmid};
   my @farmuids;
   if ($farmid ne ""){
      my $itfarm=getModuleObject($self->getParent->Config,"itil::itfarm");
      $itfarm->SetFilter({id=>\$farmid});
      @farmuids=$itfarm->getVal("databossid");
   }
   return(@farmuids);
}



sub finalizeNotifyParam
{
   my $self=shift;
   my $rec=shift;
   my $notifyparam=shift;
   my $mode=shift;

   if ($rec->{itfarm} ne ""){
      $notifyparam->{emailto}=[$self->getFarmUserIds($rec)];
   }
}







1;
