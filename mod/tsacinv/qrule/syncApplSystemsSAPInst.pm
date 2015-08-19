package tsacinv::qrule::syncApplSystemsSAPInst;
#######################################################################
=pod

=head3 PURPOSE

This rule checks an application in CI-Status "installed/active" or "available"
with managed item group "SAP".
It detects all systems of related SAP-Instances in AssetManager and
synchronizes the system relations of the application automatically.

Not yet existing assets and systems will be previously automatically created.

If an automtic action fails, it produces an error.

=head3 IMPORTS

NONE

=head3 HINTS

[en:]

If an automatic action has failed, please try to do it manually.
If necessary, please contact the W5Base/Darwin 1st level support.

Possible actions are:

- Add or remove of a system relation

- Create an asset

- Create a logical system

[de:]

Wenn eine automatische Aktion fehlgeschlagen ist,
versuchen Sie diese bitte manuell durchzuf�hren.
Falls n�tig, kontaktieren Sie bitte den W5Base/Darwin 1st Level Support.

M�gliche Aktionen sind:

- Hinzuf�gen oder entfernen einer Verkn�pfung mit einem System

- Anlegen eines Assets

- Anlegen eines logischen Systems

=cut

#######################################################################
#
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
@ISA=qw(kernel::QRule);

# Databoss for new systems/assets
our $newCIDataboss='12808977330001';

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   return($self);
}

sub getPosibleTargets
{
   return(["TS::appl"]);
}

sub qcheckRecord
{
   my $self=shift;
   my $dataobj=shift;
   my $rec=shift;

   ##################################################################
   # mz 2015-08-18 
   # while testing under production conditions
   # only these applications will be considered:
   my @appl2chk=(qw(12199294360024 12199302380006 12962281170017
                    13355257150001 14157032310001 250));
   return(0,undef) if (!in_array(\@appl2chk,$rec->{id}));
   ##################################################################

   return(0,undef) if ($rec->{cistatusid}!=4 && $rec->{cistatusid}!=3);
   return(0,undef) if (!in_array($rec->{mgmtitemgroup},'SAP'));

   my $acapplappl=getModuleObject($self->getParent->Config,
                                  "tsacinv::lnkapplappl");
   $acapplappl->SetFilter({parent_applid=>$rec->{applid},type=>\'SAP'});
   my @sapappls=$acapplappl->getHashList(qw(lchildid));

   return(0,undef) if ($#sapappls==-1);

   my $acapplsys=getModuleObject($self->getParent->Config,
                                 "tsacinv::lnkapplsystem");
   my $applsys=getModuleObject($self->getParent->Config,
                               "itil::lnkapplsystem");

   # Systems in SAP-Relations
   my @sapapplids=map {$_->{lchildid}} @sapappls;
   $acapplsys->SetFilter({lparentid=>\@sapapplids});
   my @sapsys=$acapplsys->getHashList(qw(systemid child sysstatus));

   # Systems in W5Base application
   $applsys->SetFilter({applid=>\$rec->{id}});
   my @w5sys=$applsys->getHashList(qw(systemsystemid system systemcistatusid));

   my %allsys;
   foreach my $sys (@sapsys) {
      $allsys{$sys->{systemid}}{is_sap}++;
      $allsys{$sys->{systemid}}{name}=lc($sys->{child});
   }
   foreach my $sys (@w5sys) {
      $allsys{$sys->{systemsystemid}}{is_w5}++;
      $allsys{$sys->{systemsystemid}}{name}=$sys->{system};
   }
   
   my @missingsys=grep {$allsys{$_}{is_sap} && !$allsys{$_}{is_w5}}
                       keys(%allsys);

   my @disusedsys=grep {$allsys{$_}{is_w5} && !$allsys{$_}{is_sap}}
                       keys(%allsys);

   return(0,undef) if ($#missingsys==-1 && $#disusedsys==-1);

   my @qmsg;
   my @dataissue;
   my $errorlevel=0;
   my @notifymsg;

   $dataobj->NotifyWriteAuthorizedContacts($rec,undef,{
      emailcc=>['11634955120001'],
   },{
      autosubject=>1,
      autotext=>1,
      mode=>'QualityCheck',
      datasource=>'SAP-Instances in AssetManager'
   },sub {
      my $sysobj=getModuleObject($self->getParent->Config,"itil::system"); 

      # add missing system-relations to application
      foreach my $sys2add (@missingsys) {
         $sysobj->ResetFilter();
         $sysobj->SetFilter({systemid=>\$sys2add});
         my ($w5s,$msg)=$sysobj->getOnlyFirst(qw(id));

         my $w5id;
         $w5id=$w5s->{id} if (defined($w5s->{id}));

         if (!defined($w5id)) {
            my $uobj=getModuleObject($self->getParent->Config,"base::user");
            $uobj->SetFilter({userid=>\$newCIDataboss,cistatusid=>[4]});
            my ($user,$msg)=$uobj->getOnlyFirst(qw(userid));
            $newCIDataboss=$rec->{databossid} if (!defined($user));

            my $newrec={name=>$allsys{$sys2add}{name},
                        systemid=>$sys2add,
                        databossid=>\$newCIDataboss,
                        mandatorid=>$rec->{mandatorid},
                        allowifupdate=>1,
                        cistatusid=>4};
            my $assetid=$self->chkAsset($newrec,$rec,
                                        \$errorlevel,
                                        \@qmsg,\@dataissue,\@notifymsg);
            if (defined($assetid)) {
               $newrec->{asset}=$assetid;
               $w5id=$sysobj->ValidatedInsertRecord($newrec);
               if (defined($w5id)) {
                  ($w5s,$msg)=$sysobj->getOnlyFirst(qw(urlofcurrentrec));
                  my $m=sprintf($self->T("System '%s' created"),
                                $newrec->{name});
                  push(@qmsg,$m);
                  $m.="\n  $w5s->{urlofcurrentrec}";
                  push(@notifymsg,$m);
               }
               else {
                  $errorlevel=3 if ($errorlevel<3);
                  my $m=sprintf($self->T("Automatic creation ".
                                         "of System '%s' failed"),
                                $newrec->{name});
                  push(@qmsg,$m);
                  push(@dataissue,$m);
               }
            }
         }

         if (defined($w5id)) {
            my $newrec={systemid=>$w5id,
                        applid=>$rec->{id},
                        comments=>'automatic added by qrule'};

            if ($applsys->ValidatedInsertRecord($newrec)) {
               my $m=sprintf($self->T("Relation with system '%s' added"),
                             $allsys{$sys2add}{name});
               push(@qmsg,$m);
               push(@notifymsg,$m);
            }
            else {
               $errorlevel=3 if ($errorlevel<3);
               my $m=sprintf($self->T("Automatic relation ".
                                      "with system '%s' failed"),
                             $allsys{$sys2add}{name});
               push(@qmsg,$m);
               push(@dataissue,$m);
            }
         }
      } 

      # remove unused system-relations from application
      foreach my $sys2del (@disusedsys) {
         $applsys->ResetFilter();
         $applsys->SetFilter({systemsystemid=>\$sys2del,
                              applapplid=>\$rec->{applid}});
         my ($lnk,$msg)=$applsys->getOnlyFirst('id');
         my $lnkid=$applsys->ValidatedDeleteRecord($lnk);
         if (defined($lnkid)) {
            my $m=sprintf($self->T("Relation with system '%s' removed"),
                          $allsys{$sys2del}{name});
            push(@qmsg,$m);
            push(@notifymsg,$m);
         }
         else {
            $errorlevel=3 if ($errorlevel<3);
            my $m=sprintf($self->T("Automatic removal of relation ".
                                   "with system '%s' failed"),
                          $allsys{$sys2del}{name});
            push(@qmsg,$m);
            push(@dataissue,$m);
         }
      } 

      if ($#notifymsg!=-1) {
         return($rec->{name},join("\n\n",map({"- ".$_} @notifymsg)));
      }
      return(undef,undef);
   });

   return($errorlevel,{qmsg=>\@qmsg,dataissue=>\@dataissue});
}


sub chkAsset {
   my $self=shift;
   my $sysdata=shift;
   my $rec=shift;
   my $errorlevel=shift;
   my $qmsg=shift;
   my $dataissue=shift;
   my $notifymsg=shift;

   my $acsys=getModuleObject($self->getParent->Config,"tsacinv::system");
   my $acasset=getModuleObject($self->getParent->Config,"tsacinv::asset");
   my $asset=getModuleObject($self->getParent->Config,"itil::asset");

   $acsys->SetFilter({systemid=>$sysdata->{systemid}});
   my ($sysasset,$msg)=$acsys->getOnlyFirst('lassetid');
   return(undef) if (!defined($sysasset->{lassetid}));

   $acasset->SetFilter({lassetid=>$sysasset->{lassetid},status=>\'in work'});
   my ($assetasset,$msg)=$acasset->getOnlyFirst('assetid');
   return(undef) if (!defined($assetasset->{assetid}));

   $asset->SetFilter({name=>$assetasset->{assetid}});

   if ($asset->CountRecords()==0) {
      my $newrec={name=>$assetasset->{assetid},
                  databossid=>\$newCIDataboss,
                  mandatorid=>$rec->{mandatorid},
                  allowifupdate=>1,
                  cistatusid=>4};
      if ($asset->ValidatedInsertRecord($newrec)) {
         my ($w5a,$msg)=$asset->getOnlyFirst(qw(urlofcurrentrec));
         my $m=sprintf($self->T("Asset '%s' created"),$newrec->{name});
         push(@$qmsg,$m);
         $m.="\n  $w5a->{urlofcurrentrec}";
         push(@$notifymsg,$m);
      }
      else {
         $$errorlevel=3 if ($errorlevel<3);
         my $m=sprintf($self->T("Automatic creation of asset '%s' failed"),
                       $newrec->{name});
         push(@$qmsg,$m);
         push(@$dataissue,$m);
         return(undef);
      }
   }

   return($assetasset->{assetid});
}



1;



