package TS::event::updateBusinessTeam;
#  W5Base Framework
#  Copyright (C) 2016  Hartmut Vogler (it@guru.de)
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

   $self->RegisterEvent("updbusinessteam","updbusinessteam");
   return(1);
}

sub updbusinessteam
{
   my $self=shift;

   my $debug=grep(/^debug$/i,@_);
   my $force=grep(/^force$/i,@_); # definitely take team of TSM/OPM
                                  # as businessteam
   my @param=grep(/^id$|^mandatorid$/i,@_);

   if ($#param!=0) {
      my $msg="Entweder 'id' (Appl-ID) oder 'mandatorid' angeben!";
      msg(ERROR,$msg);
      return({exitcode=>1,msg=>$msg});
   }

   if ($force && lc($param[0]) ne 'id') {
      my $msg="'force' nur in Verbindung mit 'id' (Appl-ID) erlaubt!";
      msg(ERROR,$msg);
      return({exitcode=>1,msg=>$msg});
   }

   my @id=grep(/^\d+$/,@_);
   if ($#id==-1) {
      my $msg="Keine Appl-ID oder Mandator-ID angegeben!";
      msg(ERROR,$msg);
      return({exitcode=>1,msg=>$msg});
   }

   my $applobj      =getModuleObject($self->Config,'itil::appl');
   my $applsystemobj=getModuleObject($self->Config,'itil::lnkapplsystem');
   my $systemobj    =getModuleObject($self->Config,'itil::system');
   my $itclustobj   =getModuleObject($self->Config,'itil::itclust');
   my $swinstanceobj=getModuleObject($self->Config,'itil::swinstance');
   my $assetobj     =getModuleObject($self->Config,'itil::asset');
   my $lnkcontactobj=getModuleObject($self->Config,'base::lnkcontact');
   my $grpobj       =getModuleObject($self->Config,'base::grp');
   my $ciamuserobj  =getModuleObject($self->Config,'tsciam::user');

   $applobj->SetFilter({$param[0]=>\@id,
                        cistatusid=>[3,4]});
   my @appls=$applobj->getHashList(qw(id name urlofcurrentrec
                                      businessteam businessteamid
                                      tsmid opmid databossid));
   my %usercnt;   # count users in old CIAM group

   # 'force' should be the standard
   $force=1;
   
   foreach my $appl (@appls) {

      my @bteamcontacts=();
      push(@bteamcontacts,$appl->{tsmid}) if defined($appl->{tsmid});
      push(@bteamcontacts,$appl->{opmid}) if defined($appl->{opmid});

      next if (!defined($appl->{businessteamid}));
      next if ($#bteamcontacts==-1);

      my $contact;
      my $grps;
      my $found=0;

      while ($#bteamcontacts!=-1 && !$found) {
         $contact=shift(@bteamcontacts);
         $grps=$self->getPossibleGrps($contact);

         if (in_array($grps,$appl->{businessteamid})) {
            $found++;
         }
      }

      next if (!$found);
      next if ($#{$grps}==0);

      my $curteam=$self->getCurrentTeam($contact);

      next if (!defined($curteam->{grpid}));
      next if ($curteam->{grpid}==$appl->{businessteamid});

      $grpobj->ResetFilter();
      $grpobj->SetFilter({grpid=>$appl->{businessteamid}});
      my ($oldgrp,$msg)=$grpobj->getOnlyFirst(qw(srcid name));

      next if (!defined($oldgrp));

      if (exists($usercnt{$oldgrp->{srcid}}) &&
          $usercnt{$oldgrp->{srcid}}>0 && !$force) {
         next;
      }

      if (!exists($usercnt{$oldgrp})) {
         # count user in CIAM group only if not yet done
         $ciamuserobj->ResetFilter();
         $ciamuserobj->SetFilter({toucid=>$oldgrp->{srcid},
                                  active=>\'true'});
         my @oldgrpuser=$ciamuserobj->getHashList(qw(tcid));
         $usercnt{$oldgrp->{srcid}}=scalar(@oldgrpuser);
      }

      if (!exists($usercnt{$oldgrp->{srcid}}) ||
          ($usercnt{$oldgrp->{srcid}}>0 && !$force)) {
         next;
      }

      #######################################################################
      # OK, Busineesteam and all dependencies will be updated now
      #######################################################################
      my %oldrec=%$appl;
      my %newrec=(businessteamid=>$curteam->{grpid});
      my %paramlnkcontact=(oldgrp=>$appl->{businessteamid},
                           newgrp=>$curteam->{grpid});

      # used for notification informations
      my %applinfo=(name=>$appl->{name},
                    oldteam=>$appl->{businessteam},
                    newteam=>$curteam->{fullname});
      my %dbossinfo;
      my $updated;

      # change businessteam of application
      msg(WARN,"Refresh Businessteam of '$oldrec{name}':\n".
               "----------------------------------------\n".
               "old: $oldrec{businessteam}\n".
               "new: $curteam->{fullname}\n");
      if (!$debug) {
         if (!$applobj->ValidatedUpdateRecord(\%oldrec,\%newrec,
                                              {id=>$appl->{id}})) {
            next;
         }
         $dbossinfo{$appl->{databossid}}{$appl->{name}}=
            $appl->{urlofcurrentrec};
      }

      # change grp of linked contact in appl
      $self->updateLnkContact($lnkcontactobj,$debug,
                              refid=>$appl->{id},
                              parentobj=>'itil::appl',
                              %paramlnkcontact);

      #########################################################################
      # SYSTEMS
      #########################################################################
      $applsystemobj->ResetFilter();
      $applsystemobj->SetFilter({applid=>$appl->{id},
                                 systemcistatusid=>[3,4]});
      my $lnksystems=$applsystemobj->getHashList(qw(systemid));

      my @w5systemids=map($_->{systemid},@$lnksystems);
      
      if ($#w5systemids!=-1) {
         $systemobj->ResetFilter();
         $systemobj->SetFilter({id=>\@w5systemids});
         my @systems=$systemobj->getHashList(
                        qw(id name databossid adminteamid assetid
                           isclusternode itclustid urlofcurrentrec));

         foreach my $system (@systems) {
            $updated=0;
            # change adminteam of system
            if ($system->{adminteamid}==$appl->{businessteamid}) {
               msg(WARN,"Refresh Adminteam of '$system->{name}'");
               if (!$debug) {
                  if ($systemobj->ValidatedUpdateRecord(
                                     $system,
                                     {adminteamid=>$curteam->{grpid}},
                                     {id=>\$system->{id}})) {
                     $updated++;
                  }
               }
            }
     
            # change grp of linked contact in system
            if ($self->updateLnkContact($lnkcontactobj,$debug,
                                        refid=>$system->{id},
                                        parentobj=>'itil::system',
                                        %paramlnkcontact)) {
               $updated++;
            }

            if ($updated) {
               $dbossinfo{$system->{databossid}}{$system->{name}}=
                  $system->{urlofcurrentrec};
            }

            ###################################################################
            # ASSET
            ###################################################################
            if (defined($system->{assetid})) {
               $updated=0;
               $assetobj->ResetFilter();
               $assetobj->SetFilter({id=>$system->{assetid},
                                     cistatusid=>[3,4]});
               my ($asset,$msg)=$assetobj->getOnlyFirst(qw(id name databossid
                                                          guardianteamid
                                                          urlofcurrentrec));
               # change guardianteam of asset
               if ($asset->{guardianteamid}==$appl->{businessteamid}) {
                  msg(WARN,"Refresh Guardianteam of '$asset->{name}'");
                  if (!$debug) {
                     if ($assetobj->ValidatedUpdateRecord(
                                       $asset,
                                       {guardianteamid=>$curteam->{grpid}},
                                       {id=>\$asset->{id}})) {
                        $updated++;
                     }
                  }
               }

               # change grp of linked contact in asset
               if ($self->updateLnkContact($lnkcontactobj,$debug,
                                           refid=>$asset->{id},
                                           parentobj=>'itil::asset',
                                           %paramlnkcontact)) {
                  $updated++;
               }

               if ($updated) {
                  $dbossinfo{$asset->{databossid}}{$asset->{name}}=
                     $asset->{urlofcurrentrec};
               }
            }
         }

         ######################################################################
         # CLUSTER
         ######################################################################
         my %itclustids=map({$_->{itclustid}=>1}
                        grep($_->{isclusternode},@systems));
         my @clids=keys(%itclustids);

         if ($#clids!=-1) {
            $itclustobj->ResetFilter();
            $itclustobj->SetFilter({id=>\@clids,cistatusid=>[3,4]});
            my @itclusts=$itclustobj->getHashList(
                                         qw(id fullname databossid
                                            urlofcurrentrec));
            foreach my $cluster (@itclusts) {
               # change grp of linked contact in cluster
               if ($self->updateLnkContact($lnkcontactobj,$debug,
                                           refid=>$cluster->{id},
                                           parentobj=>'itil::itclust',
                                           %paramlnkcontact)) {
                  $dbossinfo{$cluster->{databossid}}{$cluster->{fullname}}=
                     $cluster->{urlofcurrentrec};
               }
            }
         }
      }

      #########################################################################
      # SOFTWARE INSTANCES
      #########################################################################
      $swinstanceobj->ResetFilter();
      $swinstanceobj->SetFilter({applid=>$appl->{id},
                                 cistatusid=>[3,4]});
      my @swinstances=$swinstanceobj->getHashList(qw(ALL));

      foreach my $instance (@swinstances) {
         $updated=0;
         # change Instance guardian team
         if ($instance->{swteamid}==$appl->{businessteamid}) {
            msg(WARN,"Refresh Instance guardian team of ".
                     "'$instance->{fullname}'");
            if (!$debug) {
               if ($swinstanceobj->ValidatedUpdateRecord(
                                      $instance,
                                      {swteamid=>$curteam->{grpid}},
                                      {id=>\$instance->{id}})) {
                  $updated++;
               }
            }
         }

         # change grp of linked contact in swinstance
         if ($self->updateLnkContact($lnkcontactobj,$debug,
                                     refid=>$instance->{id},
                                     parentobj=>'itil::swinstance',
                                     %paramlnkcontact)) {
            $updated++;
         }

         if ($updated) {
            $dbossinfo{$instance->{databossid}}{$instance->{fullname}}=
               $instance->{urlofcurrentrec};
         }
      }

      foreach my $databossid (keys(%dbossinfo)) {
         $self->databossNotify($databossid,\%applinfo,$dbossinfo{$databossid});
      }
   }

   return({exitcode=>0,msg=>'ok'});
}


sub databossNotify
{
   my $self=shift;
   my $databossid=shift;
   my $applinfo=shift;
   my $notifydata=shift;

   my $userobj=getModuleObject($self->Config,'base::user');
   $userobj->SetFilter({userid=>$databossid});
   my ($databoss,$msg)=$userobj->getOnlyFirst(qw(lastlang));

   my $oldlang;
   if (defined($ENV{HTTP_FORCE_LANGUAGE})) {
      $oldlang=$ENV{HTTP_FORCE_LANGUAGE};
   }
   $ENV{HTTP_FORCE_LANGUAGE}=$databoss->{lastlang};

   my $subject=$self->T("Automatic data update");
   $subject.=" '".$applinfo->{name}."' ";
   $subject.=$self->T("based on reorganisation");
   my $items;

   foreach my $ciname (keys(%$notifydata)) {
      $items.=$ciname."\n";
      $items.=$notifydata->{$ciname}."\n\n";
   }

   my $text=$self->getParsedTemplate('tmpl/ext.event.updbusinessteam',
                                     {skinbase=>'TS',
                                      static=>{
                                         appl=>$applinfo->{name},
                                         oldteam=>$applinfo->{oldteam},
                                         newteam=>$applinfo->{newteam},
                                         items=>$items
                                      }});

   my $supportnote=$userobj->getParsedTemplate("tmpl/mailsend.supportnote",
                                               {static=>{}});
   $text.=$supportnote if ($supportnote ne "");

   my $wfact=getModuleObject($self->Config,'base::workflowaction');
   $wfact->Notify('INFO',$subject,$text,'emailto'=>$databossid,
                                        'adminbcc'=>1);

   if (defined($oldlang)) {
      $ENV{HTTP_FORCE_LANGUAGE}=$oldlang;
   }
   else {
      delete($ENV{HTTP_FORCE_LANGUAGE});
   }
}


sub updateLnkContact
{
   my $self=shift;
   my $dataobj=shift;
   my $debug=shift;
   my %param=@_;
   my $updated;

   $dataobj->ResetFilter();
   $dataobj->SetFilter({refid=>$param{refid},
                        parentobj=>$param{parentobj},
                        target=>\'base::grp',
                        targetid=>[$param{oldgrp},$param{newgrp}]});
   my @lnkcontact=$dataobj->getHashList(qw(ALL));

   if ($#lnkcontact==0 && $lnkcontact[0]->{targetid}==$param{oldgrp}) {
      # update linked contact only if link to new contact not yet exists
      my $lnkid=$lnkcontact[0]->{id};
      msg(WARN,"Update Kontaktverkn�pfung '$lnkid' ".
               "($lnkcontact[0]->{parentobj})\n");
      if (!$debug) {
         $updated=$dataobj->ValidatedUpdateRecord($lnkcontact[0],
                                                  {targetid=>$param{newgrp}},
                                                  {id=>$lnkid});
      }
   }

   return($updated);
}

 
sub getPossibleGrps
{
   my $self=shift;
   my $userid=shift;

   return(undef) if (!defined($userid));

   my $lnkgrpuserobj=getModuleObject($self->Config,'base::lnkgrpuser');

   $lnkgrpuserobj->SetFilter({userid=>\$userid,
                              srcsys=>\'CIAM'});
   my $grps=$lnkgrpuserobj->getHashList(qw(grpid));
   my @res=map({$_->{grpid}} @$grps);

   return(\@res);
}


sub getCurrentTeam
{
   my $self=shift;
   my $userid=shift;

   my $userobj=getModuleObject($self->Config,'base::user');
   my $grpobj=getModuleObject($self->Config,'base::grp');
   my $ciamuserobj=getModuleObject($self->Config,'tsciam::user');

   my $msg;
   $userobj->SetFilter({userid=>\$userid});
   (my $user,$msg)=$userobj->getOnlyFirst('dsid');
   (my $tcid=$user->{dsid})=~s/tCID:(\d+)$/$1/;

   $ciamuserobj->SetFilter({tcid=>$tcid,
                            active=>\'true'});
   (my $ciamuser,$msg)=$ciamuserobj->getOnlyFirst(qw(toucid));

   $grpobj->SetFilter({srcsys=>\'CIAM',
                       srcid=>$ciamuser->{toucid},
                       cistatusid=>[3,4]});

   (my $res,$msg)=$grpobj->getOnlyFirst(qw(grpid fullname));

   return($res);
}



1;
