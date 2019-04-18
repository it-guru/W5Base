package tsotc::qrule::compareSystem;
#######################################################################
=pod

=encoding latin1

=head3 PURPOSE

This QualityRule compares a W5Base/Darwin logical system to an OTC 
logical system and updates the defined fields if necessary. Automated
imports are only done if the field "Allow automatic interface updates"
is set to "yes". 

=head3 IMPORTS

The fields Memory, CPU-Count, CO-Number, Description, Systemname
are imported from OTC. IP-Addresses can only be synced when the field 
"Allow automatic interface updates" is set to "yes". 

=head3 HINTS

[en:]


[de:]



=cut

#######################################################################
#
#  W5Base Framework
#  Copyright (C) 2019  Hartmut Vogler (it@guru.de)
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
   return(["itil::system","AL_TCom::system"]);
}

sub qcheckRecord
{
   my $self=shift;
   my $dataobj=shift;
   my $rec=shift;
   my $checksession=shift;
   my $autocorrect=$checksession->{autocorrect};


   my $wfrequest={};
   my $forcedupd={};
   my @qmsg;
   my @dataissue;
   my $errorlevel=0;

   return(undef,undef) if ($rec->{srcsys} ne "OTC");

   my ($parrec,$msg);
   my $par=getModuleObject($self->getParent->Config(),"tsotc::system");
   return(undef,undef) if (!$par->Ping());


   #
   # Level 1
   #
   if (!defined($parrec)){      # pruefen ob wir bereits nach OTC geschrieben
      # try to find parrec by srcsys and srcid
      $par->ResetFilter();
      $par->SetFilter({id=>\$rec->{srcid}});
      ($parrec)=$par->getOnlyFirst(qw(ALL));
   }

   #
   # Level 3
   #
   # Das zur�cksetzen der srcid bei veraltet/gel�schten Elementen ist
   # vielleicht doch keine so gute Idee
   #
   #if ($rec->{cistatusid}>5){
   #   if ($rec->{srcid} ne ""){
   #      $forcedupd->{srcid}=undef;
   #      $forcedupd->{srcload}=undef;
   #   }
   #}
   if ($rec->{cistatusid}==4 || $rec->{cistatusid}==3 ||
       $rec->{cistatusid}==5){
      if ($rec->{srcid} ne "" && $rec->{srcsys} eq "OTC"){
         if (!defined($parrec)){
            push(@qmsg,'given id not found in OTC');
            push(@dataissue,'given id not found in OTC');
            $errorlevel=3 if ($errorlevel<3);
         }
         else{
            if ($rec->{srcsys} eq "OTC"){
               # assetid compare 

               if (defined($parrec->{name})){
                  $parrec->{name}=lc($parrec->{name});
                  $parrec->{name}=~s/\..*$//; # remove posible Domain part 
               }
               my $nameok=1;
               if ($parrec->{name} ne $rec->{name} &&
                   ($parrec->{name}=~m/\s/)){
                  $nameok=0;
                  my $m='systemname with whitespace in OTC - '.
                        'contact OTC Admin to fix this!';
                  push(@qmsg,$m);
                  push(@dataissue,$m);
                  $errorlevel=3 if ($errorlevel<3);
               }
               if ($parrec->{name}=~m/\.\S{1,3}$/){
                  $parrec->{name}=~s/\..*//;
                  my $m='systemname with DNS Domain in OTC - '.
                        'contact OTC Admin to fix this!';
                  push(@qmsg,$m);
                  push(@dataissue,$m);
                  $errorlevel=3 if ($errorlevel<3);
               }

               if ($parrec->{name}=~m/^\s*$/){  # k�nnte notwendig werden!
                  $nameok=0;
                  push(@qmsg,'systemname from OTC not useable - '.
                             'contact OTC Admin to fix this!');
                  $errorlevel=3 if ($errorlevel<3);
               }
               if ($nameok){
                  $dataobj->ResetFilter();
                  $dataobj->SetFilter({name=>\$parrec->{name},
                                       id=>"!".$rec->{id}});
                  my ($chkrec,$msg)=$dataobj->getOnlyFirst(qw(id name));
                  if (defined($chkrec)){
                     $nameok=0;
                     my $m='systemname from OTC is already in use '.
                           'by an other system - '.
                           'contact OTC Admin to make the systemname unique!';
                     push(@qmsg,$m);
                     push(@dataissue,$m);
                     $errorlevel=3 if ($errorlevel<3);
                  }
               }

               if ($nameok){
                  $self->IfComp($dataobj,
                                $rec,"name",
                                $parrec,"name",
                                $autocorrect,$forcedupd,$wfrequest,
                                \@qmsg,\@dataissue,\$errorlevel,
                                mode=>'string');
               }
               $self->IfComp($dataobj,
                             $rec,"cpucount",
                             $parrec,"cpucount",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'integer');

               $self->IfComp($dataobj,
                             $rec,"memory",
                             $parrec,"memory",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'integer');

               $self->IfComp($dataobj,
                             $rec,"osrelease",
                             $parrec,"image_name",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'leftouterlinkbaselogged',
                             iomapped=>$par);
               if ($autocorrect){
                  my $net=getModuleObject($self->getParent->Config(),
                          "itil::network");
                  $net->SetCurrentView(qw(id name));
                  my $netarea=$net->getHashIndexed("name");
                  my @opList;

                  #
                  # %cleanAmIPlist is neassasary, because multiple IP-Addresses
                  # can be in one networkcard record
                  #
                  my %cleanAmIPlist;
                  foreach my $otciprec (@{$parrec->{ipaddresses}}){
                     my $mappedCIStatus=4;
                     if ($otciprec->{name} ne ""){
                        if ($otciprec->{name}=~
                            m/^\d{1,3}(\.\d{1,3}){3,3}$/){
                           $cleanAmIPlist{$otciprec->{name}}={
                              cistatusid=>$mappedCIStatus,
                              ipaddress=>$otciprec->{name},
                              comments=>trim($otciprec->{comments})
                           };
                        }
                        else{
                           msg(WARN,"ignoring IPv4 invalid ".
                                    "'$otciprec->{name}' ".
                                    "for $parrec->{id}");
                        }
                     }
                  }
                  my @cleanAmIPlist=values(%cleanAmIPlist);

                  my $res=OpAnalyse(
                             sub{  # comperator 
                                my ($a,$b)=@_;
                                my $eq;
                                if ($a->{name} eq $b->{ipaddress}){
                                  $eq=0;
                                   $eq=1 if ($a->{srcsys} eq "OTC" &&
                                             $a->{cistatusid} eq 
                                             $b->{cistatusid}       &&
                                             $a->{comments} eq 
                                             $b->{comments});
                                }
                                return($eq);
                             },
                             sub{  # oprec generator
                                my ($mode,$oldrec,$newrec,%p)=@_;
                                if ($mode eq "insert" || $mode eq "update"){
                                   if ($mode eq "insert" && 
                                       $newrec->{cistatusid} eq "6"){
                                      return(); # do not insert 
                                                # already unconfigured ip's
                                   }
                                   my $networkid=$p{netarea}->{name}->
                                               {'Insel-Netz/Kunden-LAN'}->{id};
                                   my $identifyby=undef;
                                   if ($mode eq "update"){
                                      $identifyby=$oldrec->{id};
                                   }
                                   if ($newrec->{ipaddress}=~m/^\s*$/){
                                      $mode="nop";
                                   }
                                   my $type="1";   # secondary
                                   # Customer Interface can not be marked
                                   # as primary interface, because in some
                                   # cases multiple customer interfaces
                                   # exists in OTC Rotz.
                                   #
                                   #if (lc(trim($newrec->{description})) eq
                                   #    "customer"){
                                   #   $type="0"; # Customer Interface is prim
                                   #}
                                   return({OP=>$mode,
                                           MSG=>"$mode ip $newrec->{ipaddress} ".
                                                "in W5Base",
                                           IDENTIFYBY=>$identifyby,
                                           DATAOBJ=>'itil::ipaddress',
                                           DATA=>{
                                              name      =>$newrec->{ipaddress},
                                              cistatusid=>$newrec->{cistatusid},
                                              srcsys    =>'OTC',
                                              type      =>$type,
                                              networkid =>$networkid,
                                              comments  =>$newrec->{comments},
                                              systemid  =>$p{refid}
                                              }
                                           });
                                }
                                elsif ($mode eq "delete"){
                                   my $networkid=$oldrec->{networkid};
                                   if ($networkid ne $p{netarea}->{name}->
                                       {'Insel-Netz/Kunden-LAN'}->{id}){
                                      return();
                                   }
                                   return({OP=>$mode,
                                           MSG=>"delete ip $oldrec->{name} ".
                                               "from W5Base",
                                           DATAOBJ=>'itil::ipaddress',
                                           IDENTIFYBY=>$oldrec->{id},
                                           });
                                }
                                return(undef);
                             },
                             $rec->{ipaddresses},\@cleanAmIPlist,\@opList,
                             refid=>$rec->{id},netarea=>$netarea);
                  if (!$res){
                     my $opres=ProcessOpList($self->getParent,\@opList);
                  }
               }
            }
            if (!($parrec->{availability_zone}=~m/^eu[0-9a-z-]{3,10}$/)){
               my $msg='invalid availability zone from OTC';
               push(@qmsg,$msg);
               push(@dataissue,$msg);
               $errorlevel=3 if ($errorlevel<3);
            }
            else{  # handling AssetID
               my $ass=getModuleObject($self->getParent->Config(),
                                       "itil::asset");
               my $k="OTC: Availability Zone ".$parrec->{availability_zone};
               msg(INFO,"checking assetid for '$k'");
               $ass->SetFilter({
                  kwords=>\$k,
                  cistatusid=>[4],
                  srcsys=>\'w5base'
               }); 
               my @l=$ass->getHashList(qw(id name fullname));
               if ($#l==-1){
                  my $msg='can not identify availability zone asset from OTC';
                  push(@qmsg,$msg);
                  push(@dataissue,$msg);
               }
               elsif ($#l>0){
                  my $msg='availability zone asset not unique from OTC';
                  push(@qmsg,$msg);
                  push(@dataissue,$msg);
               }
               else{
                  $self->IfComp($dataobj,
                                $rec,"asset",
                                {assetassetid=>$l[0]->{name}},"assetassetid",
                                $autocorrect,$forcedupd,$wfrequest,
                                \@qmsg,\@dataissue,\$errorlevel,
                                mode=>'leftouterlink');
               }
            }
         }
      }
   }

   if (keys(%$forcedupd)){
      #printf STDERR ("fifi request a forceupd=%s\n",Dumper($forcedupd));
      if ($dataobj->ValidatedUpdateRecord($rec,$forcedupd,{id=>\$rec->{id}})){
         my @fld=grep(!/^srcload$/,keys(%$forcedupd));
         if ($#fld!=-1){
            push(@qmsg,"all desired fields has been updated: ".join(", ",@fld));
         }
      }
      else{
         push(@qmsg,$self->getParent->LastMsg());
         $errorlevel=3 if ($errorlevel<3);
      }
   }
   if (keys(%$wfrequest)){
      my $msg="different values stored in OTC: ";
      push(@qmsg,$msg);
      push(@dataissue,$msg);
      $errorlevel=3 if ($errorlevel<3);
   }
   return($self->HandleWfRequest($dataobj,$rec,
                                 \@qmsg,\@dataissue,\$errorlevel,$wfrequest));
}



1;
