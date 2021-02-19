package tsacinv::qrule::compareSystem;
#######################################################################
=pod

=encoding latin1

=head3 PURPOSE

This QualityRule compares a W5Base/Darwin logical system to an AssetManager
logical system and updates the defined fields if necessary. Automated
imports are only done if the field "Allow automatic interface updates"
is set to "yes". If a logical system is a workstation, no DataIssue Workflow
about a missing System ID is created. If the System ID is the same as the 
W5BaseID, no error is generated, because the system is handled as a
"locally documented only". Only logical systems in W5Base with state 
"installed/active" are synced!

=head3 IMPORTS

The fields Memory, CPU-Count, CO-Number, Description, Systemname (since 04/2011)
are imported from AssetManager. IP-Addresses can only be synced when the field 
"Allow automatic interface updates" is set to "yes". If the Mandator is set to
"Extern" and "Allow automatic interface updates" is set to "yes" some aditional
Imports are posible:

- "W5Base Administrator" field is set to the supervisor of Assignmentgroup in AC

- "AC Assignmentgroup" is imported to the comments field in W5Base

If the system type is vmware, the AssetID from AssetManager will NOT be imported.

=head3 HINTS

[en:]

If the logical system is maintained in AssetManager by the TSI and only 
mirrored to W5Base/Darwin, set the field "allow automatic updates by 
interfaces" in the block "Control-/Automationinformations" to "yes". 
The data will then be synchronised automatically.

[de:]

Falls das logische System in AssetManager durch die TSI gepflegt ist, 
sollte das Feld "automatisierte Updates durch Schnittstellen zulassen" 
im Block "Steuerungs-/Automationsdaten" auf "ja" gesetzt werden


=cut
#######################################################################

#  Functions:
#  * at cistatus "installed/active" and "availabel":
#    - check if systemid is valid in tsacinv::system
#    - check if assetid is valid in tsacinv::asset 
#
#######################################################################
#
#  W5Base Framework
#  Copyright (C) 2007  Hartmut Vogler (it@guru.de)
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

   my ($parrec,$msg);
   my $par=getModuleObject($self->getParent->Config(),"tsacinv::system");

   # ATTENTION: AssetManager qrule needs to be run in every case of srcsys!
   #            This is needed to allow to get ervery system a systemid from AM!

   #
   # Level 0
   #
   if ($rec->{systemid} ne ""){   # pruefen ob SYSTEMID von AssetManager
      $par->SetFilter({systemid=>\$rec->{systemid},
                       status=>'"!out of operation"',
                       deleted=>\'0'});
      ($parrec,$msg)=$par->getOnlyFirst(qw(ALL));
      return(undef,undef) if (!$par->Ping());
   }
   if (!defined($parrec)){
      if ($rec->{systemid} eq "" && 
          $rec->{scapprgroupid} eq "" && # nur falls noch keine IAC gesetzt!
          $rec->{srcsys} eq "w5base"){
         # Hier wird versucht, eine Verbindung zu AssetManager �ber
         # den Systemnamen aufzubauen
         $par->ResetFilter();
         $par->SetFilter({systemname=>$rec->{name},
                          status=>'"!out of operation"'});
         my @l=$par->getHashList(qw(ALL));
         if ($#l==0){
            if ($l[0]->{srcsys} ne "W5Base"){ #falsch, per neueingabe erfasstes
               $parrec=$l[0];            # System in Darwin -> mu�te eigentlich
            }                            # per Import geladen werden
         }
         elsif($#l>0){
            printf STDERR ("\nThe System with W5BaseID $rec->{id} has been\n");
            printf STDERR ("created with 'New' but AssetManager Import\n");
            printf STDERR ("seems to be the correct way.(Name=$rec->{name})\n");
            printf STDERR ("The name is not unique in AM, so the problem\n");
            printf STDERR ("can not be fixed automaticly.\n");
         }
      }
   }

   #
   # Level 1
   #
   if (!defined($parrec)){      # pruefen ob wir bereits nach AM geschrieben
      # try to find parrec by srcsys and srcid
      $par->ResetFilter();
      $par->SetFilter({srcsys=>\'W5Base',srcid=>\$rec->{id}});
      ($parrec)=$par->getOnlyFirst(qw(ALL));
   }

   #
   # Level 2
   #
   if (defined($parrec)){
      if ($rec->{systemid} ne $parrec->{systemid}){
         $forcedupd->{systemid}=$parrec->{systemid};
      }
      if ($parrec->{srcsys} eq "W5Base"){
         if ($rec->{srcsys} eq "AssetManager"){
            $forcedupd->{srcsys}="w5base";
            if ($rec->{srcid} ne ""){
               $forcedupd->{srcid}=undef;
            }
            # transfer Incident-Assignmentgroup from AssetManager to W5Base
            # System-Record - if no Incident-Assignmentgroup is in W5Base
            if (exists($rec->{acinmassignmentgroupid}) && 
                $rec->{acinmassignmentgroupid} eq ""){
               if ($rec->{acreliassignmentgroup} ne ""){
                  $forcedupd->{acinmassingmentgroup}=
                     $rec->{acreliassignmentgroup}; # transfer Incident-AG
                                                    # from AM to Darwin
               }
            }
         }
      }
      else{
         if ($rec->{srcsys} ne "AssetManager"){
            $forcedupd->{srcsys}="AssetManager";
            $forcedupd->{allowifupdate}="1";  # Beim Switch auf AssetManager
         }                                    # AutoUpdate auf Ja
         if ($rec->{srcid} ne $parrec->{systemid}){
            $forcedupd->{srcid}=$parrec->{systemid};
         }
         $forcedupd->{srcload}=NowStamp("en");
      }
      if (keys(%$forcedupd)){
         if ($rec->{systemid} eq "" &&
             exists($forcedupd->{systemid}) &&
             ($parrec->{usage}=~m/^INVOICE_ONLY/)){
            $parrec=undef;
            my $msg="invoice systems are not allowed ".
                    "to be imported/created";
            push(@qmsg,$msg);
            push(@dataissue,$msg);
            $errorlevel=3 if ($errorlevel<3);
            $forcedupd={};
         }
      }
      if ($rec->{systemid} ne "" && ($parrec->{usage}=~m/^INVOICE_ONLY/)){
         $parrec=undef;
         push(@qmsg,"TSI has migrated the system to INVOICE_ONLY, ".
                    "therefore it needs to be removed ".
                    "from Darwin -> IT-Inventory");
         $forcedupd={};
         $errorlevel=3;
         return($self->HandleWfRequest($dataobj,$rec,
                                 \@qmsg,\@dataissue,\$errorlevel,$wfrequest));
      }
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
      # productline calculation
      if (($rec->{itfarm}=~m/^NGSSM-Farm_x86/i)){
         if ($rec->{productline} ne "NGSSM-Farm_x86"){
            $forcedupd->{productline}="NGSSM-Farm_x86"; 
         }
      }
      elsif (defined($parrec) &&
             $parrec->{systemolaclass} eq "10" &&  # CLASSIC
          ($rec->{itfarm} eq "")){
         if ($rec->{productline} ne "CLASSIC"){
            $forcedupd->{productline}="CLASSIC"; 
         }
      }
      elsif (defined($parrec) &&
             $parrec->{systemolaclass} eq "10" &&  # CLASSIC
          ($rec->{itfarm}=~m/^IT-Serverfarm_AIX/i)){
         if ($rec->{productline} ne "ITSF-AIX"){
            $forcedupd->{productline}="ITSF-AIX"; 
         }
      }
      elsif (defined($parrec) &&
             $parrec->{systemolaclass} eq "10" &&  # CLASSIC
          ($rec->{itfarm}=~m/^IT-Serverfarm_Solaris/i)){
         if ($rec->{productline} ne "ITSF-SOLARIS"){
            $forcedupd->{productline}="ITSF-SOLARIS"; 
         }
      }
      elsif (defined($parrec) &&
             $parrec->{systemolaclass} eq "10" &&  # CLASSIC
          ($rec->{itfarm}=~m/^IT-Serverfarm_SAP_HANA/i)){
         if ($rec->{productline} ne "SAP-HANA"){
            $forcedupd->{productline}="SAP-HANA"; 
         }
      }
      elsif (defined($parrec) &&
             $parrec->{systemolaclass} eq "38" &&  # DCS
          ($rec->{itfarm}=~m/^IT-Serverfarm_X86/i)){
         if ($rec->{productline} ne "ITSF-x86"){
            $forcedupd->{productline}="ITSF-x86"; 
         }
      }
      elsif (defined($parrec) &&
             $parrec->{systemolaclass} eq "0" &&  # UNDEFINED
          ($rec->{itfarm}=~m/^IT-Serverfarm_DBaaS/i)){
         if ($rec->{productline} ne "DBaaS"){
            $forcedupd->{productline}="DBaaS"; 
         }
      }
      elsif (defined($parrec) &&
             $parrec->{systemolaclass} eq "30"   # APPCOM
             ){
         if ($rec->{productline} ne "APPCOM"){
            $forcedupd->{productline}="APPCOM"; 
         }
      }
      else{
         if ($rec->{productline} ne ""){
            $forcedupd->{productline}=undef; 
         }
      }
      if ($rec->{srcid} ne "" && $rec->{srcsys} eq "AssetManager"){
         if (!defined($parrec)){
            push(@qmsg,'given systemid not found as active in AssetManager');
            push(@dataissue,'given systemid not found as active in AssetManager');
            $errorlevel=3 if ($errorlevel<3);
         }
         else{
            if ($rec->{srcsys} eq "AssetManager"){
               #
               # osrelease mapping
               #
               if (!($parrec->{systemos}=~/^\s*$/)){
                  my $mapos=$dataobj->ModuleObject("tsacinv::lnkw5bosrelease");
                  $mapos->SetFilter({extosrelease=>\$parrec->{systemos}});
                  my ($maposrec,$msg)=$mapos->getOnlyFirst(qw(ALL));
                  if (defined($maposrec)){
                     if ($maposrec->{w5bosrelease} ne ""){
                        $parrec->{systemos}=$maposrec->{w5bosrelease};
                     }
                     else{  # try automatic map update
                        my $os=$dataobj->ModuleObject("itil::osrelease");
                        my $osname=$parrec->{systemos};
                        $osname=~s/"//g;
                        $osname='"'.$osname.'"';
                        $os->SetFilter({name=>$osname,cistatusid=>4});
                        my ($osrec,$msg)=$os->getOnlyFirst(qw(ALL));
                        if (defined($osrec)){
                           msg(INFO,"auto update tsacinv::lnkw5bosrelease");
                           $mapos->ValidatedUpdateRecord($maposrec,
                                   {w5bosrelease=>$osrec->{name}},
                                   {id=>\$maposrec->{id}});
                        }
                     }
                  }
                  else{
                     my %new=(extosrelease=>$parrec->{systemos},direction=>1);
                     # try to find an already existing name in W5Base
                     my $os=$dataobj->ModuleObject("itil::osrelease");
                     $os->SetFilter({name=>'"'.$parrec->{systemos}.'"'});
                     my ($w5osrec,$msg)=$mapos->getOnlyFirst(qw(name));
                     if (defined($w5osrec)){
                        $new{w5bosrelease}=$w5osrec->{name};
                     }
                     $mapos->ValidatedInsertRecord(\%new);
                  }
               }
               #################################################################### 
               # assetid compare 
               if (!in_array($dataobj->needVMHost(),$rec->{systemtype})){
                  my $assetid=$parrec->{assetassetid};
                  # special handling to detect the correct AssetID for a
                  # system. Because posible wrong informations for ESX vm's,
                  # it is needed to query eCMDB (ADOP-T)
                  if ($parrec->{systemid} ne ""){
                     my $vsys=$dataobj->getPersistentModuleObject(
                               'tsadopt::vsys');
                     $vsys->SetFilter({
                        systemid=>$parrec->{systemid}
                     });
                     my ($vsysrec,$msg)=$vsys->getOnlyFirst(qw(id name 
                                                               assetid));
                     if (!$vsys->Ping()){
                        return(undef,{qmsg=>"ADOP-T not available - ".
                                     "assetid is not detectable"});
                     }
                     if ($vsysrec->{assetid} ne ""){
                        my $msg=$self->T('substituted assetid for %s '.
                                       'from %s to %s based on ADOP-T');
                        $msg=sprintf($msg,$parrec->{systemid},
                                          $assetid,$vsysrec->{assetid});
                        push(@qmsg,$msg);
                        $assetid=$vsysrec->{assetid};
                     }
                  }
                  if ($assetid ne ""){
                     my $assetobj=getModuleObject($self->getParent->Config,
                                                  'itil::asset');
                     $assetobj->SetFilter({srcsys=>'AssetManager',
                                           srcid=>$assetid});
                     my @w5asset=$assetobj->getHashList(qw(ALL));
                     my $foundactive;
                     foreach my $a (@w5asset) {
                        if ($a->{cistatusid}==3 || $a->{cistatusid}==4) {
                           $foundactive++;
                        }
                     }

                     if ($#w5asset!=-1 && !$foundactive) {
                        # set asset installed/active before IfComp
                        my $a=$w5asset[0];
                        my $oldcistatus=$a->{cistatusid};
                        
                        $assetobj->ValidatedUpdateRecord($a,
                                           {cistatusid=>4,
                                            databossid=>$rec->{databossid}},
                                           {id=>\$a->{id}}); 
                     }

                     $self->IfComp($dataobj,
                                   $rec,"asset",
                                   {assetassetid=>$assetid},"assetassetid",
                                   $autocorrect,$forcedupd,$wfrequest,
                                   \@qmsg,\@dataissue,\$errorlevel,
                                   mode=>'leftouterlinkcreate',
                                   onCreate=>{
                                      comments=>
                                         "automatically generated by QualityCheck",
                                      cistatusid=>4,
                                      allowifupdate=>1,
                                      databossid=>$rec->{databossid},
                                      mandatorid=>$rec->{mandatorid},
                                      name=>$assetid,
                                      srcsys=>'AssetManager',
                                      srcid=>$assetid});
                  }
               }
               else{  # special VM Host-system handling - vhostsystem needs to sync
                  my $assetid=$parrec->{assetassetid};
                  if ($assetid ne ""){
                     my $sys=$dataobj->ModuleObject("tsacinv::system");
                     $sys->SetFilter({
                        assetassetid=>\$assetid,
                        status=>\'in operation',
                        usage=>['OSY-I: KONSOLSYSTEM HYPERVISOR',
                                'OSY-I: KONSOLSYSTEM VMWARE']
                     });
                     my @l=$sys->getHashList(qw(systemname systemid));
                     if ($#l==-1){
                        $sys->ResetFilter();
                        $sys->SetFilter({
                           assetassetid=>\$assetid,
                           status=>\'in operation',
                           usage=>['OSY-I: KONSOLSYSTEM(BLADE&APPCOM)']
                        });
                        @l=$sys->getHashList(qw(systemname systemid));
                     }
                     if ($#l!=0){
                        my $m='can not find a related VMWARE KONSOLSYSTEM '.
                                'in AssetManager';
                        push(@dataissue,$m);
                        push(@qmsg,$m);
                        $errorlevel=3 if ($errorlevel<3);
                     }
                     else{
                        my $hostsystemsystemid=$l[0]->{systemid};
                        my $o=getModuleObject($self->getParent->Config(),
                                              "itil::system");
                        $o->SetFilter({systemid=>\$hostsystemsystemid});
                        my @h=$o->getHashList(qw(name));
                        if ($#h<0){
                           push(@qmsg,'can not find needed '.
                                      'vm host system in IT-Inventar: '.
                                      $l[0]->{systemname}." ".
                                      'SystemID: '.$l[0]->{systemid});
                           $errorlevel=3 if ($errorlevel<3);
                        }
                        if ($#h==0){
                           $parrec->{vhostsystem}=$h[0]->{name};
                        }
                     }
                  }
                  $self->IfComp($dataobj,
                                $rec,"vhostsystem",
                                $parrec,"vhostsystem",
                                $autocorrect,$forcedupd,$wfrequest,
                                \@qmsg,\@dataissue,\$errorlevel,
                                mode=>'string');
               }
               #################################################################### 

               if (defined($parrec->{systemname})){
                  $parrec->{systemname}=lc($parrec->{systemname});
                  $parrec->{systemname}=~s/\..*$//; # remove posible Domain part 
               }
               my $nameok=1;
               if ($parrec->{systemname} ne $rec->{name} &&
                   ($parrec->{systemname}=~m/\s/)){
                  $nameok=0;
                  my $m='systemname with whitespace in AssetManager - '.
                        'contact oss to fix this!';
                  push(@qmsg,$m);
                  push(@dataissue,$m);
                  $errorlevel=3 if ($errorlevel<3);
               }
               if ($parrec->{systemname}=~m/\.\S{1,3}$/){
                  $parrec->{systemname}=~s/\..*//;
                  my $m='systemname with DNS Domain in AssetManager - '.
                        'contact oss to fix this!';
                  push(@qmsg,$m);
                  push(@dataissue,$m);
                  $errorlevel=3 if ($errorlevel<3);
               }

               if ($parrec->{systemname}=~m/^\s*$/){  # k�nnte notwendig werden!
                  $nameok=0;
                  push(@qmsg,'systemname from AssetManager not useable - '.
                             'contact oss to fix this!');
                  $errorlevel=3 if ($errorlevel<3);
               }
               if ($nameok){
                  $dataobj->ResetFilter();
                  $dataobj->SetFilter({name=>\$parrec->{systemname},
                                       id=>"!".$rec->{id}});
                  my ($chkrec,$msg)=$dataobj->getOnlyFirst(qw(id name));
                  if (defined($chkrec)){
                     $nameok=0;
                     my $m='systemname from AssetManager is already in use '.
                           'by an other system - '.
                           'contact OSS make the systemname unique!';
                     push(@qmsg,$m);
                     push(@dataissue,$m);
                     $errorlevel=3 if ($errorlevel<3);
                  }
               }

               if ($nameok){
                  $self->IfComp($dataobj,
                                $rec,"name",
                                $parrec,"systemname",
                                $autocorrect,$forcedupd,$wfrequest,
                                \@qmsg,\@dataissue,\$errorlevel,
                                mode=>'string');
               }

               $self->IfComp($dataobj,
                             $rec,"servicesupport",
                             $parrec,"systemola",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'leftouterlinkcreate',
                             onCreate=>{
                                comments=>"automatically generated by QualityCheck",
                                cistatusid=>4,
                                name=>$parrec->{systemola}});
               $self->IfComp($dataobj,
                             $rec,"memory",
                             $parrec,"systemmemory",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'integer',tolerance=>5);
               $self->IfComp($dataobj,
                             $rec,"cpucount",
                             $parrec,"systemcpucount",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'integer');


               #
               # Filter for conumbers, which are allowed to use in darwin
               #
               if (defined($parrec->{conumber})){
                  if ($parrec->{conumber} eq ""){
                     $parrec->{conumber}=undef;
                  }
                  if (defined($parrec->{conumber})){
                     #
                     # hier mu� der Check gegen die SAP P01 rein f�r die 
                     # Umrechnung auf PSP Elemente
                     #
                     if ($parrec->{conumber}=~m/^\S{10}$/){
                        my $sappsp=getModuleObject($self->getParent->Config,
                                                   "tssapp01::psp");
                        my $psp=$sappsp->CO2PSP_Translator($parrec->{conumber});
                        $parrec->{conumber}=$psp if (defined($psp));
                     }

                     ###############################################################
                     my $co=getModuleObject($self->getParent->Config,
                                            "finance::costcenter");
                     if (defined($co)){
                        if (!($co->ValidateCONumber(
                              $dataobj->SelfAsParentObject,"conumber", $parrec,
                              {conumber=>$parrec->{conumber}}))){ # simulierter newrec
                           if ($parrec->{conumber} ne ""){
                              push(@qmsg,"not acceptable CO-Number format: ".
                                         $parrec->{conumber});
                              $parrec->{conumber}=undef;
                           }
                        }
                     }
                     else{
                        $parrec->{conumber}=undef;
                     }
                  }
               }




               $self->IfComp($dataobj,
                             $rec,"conumber",
                             $parrec,"conumber",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'string');
               $self->IfComp($dataobj,
                             $rec,"osrelease",
                             $parrec,"systemos",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'leftouterlinkbaselogged');
               if ($dataobj->getField("itnormodel")){
                  $self->IfComp($dataobj,
                                $rec,"itnormodel",
                                $parrec,"norsolutionclass",
                                $autocorrect,$forcedupd,$wfrequest,
                                \@qmsg,\@dataissue,\$errorlevel,
                                mode=>'leftouterlink');
               }
               if ($rec->{allowifupdate}){
                  my $net=getModuleObject($self->getParent->Config(),"itil::network");
                  $net->SetCurrentView(qw(id name));
                  my $netarea=$net->getHashIndexed("name");
                  my @opList;

                  #
                  # %cleanAmIPlist is neassasary, because multiple IP-Addresses
                  # can be in one networkcard record
                  #
                  my %cleanAmIPlist;
                  foreach my $amiprec (@{$parrec->{ipaddresses}}){
                     my $mappedCIStatus=5;
                     if (lc($amiprec->{status}) eq "unconfigured"){
                        $mappedCIStatus=6;
                     }
                     if (lc($amiprec->{status}) eq "out of service"){
                        $mappedCIStatus=6;
                     }
                     elsif (lc($amiprec->{status}) eq "configured"){
                        $mappedCIStatus=4;
                     }
                     if ($amiprec->{ipv4address} ne ""){
                        if ($amiprec->{ipv4address}=~
                            m/^\d{1,3}(\.\d{1,3}){3,3}$/){
                           $cleanAmIPlist{$amiprec->{ipv4address}}={
                              cistatusid=>$mappedCIStatus,
                              ipaddress=>$amiprec->{ipv4address},
                              description=>$amiprec->{description}
                           };
                        }
                        else{
                           msg(WARN,"ignoring IPv4 invalid ".
                                    "'$amiprec->{ipv4address}' ".
                                    "for $parrec->{systemid}");
                        }
                     }
                     if ($amiprec->{ipv6address} ne ""){
                        if ($amiprec->{ipv6address}=~
                            m/^[a-f0-9]{1,4}(:[a-f0-9]{0,4}){3,7}$/){
                           $cleanAmIPlist{$amiprec->{ipv6address}}={
                              cistatusid=>$mappedCIStatus,
                              ipaddress=>$amiprec->{ipv6address},
                              description=>$amiprec->{description}
                           };
                        }
                        else{
                           msg(INFO,"ignoring invalid IPv6 ".
                                    "'$amiprec->{ipv6address}' ".
                                    "for $parrec->{systemid}");
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
                                   $eq=1 if ($a->{comments} eq $b->{description} &&
                                             $a->{srcsys} eq "AMCDS" &&
                                             $a->{cistatusid} eq $b->{cistatusid});
                                }
                                return($eq);
                             },
                             sub{  # oprec generator
                                my ($mode,$oldrec,$newrec,%p)=@_;
                                if ($mode eq "insert" || $mode eq "update"){
                                   if ($mode eq "insert" && $newrec->{cistatusid} eq "6"){
                                      return(); # do not insert already unconfigured ip's
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
                                   # exists in AssetManager Rotz.
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
                                              srcsys    =>'AMCDS',
                                              type      =>$type,
                                              networkid =>$networkid,
                                              comments  =>$newrec->{description},
                                              systemid  =>$p{refid}
                                              }
                                           });
                                }
                                elsif ($mode eq "delete"){
                                   my $networkid=$oldrec->{networkid};
                                   if ($networkid ne $p{netarea}->{name}->
                                             {'Insel-Netz/Kunden-LAN'}->{id}){
                                      my $msg=$self->T('can not automatic '.
                                                       'delete ip %s '.
                                                       'because network area '.
                                                       'has been changed');
                                      $msg=sprintf($msg,$oldrec->{name});
   
                                      push(@qmsg,$msg);
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

            if ($rec->{mandator} eq "Extern" && $rec->{allowifupdate}){
               # forced updates on External Data
               my $admid;
               my $acgroup=getModuleObject($self->getParent->Config,"tsacinv::group");
               $acgroup->SetFilter({lgroupid=>\$parrec->{lassignmentid}});
               my ($acgrouprec,$msg)=$acgroup->getOnlyFirst(qw(supervisorldapid));
               if (defined($acgrouprec)){
                  if ($acgrouprec->{supervisorldapid} ne "" ||
                      $acgrouprec->{supervisoremail} ne ""){
                     my $importname=$acgrouprec->{supervisorldapid};
                     if ($importname eq ""){
                        $importname=$acgrouprec->{supervisoremail};
                     }
                     my $user=getModuleObject($self->getParent->Config,
                                               "base::user");
                     my $databossid=$user->GetW5BaseUserID($importname,"posix",
                                                           {quiet=>1});
                     if (defined($databossid)){
                        $admid=$databossid;
                     }
                  }
               }
               if ($admid ne ""){
                  $self->IfComp($dataobj,
                                $rec,"admid",
                                {admid=>$admid},"admid",
                                $autocorrect,$forcedupd,$wfrequest,
                                \@qmsg,\@dataissue,\$errorlevel,
                                mode=>'integer');
               }
               my $comments="";
               if ($parrec->{assignmentgroup} ne ""){
                  $comments.="\n" if ($comments ne "");
                  $comments.="AssetManager AssignmentGroup: ".
                             $parrec->{assignmentgroup};
               }
               if ($parrec->{conumber} ne ""){
                  $comments.="\n" if ($comments ne "");
                  $comments.="AssetManager CO-Number: ".
                             $parrec->{conumber};
               }
               $self->IfComp($dataobj,
                             $rec,"comments",
                             {comments=>$comments},"comments",
                             $autocorrect,$forcedupd,$wfrequest,
                             \@qmsg,\@dataissue,\$errorlevel,
                             mode=>'string');
            }
         }
         if ($rec->{asset} ne ""){
            my $par=getModuleObject($self->getParent->Config(),"tsacinv::asset");
            $par->SetFilter({assetid=>\$rec->{asset}});
            my ($parrec,$msg)=$par->getOnlyFirst(qw(ALL));
            if (!defined($parrec)){
               push(@qmsg,'given assetid not found as active in AssetManager');
               $errorlevel=3 if ($errorlevel<3);
            }
         }
         else{
            if ($#qmsg==-1 && keys(%$forcedupd)==0){ # this makes only sense, if
               push(@qmsg,'no assetid specified');  # this rule have no other 
               push(@dataissue,'no assetid specified'); # error messages and there
               $errorlevel=3 if ($errorlevel<3);    # are no updates in the pipe
            }
         }
      }
      #else{
      #   push(@qmsg,'no systemid specified');
      #   if (!($rec->{isworkstation})){
      #      push(@dataissue,'no systemid specified');
      #      $errorlevel=3 if ($errorlevel<3);
      #   }
      #}
   }

   if (keys(%$forcedupd)){
      if (keys(%$forcedupd)==1 && exists($forcedupd->{srcload})){
         $forcedupd->{mdate}=$rec->{mdate};  # do not change mdate
      }
      if ($dataobj->ValidatedUpdateRecord($rec,$forcedupd,{id=>\$rec->{id}})){
         my @fld=grep(!/^(srcload|mdate)$/,keys(%$forcedupd));
         if ($#fld!=-1){
            push(@qmsg,"all desired fields has been updated: ".join(", ",@fld));
            $checksession->{EssentialsChangedCnt}++;
            map({$checksession->{EssentialsChanged}->{$_}++} @fld);
         }
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
