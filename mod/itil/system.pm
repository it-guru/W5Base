package itil::system;
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
use kernel::App::Web;
use kernel::DataObj::DB;
use kernel::App::Web::InterviewLink;
use kernel::Field;
use kernel::CIStatusTools;
use finance::costcenter;
use itil::lib::Listedit;
use itil::appl;
@ISA=qw(kernel::App::Web::Listedit kernel::DataObj::DB 
        kernel::App::Web::InterviewLink
        kernel::CIStatusTools);

sub new
{
   my $type=shift;
   my %param=@_;
   $param{MainSearchFieldLines}=4;
   my $self=bless($type->SUPER::new(%param),$type);

   my $vmifexp="if (".join(' or ',
                map({"system.systemtype='$_'"} @{$self->needVMHost()}));
   if ($#{$self->needVMHost()}==-1){
      $vmifexp="if (0";
   }


   $self->AddFields(
      new kernel::Field::Linenumber(
                name          =>'linenumber',
                label         =>'No.'),

      new kernel::Field::Id(
                name          =>'id',
                sqlorder      =>'desc',
                searchable    =>0,
                label         =>'W5BaseID',
                group         =>'source',
                dataobjattr   =>'system.id'),

      new kernel::Field::RecordUrl(),
                                                  
      new kernel::Field::Text(
                name          =>'name',
                label         =>'Name',
                dataobjattr   =>'system.name'),

      new kernel::Field::Interface(
                name          =>'fullname',
                label         =>'Fullname',
                readonly      =>1,
                dataobjattr   =>"concat(system.name,".
                                "if (system.shortdesc<>'',concat(' - ',".
                                "system.shortdesc),''))"),

      new kernel::Field::Link(
                name          =>'signedfiletransfername',
                label         =>'sigend file transfer name',
                dataobjattr   =>'system.name'),

      new kernel::Field::Mandator(),

      new kernel::Field::Link(
                name          =>'mandatorid',
                dataobjattr   =>'system.mandator'),

      new kernel::Field::Select(
                name          =>'cistatus',
                htmleditwidth =>'40%',
                label         =>'CI-State',
                vjoineditbase =>{id=>">0 AND <7"},
                vjointo       =>'base::cistatus',
                vjoinon       =>['cistatusid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Interface(
                name          =>'cistatusid',
                label         =>'CI-StateID',
                dataobjattr   =>'system.cistatus'),

      new kernel::Field::Text(
                name          =>'systemid',
                label         =>'SystemID',
                readonly     =>sub{
                   my $self=shift;
                   if ($self->getParent->IsMemberOf("admin")){
                      return(0);
                   }
                   return(1);
                },
                dataobjattr   =>'system.systemid'),

      new kernel::Field::Text(
                name          =>'shortdesc',
                label         =>'Short Description',
                dataobjattr   =>'system.shortdesc'),

      new kernel::Field::Databoss(),

      new kernel::Field::Link(
                name          =>'databossid',
                dataobjattr   =>'system.databoss'),

      new kernel::Field::SubList(
                name          =>'applications',
                label         =>'Applications',
                group         =>'applications',
                subeditmsk    =>'subedit.appl',
                allowcleanup  =>1,
                forwardSearch =>1,
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['appl','applcistatus','reltyp','fraction'],
                vjoininhash   =>['appl','applcistatusid','mandatorid',
                                 'applid']),

      new kernel::Field::Text(
                name          =>'applicationnames',
                label         =>'Applicationnames',
                group         =>'applications',
                htmldetail    =>0,
                readonly      =>1,
                searchable    =>0,
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['appl']),

      new kernel::Field::Text(
                name          =>'tsmemails',
                label         =>'Technical Solution Manager E-Mails',
                group         =>'applications',
                htmldetail    =>0,
                readonly      =>1,
                searchable    =>0,
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['tsmemail']),


      new kernel::Field::Text(
                name          =>'customer',
                label         =>'all Customers',
                group         =>'customer',
                depend        =>['applications'],
                searchable    =>0,
                readonly      =>1,
                htmldetail    =>0,
                onRawValue    =>sub{
                   my $self=shift;
                   my $current=shift;
                   my $fo=$self->getParent->getField("applications");
                   my $f=$fo->RawValue($current);
                   my @aid=();
                   my %customer;
                   if (ref($f) eq "ARRAY"){
                      foreach my $a (@{$f}){
                         push(@aid,$a->{applid});
                      }
                   }
                   if ($#aid!=-1){
                      my $appl=getModuleObject($self->getParent->Config,
                                               "itil::appl");
                      $appl->SetFilter({id=>\@aid,cistatusid=>"<5"});
                      foreach my $arec ($appl->getHashList(qw(customer))){
                         if ($arec->{customer} ne ""){
                            $customer{$arec->{customer}}++;
                         }
                      } 
                      my $cont=getModuleObject($self->getParent->Config,
                                               "itil::custcontract");
                      $cont->SetFilter({applicationids=>\@aid,
                                        cistatusid=>"<5"});
                      foreach my $arec ($cont->getHashList(qw(customer))){
                         if ($arec->{customer} ne ""){
                            $customer{$arec->{customer}}++;
                         }
                      } 
                   }
                   return([keys(%customer)]);
                }),

      new kernel::Field::SubList(
                name          =>'applcustomers',
                label         =>'Application Customers',
                htmlwidth     =>'200px',
                group         =>'customer',
                searchable    =>1,
                readonly      =>1,
                htmldetail    =>0,
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=5",
                                  systemcistatusid=>"<=5"}],
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['applcustomer','appl']),

      new kernel::Field::Text(
                name          =>'custcontract',
                label         =>'Customer Contract',
                group         =>'customer',
                depend        =>['applications'],
                searchable    =>0,
                readonly      =>1,
                htmldetail    =>0,
                onRawValue    =>sub{
                   my $self=shift;
                   my $current=shift;
                   my $fo=$self->getParent->getField("applications");
                   my $f=$fo->RawValue($current);
                   my @aid=();
                   my %customer;
                   if (ref($f) eq "ARRAY"){
                      foreach my $a (@{$f}){
                         push(@aid,$a->{applid});
                      }
                   }
                   if ($#aid!=-1){
                      my $cont=getModuleObject($self->getParent->Config,
                                               "itil::custcontract");
                      $cont->SetFilter({applicationids=>\@aid,
                                        cistatusid=>"<5"});
                      foreach my $arec ($cont->getHashList(qw(name))){
                         if ($arec->{name} ne ""){
                            $customer{$arec->{name}}++;
                         }
                      } 
                   }
                   return([keys(%customer)]);
                }),

      new kernel::Field::SubList(
                name          =>'software',
                label         =>'Software',
                group         =>'software',
                subeditmsk    =>'subedit.system',
                allowcleanup  =>1,
                forwardSearch =>1,
                vjointo       =>'itil::lnksoftwaresystem',
                vjoinon       =>['id'=>'systemid'],
                vjoinbase     =>{softwarecistatusid=>"<=6"},
                vjoindisp     =>['software','version','quantity','comments'],
                vjoininhash   =>['softwarecistatusid','liccontractcistatusid',
                                 'liccontractid','id',
                                 'software','version','quantity','softwareid']),

      new kernel::Field::SubList(
                name          =>'swinstances',
                label         =>'Software instances',
                group         =>'swinstances',
                vjointo       =>'itil::swinstance',
                vjoinbase     =>[{cistatusid=>"<=5"}],
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['fullname','swnature'],
                vjoininhash   =>['fullname','swnature',
                                 'softwareinstname',
                                 'techproductstring',
                                 'techrelstring']),

      new kernel::Field::Contact(
                name          =>'adm',
                AllowEmpty    =>1,
                group         =>'admin',
                label         =>'Administrator',
                vjoinon       =>['admid'=>'userid']),

      new kernel::Field::Link(
                name          =>'admid',
                dataobjattr   =>'system.adm'),

      new kernel::Field::TextDrop(
                name          =>'admemail',
                group         =>'admin',
                label         =>'Administrator E-Mail',
                vjointo       =>'base::user',
                htmldetail    =>0,
                readonly      =>1,
                vjoinon       =>['admid'=>'userid'],
                vjoindisp     =>'email'),

      new kernel::Field::TextDrop(
                name          =>'vhostsystem',
                group         =>'vhost',
                label         =>'Host system (parent of virtual system)',
                AllowEmpty    =>1,
                vjointo       =>'itil::system',
                vjoineditbase =>{'cistatusid'=>"<=5",
                                 'systemtype'=>['standard','',undef]},
                vjoinon       =>['vhostsystemid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Link(
                name          =>'vhostsystemid',
                dataobjattr   =>'system.vhostsystem'),

      new kernel::Field::TextDrop(
                name          =>'asset',
                group         =>'physys',
                label         =>'Asset-Name',
                AllowEmpty    =>1,
                htmldetail    =>0,
                vjointo       =>'itil::asset',
                vjoineditbase =>{'cistatusid'=>"<=5"},
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::TextDrop(
                name          =>'assetfullname',
                group         =>'physys',
                label         =>'Asset',
                AllowEmpty    =>1,
                vjointo       =>'itil::asset',
                vjoineditbase =>{'cistatusid'=>"<=5"},
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Text(
                name          =>'assetserialno',
                readonly      =>1,
                weblinkto     =>'none',
                translation   =>'itil::asset',
                label         =>'Serialnumber',
                group         =>'physys',
                vjointo       =>'itil::asset',
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'serialno'),

      new kernel::Field::TextDrop(
                name          =>'location',
                depend        =>['assetid'],
                readonly      =>1,
                group         =>'location',
                label         =>'Location',
                vjointo       =>'base::location',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['locationid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Text(
                name          =>'assetroom',
                readonly      =>1,
                weblinkto     =>'none',
                label         =>'Room',
                group         =>'location',
                vjointo       =>'itil::asset',
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'room'),

      new kernel::Field::Text(
                name          =>'assetplace',
                readonly      =>1,
                weblinkto     =>'none',
                label         =>'Place',
                group         =>'location',
                vjointo       =>'itil::asset',
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'place'),

      new kernel::Field::Text(
                name          =>'assetrack',
                readonly      =>1,
                weblinkto     =>'none',
                label         =>'Rack',
                group         =>'location',
                vjointo       =>'itil::asset',
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'rack'),

      new kernel::Field::Contact(
                name          =>'adm2',
                AllowEmpty    =>1,
                group         =>'admin',
                label         =>'Deputy Administrator',
                vjoinon       =>['adm2id'=>'userid']),

      new kernel::Field::Link(
                name          =>'adm2id',
                dataobjattr   =>'system.adm2'),

      new kernel::Field::TextDrop(
                name          =>'adm2email',
                group         =>'admin',
                label         =>'Deputy Administrator E-Mail',
                searchable    =>0,
                vjointo       =>'base::user',
                htmldetail    =>0,
                readonly      =>1,
                vjoinon       =>['adm2id'=>'userid'],
                vjoindisp     =>'email'),

      new kernel::Field::TextDrop(
                name          =>'adminteam',
                htmlwidth     =>'300px',
                group         =>'admin',
                label         =>'Administrationteam',
                vjointo       =>'base::grp',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['adminteamid'=>'grpid'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Link(
                name          =>'adminteamid',
                dataobjattr   =>'system.admteam'),

      new kernel::Field::Text(
                name          =>'adminteambossid',
                group         =>'admin',
                label         =>'Admin Team Boss ID',
                onRawValue    =>\&getTeamBossID,
                searchable    =>0,
                readonly      =>1,
                uivisible     =>0,
                depend        =>['adminteamid']),

      new kernel::Field::Text(
                name          =>'adminteamboss',
                group         =>'admin',
                label         =>'Admin Team Boss',
                onRawValue    =>\&getTeamBoss,
                searchable    =>0,
                htmldetail    =>0,
                readonly      =>1,
                depend        =>['adminteambossid']),

      new kernel::Field::Text(
                name          =>'adminteambossemail',
                searchable    =>0,
                group         =>'admin',
                label         =>'Admin Team Boss EMail',
                onRawValue    =>\&getTeamBossEMail,
                htmldetail    =>0,
                readonly      =>1,
                depend        =>['adminteambossid']),

      new kernel::Field::Select(
                name          =>'osrelease',
                group         =>'logsys',
                htmleditwidth =>'80%',
                label         =>'OS-Release',
                vjointo       =>'itil::osrelease',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['osreleaseid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Interface(
                name          =>'osreleaseid',
                label         =>'OSReleaseID',
                dataobjattr   =>'system.osrelease'),

      new kernel::Field::Select(
                name          =>'osclass',
                group         =>'logsys',
                label         =>'OS-Class',
                readonly      =>1,
                htmldetail    =>0,
                vjointo       =>'itil::osrelease',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['osreleaseid'=>'id'],
                vjoindisp     =>'osclass'),

      new kernel::Field::Select(
                name          =>'systemtype',
                default       =>'standard',
                htmleditwidth =>'40%',
                selectfix     =>1,
                readonly      =>sub{
                   my $self=shift;
                   my $rec=shift;
                   if (defined($rec)){
                      my $systemtype=$rec->{"systemtype"};
                      if ($systemtype eq "abstract"){
                         return(1);
                      }
                   }
                   return(0);
                },
                label         =>'logical system type',
                value         =>['standard',
                                 'vmware',
                                 'Xen',
                                 'vPartition',
                                 'nPartition',
                                 'IntegrityVM',
                                 'gZone',                # solaris
                                 'lZone',                # solaris
                                 'LDomain',              # sun logische Domain
                                 'HDomain',              # sun hardware Domain
                                 'lpar',                 # z/os
                                 'abstract'
                                 ],
                dataobjattr   =>'system.systemtype'),

      new kernel::Field::Number(
                name          =>'cpucount',
                group         =>'logsys',
                editrange     =>[1,4096],
                label         =>'CPU-Count',
                dataobjattr   =>'system.cpucount'),

      new kernel::Field::Number(
                name          =>'relphysicalcpucount',
                searchable    =>0,
                precision     =>2,
                htmldetail    =>0,
                readonly      =>1,
                depend        =>['cpucount','assetid','hwcpucount'],
                group         =>'logsys',
                label         =>'relative phys. CPU-Count',
                onRawValue    =>\&calcPhyCpuCount),

      new kernel::Field::Number(
                name          =>'memory',
                group         =>'logsys',
                label         =>'Memory',
                unit          =>'MB',
                editrange     =>[1,2147483647],
                dataobjattr   =>'system.memory'),

      new kernel::Field::Text(
                name          =>'hostid',
                htmldetail    =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   if (defined($param{current})){
                      my $osobj=$self->getParent->getField("osrelease");
                      my $os=$osobj->RawValue($param{current});
                      return(1) if ($os=~m/^solaris/i);
                   }
                   return(0);
                },
                depend        =>['osrelease','osreleaseid'],
                group         =>'logsys',
                label         =>'HostID',
                dataobjattr   =>'system.hostid'),

      new kernel::Field::Text(
                name          =>'consoleip',
                group         =>'logsys',
                label         =>'Console-IP[:Port]',
                dataobjattr   =>'system.consoleip'),

      new kernel::Field::TextDrop(
                name          =>'servicesupport',
                AllowEmpty    =>1,
                group         =>'monisla',
                label         =>'Service&Support Class',
                vjointo       =>'itil::servicesupport',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['servicesupportid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Link(
                name          =>'servicesupportid',
                dataobjattr   =>'system.servicesupport'),

      new kernel::Field::Select(
                name          =>'monistatus',
                group         =>'monisla',
                label         =>'monitoring status',
                transprefix   =>'monistatus.',
                value         =>['',
                                 'NOMONI',
                                 'MONISIMPLE',
                                 'MONIAUTOIN'],
                htmleditwidth =>'280px',
                dataobjattr   =>'system.monistatus'),

      new kernel::Field::Group(
                name          =>'moniteam',
                group         =>'monisla',
                label         =>'monitoring resonsible Team',
                vjoinon       =>'moniteamid'),

      new kernel::Field::Link(
                name          =>'moniteamid',
                group         =>'monisla',
                label         =>'monitoring resonsible TeamID',
                dataobjattr   =>'system.moniteam'),

      new kernel::Field::Select(
                name          =>'itnormodel',
                label         =>'NOR Model to use',
                group         =>'sec',
                searchable    =>0,
                allowempty    =>1,
                vjoinon       =>['itnormodelid'=>'id'],
                vjointo       =>'itil::itnormodel',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoindisp     =>'name'),

      new kernel::Field::Link(
                name          =>'itnormodelid',
                group         =>'sec',
                label         =>'NORmodelID',
                dataobjattr   =>'system.itnormodel'),

      new kernel::Field::JoinUniqMerge(
                name          =>'issox',
                label         =>'mangaged by rules of SOX',
                group         =>'sec',
                searchable    =>1,
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>'systemissox'),

      new kernel::Field::Select(
                name          =>'nosoxinherit',
                group         =>'sec',
                label         =>'SOX state',
                searchable    =>0,
                transprefix   =>'ApplInherit.',
                htmleditwidth =>'180px',
                value         =>['0','1'],
                translation   =>'itil::appl',
                dataobjattr   =>'system.no_sox_inherit'),


      new kernel::Field::Textarea(
                name          =>'comments',
                group         =>'misc',
                label         =>'Comments',
                searchable    =>0,
                dataobjattr   =>'system.comments'),

      new kernel::Field::Text(
                name          =>'conumber',
                group         =>'misc',
                htmlwidth     =>'100px',
                label         =>'Costcenter',
                weblinkto     =>'itil::costcenter',
                weblinkon     =>['conumber'=>'name'],
                dataobjattr   =>'system.conumber'),

      new kernel::Field::Text(
                name          =>'dsid',
                group         =>'misc',
                label         =>'Directory-Identifier',
                dataobjattr   =>"if (system.dsid is null,".
                                "system.name,system.dsid)",
                wrdataobjattr =>'system.dsid'),

      new kernel::Field::Link(
                name          =>'rawdsid',
                group         =>'misc',
                label         =>'raw Directory-Identifier',
                dataobjattr   =>'system.dsid'),

      new kernel::Field::Text(
                name          =>'kwords',
                group         =>'misc',
                label         =>'Keywords',
                dataobjattr   =>'system.kwords'),

     new kernel::Field::Select(
               name          =>'denyupselect',
               label         =>'it is posible to update/upgrade OS',
               jsonchanged   =>\&itil::lib::Listedit::getupdateDenyHandlingScript,
               jsoninit      =>\&itil::lib::Listedit::getupdateDenyHandlingScript,
               group         =>'upd',
               vjointo       =>'itil::upddeny',
               vjoinon       =>['denyupd'=>'id'],
               vjoineditbase =>{id=>"!99"},   # 99 = sonstige Gr�nde = nicht zul�ssig
               vjoindisp     =>'name'),

     new kernel::Field::Link(
               name          =>'denyupd',
               group         =>'upd',
               default       =>'0',
               label         =>'UpdDenyID',
               dataobjattr   =>'system.denyupd'),

     new kernel::Field::Textarea(
                name          =>'denyupdcomments',
                group         =>'upd',
                label         =>'comments to Update/Upgrade posibilities',
                dataobjattr   =>'system.denyupdcomments'),

     new kernel::Field::Date(
                name          =>'denyupdvalidto',
                group         =>'upd',
                htmldetail    =>sub{
                                   my $self=shift;
                                   my $mode=shift;
                                   my %param=@_;
                                   if (defined($param{current})){
                                      my $d=$param{current}->{$self->{name}};
                                      return(1) if ($d ne "");
                                   }
                                   return(0);
                                },
                label         =>'Update/Upgrade reject valid to',
                dataobjattr   =>'system.denyupdvalidto'),

     new kernel::Field::Htmlarea(
                name          =>'osanalysestate',
                readonly      =>1,
                searchable    =>0,
                htmldetail    =>0,
                htmlwidth     =>'400px',
                group         =>'upd',
                htmlnowrap    =>1,
                label         =>'System OS analysed state',
                onRawValue    =>\&itil::lib::Listedit::calcSoftwareState),
     new kernel::Field::Htmlarea(
                name          =>'osanalysetodo',
                readonly      =>1,
                searchable    =>0,
                group         =>'upd',
                htmlnowrap    =>1,
                htmlwidth     =>'500px',
                htmldetail    =>0,
                htmlnowrap    =>1,
                label         =>'System OS analysed todo',
                onRawValue    =>\&itil::lib::Listedit::calcSoftwareState),

     new kernel::Field::Text(
                name          =>'softwareset',
                readonly      =>1,
                htmldetail    =>0,
                selectsearch  =>sub{
                   my $self=shift;
                   my $ss=getModuleObject($self->getParent->Config,
                                          "itil::softwareset");
                   $ss->SecureSetFilter({cistatusid=>4});
                   my @l=$ss->getVal("name");
                   unshift(@l,"");
                   return(@l);
                },
                searchable    =>1,
                group         =>'softsetvalidation',
                htmlwidth     =>'200px',
                htmlnowrap    =>1,
                label         =>'validate against Software Set',
                onPreProcessFilter=>sub{
                   my $self=shift;
                   my $hflt=shift;
                   if (defined($hflt->{$self->{name}})){
                      my $f=$hflt->{$self->{name}};
                      if (ref($f) ne "ARRAY"){
                         $f=~s/^"(.*)"$/$1/;
                         $f=[$f];
                      }
                      $self->getParent->Context->{FilterSet}={
                         $self->{name}=>$f
                      };
                      delete( $hflt->{$self->{name}})
                   }
                   else{
                      delete($self->getParent->Context->{FilterSet} );
                   }
                   return(0);
                },
                onRawValue    =>sub{
                   my $self=shift;
                   my $FilterSet=$self->getParent->Context->{FilterSet};
                   return($FilterSet->{softwareset});
                }),

      new kernel::Field::FileList(
                name          =>'attachments',
                label         =>'Attachments',
                searchable    =>0,
                parentobj     =>'itil::system',
                group         =>'attachments'),

      new kernel::Field::Interface(
                name          =>'assetid',
                dataobjattr   =>"$vmifexp,vsystem.asset,system.asset)", 
                wrdataobjattr =>"system.asset"),

      new kernel::Field::Link(
                name          =>'locationid',
                vjointo       =>'itil::asset',
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'locationid'),

      new kernel::Field::TextDrop(
                name          =>'itfarm',
                group         =>'physys',
                readonly      =>1,
                htmldetail    =>'NotEmpty',
                label         =>'Serverfarm',
                vjointo       =>'itil::lnkitfarmasset',
                vjoinon       =>['assetid'=>'assetid'],
                vjoindisp     =>'itfarm'),

      new kernel::Field::TextDrop(
                name          =>'hwmodel',
                readonly      =>1,
                weblinkto     =>'none',
                group         =>'physys',
                label         =>'Hardwaremodel',
                vjointo       =>'itil::hwmodel',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['hwmodelid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Link(
                name          =>'hwmodelid',
                vjointo       =>'itil::asset',
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'hwmodelid'),

      new kernel::Field::TextDrop(
                name          =>'hwproducer',
                readonly      =>1,
                searchable    =>0,
                weblinkto     =>'none',
                group         =>'physys',
                label         =>'Producer',
                vjointo       =>'itil::asset',
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'hwproducer'),

      new kernel::Field::Number(
                name          =>'hwcpucount',
                readonly      =>1,
                group         =>'physys',
                label         =>'phys. CPU-Count',
                dataobjattr   =>"$vmifexp,vasset.cpucount,asset.cpucount)"),

      new kernel::Field::Number(
                name          =>'hwcorecount',
                readonly      =>1,
                group         =>'physys',
                label         =>'phys. Core-Count',
                dataobjattr   =>"$vmifexp,vasset.corecount,asset.corecount)"),

      new kernel::Field::Number(
                name          =>'hwmemory',
                readonly      =>1,
                group         =>'physys',
                label         =>'phys. Memory',
                unit          =>'MB',
                dataobjattr   =>"$vmifexp,vasset.memory,asset.memory)"),

      new kernel::Field::Text(
                name          =>'systemhandle',
                readonly      =>1,
                group         =>'physys',
                label         =>'Producer System-Handle',
                dataobjattr   =>"$vmifexp,vasset.systemhandle,asset.systemhandle)"),

      new kernel::Field::Text(
                name          =>'assetservicesupport',
                readonly      =>1,
                group         =>'physys',
                vjointo       =>'itil::servicesupport',
                vjoinon       =>['assetservicesupportid'=>'id'],
                vjoindisp     =>'name',
                label         =>'Producer Service&Support Class'),

      new kernel::Field::Link(
                name          =>'assetservicesupportid',
                dataobjattr   =>'asset.prodmaintlevel'),

      new kernel::Field::Link(
                name          =>'hwmodelid',
                vjointo       =>'itil::asset',
                vjoinon       =>['assetid'=>'id'],
                vjoindisp     =>'hwmodelid'),

      new kernel::Field::Boolean(
                name          =>'isprod',
                group         =>'opmode',
                htmlhalfwidth =>1,
                label         =>'Productionsystem',
                dataobjattr   =>'system.is_prod'),

      new kernel::Field::Boolean(
                name          =>'istest',
                group         =>'opmode',
                htmlhalfwidth =>1,
                label         =>'Testsystem',
                dataobjattr   =>'system.is_test'),

      new kernel::Field::Boolean(
                name          =>'isdevel',
                group         =>'opmode',
                htmlhalfwidth =>1,
                label         =>'Developmentsystem',
                dataobjattr   =>'system.is_devel'),

      new kernel::Field::Boolean(
                name          =>'iseducation',
                group         =>'opmode',
                htmlhalfwidth =>1,
                label         =>'Educationsystem',
                dataobjattr   =>'system.is_education'),

      new kernel::Field::Boolean(
                name          =>'isapprovtest',
                group         =>'opmode',
                htmlhalfwidth =>1,
                label         =>'Approval/Integration System',
                dataobjattr   =>'system.is_approvtest'),

      new kernel::Field::Boolean(
                name          =>'isreference',
                group         =>'opmode',
                htmlhalfwidth =>1,
                label         =>'Referencesystem',
                dataobjattr   =>'system.is_reference'),

      new kernel::Field::Boolean(
                name          =>'isapplserver',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Server/Applicationserver',
                dataobjattr   =>'system.is_applserver'),

      new kernel::Field::Boolean(
                name          =>'isinfrastruct',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Infrastructursystem',
                dataobjattr   =>'system.is_infrastruct'),

      new kernel::Field::Boolean(
                name          =>'isworkstation',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Workstation',
                dataobjattr   =>'system.is_workstation'),

      new kernel::Field::Boolean(
                name          =>'isprinter',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Printer/Printserver',
                dataobjattr   =>'system.is_printer'),

      new kernel::Field::Boolean(
                name          =>'isbackupsrv',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Backupserver',
                dataobjattr   =>'system.is_backupsrv'),

      new kernel::Field::Boolean(
                name          =>'isdatabasesrv',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Databaseserver',
                dataobjattr   =>'system.is_databasesrv'),

      new kernel::Field::Boolean(
                name          =>'iswebserver',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'WEB-Server',
                dataobjattr   =>'system.is_webserver'),

      new kernel::Field::Boolean(
                name          =>'ismailserver',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Mail/Mailrelay-Server',
                dataobjattr   =>'system.is_mailserver'),

      new kernel::Field::Boolean(
                name          =>'isrouter',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Router/Networkrouter',
                dataobjattr   =>'system.is_router'),

      new kernel::Field::Boolean(
                name          =>'isnetswitch',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Switch/Networkswitch',
                dataobjattr   =>'system.is_netswitch'),

      new kernel::Field::Boolean(
                name          =>'isterminalsrv',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Terminalserver',
                dataobjattr   =>'system.is_terminalsrv'),

      new kernel::Field::Boolean(
                name          =>'isnas',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Network Attached Storage NAS',
                dataobjattr   =>'system.is_nas'),

      new kernel::Field::Boolean(
                name          =>'isloadbalacer',
                group         =>'systemclass',
                htmlhalfwidth =>1,
                label         =>'Loadbalancer',
                dataobjattr   =>'system.is_loadbalacer'),

#      new kernel::Field::Boolean(           # vorerst nicht, da die Information
#                name          =>'ishousing',# nicht "absolut" w�re!
#                group         =>'systemclass',
#                label         =>'Housing',
#                dataobjattr   =>'system.is_housing'),

      new kernel::Field::Boolean(
                name          =>'isclusternode',
                selectfix     =>1,
                group         =>'systemclass',
                label         =>'ClusterNode',
                dataobjattr   =>'system.is_clusternode'),

      new kernel::Field::Boolean(
                name          =>'isembedded',
                selectfix     =>1,
                group         =>'systemclass',
                label         =>'Embedded System',
                dataobjattr   =>'system.is_embedded'),

      new kernel::Field::TextDrop(
                name          =>'itclust',
                group         =>'cluster',
                label         =>'Cluster',
                vjointo       =>'itil::itclust',
                vjoineditbase =>{'cistatusid'=>[2,3,4,5]},
                vjoinon       =>['itclustid'=>'id'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Link(
                name          =>'itclustid',
                dataobjattr   =>'system.clusterid'),

      new kernel::Field::SubList(
                name          =>'ipaddresses',
                label         =>'IP-Adresses',
                group         =>'ipaddresses',
                allowcleanup  =>1,
                forwardSearch =>1,
                subeditmsk    =>'subedit.system',
                vjoinbase     =>[{cistatusid=>"<=5"}],
                vjointo       =>'itil::ipaddress',
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['webaddresstyp','name','cistatus',
                                 'dnsname','shortcomments'],
                vjoininhash   =>['id','name','addresstyp',
                                 'cistatusid','networkid',
                                 'dnsname','comments',
                                 'srcsys']),

      new kernel::Field::SubList(
                name          =>'ipaddresseslist',
                label         =>'IP-Adresses list',
                group         =>'ipaddresses',
                htmldetail    =>0,
                subeditmsk    =>'subedit.system',
                vjoinbase     =>[{cistatusid=>\"4"}],
                vjointo       =>'itil::ipaddress',
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['name']),

      new kernel::Field::SubList(
                name          =>'dnsnamelist',
                label         =>'DNS-Name list',
                group         =>'ipaddresses',
                htmldetail    =>0,
                subeditmsk    =>'subedit.system',
                vjoinbase     =>[{cistatusid=>\"4"}],
                vjointo       =>'itil::ipaddress',
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['dnsname']),

      new kernel::Field::Container(
                name          =>'additional',
                label         =>'Additionalinformations',
                htmldetail    =>0,
                uivisible     =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   my $rec=$param{current};
                   if (!defined($rec->{$self->Name()})){
                      return(0);
                   }
                   return(1);
                },
                dataobjattr   =>'system.additional'),

      new kernel::Field::ContactLnk(
                name          =>'contacts',
                label         =>'Contacts',
                vjoinbase     =>[{'parentobj'=>\'itil::system'}],
                vjoininhash   =>['targetid','target','roles'],
                group         =>'contacts'),

      new kernel::Field::SubList(
                name          =>'applicationteams',
                label         =>'Application business teams',
                group         =>'applications',
                htmldetail    =>0,
                searchable    =>1,
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['businessteam']),

      new kernel::Field::PhoneLnk(
                name          =>'phonenumbers',
                label         =>'Phonenumbers',
                group         =>'phonenumbers',
                vjoinbase     =>[{'parentobj'=>\'itil::system'}],
                subeditmsk    =>'subedit'),

      new kernel::Field::Boolean(
                name          =>'allowifupdate',
                group         =>'control',
                label         =>'allow automatic updates by interfaces',
                dataobjattr   =>'system.allowifupdate'),

      new kernel::Field::Text(
                name          =>'ccproxy',
                group         =>'control',
                label         =>'JobServer Proxy Command',
                dataobjattr   =>'system.ccproxy'),

      new kernel::Field::Text(
                name          =>'mon1url',
                group         =>'control',
                htmldetail    =>0,
                label         =>'Monitoring URL1',
                dataobjattr   =>'system.mon1url'),

      new kernel::Field::Text(
                name          =>'mon2url',
                group         =>'control',
                htmldetail    =>0,
                label         =>'Monitoring URL2',
                dataobjattr   =>'system.mon2url'),

      new kernel::Field::Text(
                name          =>'perf1url',
                group         =>'control',
                htmldetail    =>0,
                label         =>'Performance URL1',
                dataobjattr   =>'system.perf1url'),

      new kernel::Field::Text(
                name          =>'perf1date',
                group         =>'control',
                htmldetail    =>0,
                history       =>0,
                label         =>'Performance Date1',
                dataobjattr   =>'system.perf1date'),

      new kernel::Field::Text(
                name          =>'perf2url',
                group         =>'control',
                htmldetail    =>0,
                label         =>'Performance URL2',
                dataobjattr   =>'system.perf2url'),

      new kernel::Field::Text(
                name          =>'srcsys',
                selectfix     =>1,
                group         =>'source',
                label         =>'Source-System',
                dataobjattr   =>'system.srcsys'),
                                                   
      new kernel::Field::Text(
                name          =>'srcid',
                group         =>'source',
                label         =>'Source-Id',
                dataobjattr   =>'system.srcid'),
                                                   
      new kernel::Field::Date(
                name          =>'srcload',
                history       =>0,
                group         =>'source',
                label         =>'Source-Load',
                dataobjattr   =>'system.srcload'),

      new kernel::Field::CDate(
                name          =>'cdate',
                group         =>'source',
                sqlorder      =>'desc',
                label         =>'Creation-Date',
                dataobjattr   =>'system.createdate'),
                                                  
      new kernel::Field::MDate(
                name          =>'mdate',
                group         =>'source',
                sqlorder      =>'desc',
                label         =>'Modification-Date',
                dataobjattr   =>'system.modifydate'),

      new kernel::Field::Creator(
                name          =>'creator',
                group         =>'source',
                label         =>'Creator',
                dataobjattr   =>'system.createuser'),

      new kernel::Field::Owner(
                name          =>'owner',
                group         =>'source',
                label         =>'last Editor',
                dataobjattr   =>'system.modifyuser'),

      new kernel::Field::Editor(
                name          =>'editor',
                group         =>'source',
                label         =>'Editor Account',
                dataobjattr   =>'system.editor'),

      new kernel::Field::RealEditor(
                name          =>'realeditor',
                group         =>'source',
                label         =>'real Editor Account',
                dataobjattr   =>'system.realeditor'),

      new kernel::Field::Interface(
                name          =>'replkeypri',
                group         =>'source',
                label         =>'primary sync key',
                dataobjattr   =>"system.modifydate"),

      new kernel::Field::Interface(
                name          =>'replkeysec',
                group         =>'source',
                label         =>'secondary sync key',
                dataobjattr   =>"lpad(system.id,35,'0')"),

      new kernel::Field::SubList(
                name          =>'customerprio',
                htmldetail    =>0,
                readonly      =>1,
                htmlwidth     =>'400px',
                translation   =>'itil::appl',
                label         =>'Customers Application Prioritiy',
                group         =>'applications',
                subeditmsk    =>'subedit.appl',
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'systemid'],
                vjoindisp     =>['applcustomerprio','appl']),

      new kernel::Field::Link(
                name          =>'sectarget',
                noselect      =>'1',
                dataobjattr   =>'lnkcontact.target'),

      new kernel::Field::Link(
                name          =>'sectargetid',
                noselect      =>'1',
                dataobjattr   =>'lnkcontact.targetid'),

      new kernel::Field::Link(
                name          =>'secroles',
                noselect      =>'1',
                dataobjattr   =>'lnkcontact.croles'),

      new kernel::Field::Link(
                name          =>'secsystemsectarget',
                noselect      =>'1',
                dataobjattr   =>'secsystemlnkcontact.target'),

      new kernel::Field::Link(
                name          =>'secsystemsectargetid',
                noselect      =>'1',
                dataobjattr   =>'secsystemlnkcontact.targetid'),

      new kernel::Field::Link(
                name          =>'secsystemsecroles',
                noselect      =>'1',
                dataobjattr   =>'secsystemlnkcontact.croles'),

      new kernel::Field::Link(
                name          =>'secsystemmandatorid',
                noselect      =>'1',
                dataobjattr   =>'secsystemappl.mandator'),

      new kernel::Field::Link(
                name          =>'secsystembusinessteamid',
                noselect      =>'1',
                dataobjattr   =>'secsystemappl.businessteam'),

      new kernel::Field::Link(
                name          =>'secsystemtsmid',
                noselect      =>'1',
                dataobjattr   =>'secsystemappl.tsm'),

      new kernel::Field::Link(
                name          =>'secsystemtsm2id',
                noselect      =>'1',
                dataobjattr   =>'secsystemappl.tsm2'),

      new kernel::Field::Link(
                name          =>'secsystemopmid',
                noselect      =>'1',
                dataobjattr   =>'secsystemappl.opm'),

      new kernel::Field::Link(
                name          =>'secsystemopm2id',
                noselect      =>'1',
                dataobjattr   =>'secsystemappl.opm2'),


      new kernel::Field::Interview(),
      new kernel::Field::QualityText(),
      new kernel::Field::IssueState(),
      new kernel::Field::QualityState(),
      new kernel::Field::QualityOk(),
      new kernel::Field::QualityLastDate(
                dataobjattr   =>'system.lastqcheck'),
      new kernel::Field::EnrichLastDate(
                dataobjattr   =>'system.lastqenrich'),
   # new kernel::Field::DatacareAssistant()

   );
   $self->{workflowlink}={ workflowkey=>[id=>'affectedsystemid'] };
   $self->{history}={
      delete=>[
         'local'
      ],
      update=>[
         'local'
      ]
   };
   $self->{use_distinct}=1;
   $self->{PhoneLnkUsage}=\&PhoneUsage;
   $self->AddGroup("control",translation=>'itil::system');
   $self->AddGroup("external",translation=>'itil::system');
   $self->setDefaultView(qw(name location cistatus mdate));
   $self->setWorktable("system");
   return($self);
}



sub genIndivAttr
{
   my $self=shift;

   my $context=$self->Context;
   if (!exists($context->{indivAttr})){
      $context->{indivAttr}={};
      if ($W5V2::OperationContext ne "QualityCheck"){
         msg(INFO,"genereat Indiv Attr");
         sleep(1);
         foreach my $indicolid (qw(23124564 
                                   23451 23141234 2134123421 234123 1423214 4523
                                   24123 21341236 76542 1242341 6426543
                                   424123 421341236 476542 41242341 46426543
                                   2341234)){
            my $f=new kernel::Field::Text(
                         name          =>"indicol_$indicolid",
                         label         =>'IP-Count'.$indicolid,
                         group         =>'ipaddresses',
                         htmldetail    =>0,
                         dataobjattr   =>"(select count(*)+$indicolid from ".
                                         "ipaddress where ".
                                         "system.id=ipaddress.system)");
            $self->InitFields($f);
            $context->{indivAttr}->{$f->Name()}=$f;
         }
      }
      else{
      }
   }
   return($context->{indivAttr});
}


sub getFieldList
{
   my $self=shift;
   my $context=shift;

   my @fobjs=$self->SUPER::getFieldList();
   if ($context ne "SearchTemplate"){  
      if ($self->IsMemberOf("admin")){
         my $indivAttr=$self->genIndivAttr();
         push(@fobjs,sort(keys(%$indivAttr)));
      }
   }

   return(@fobjs);
}


sub getField
{
   my $self=shift;
   my $fullfieldname=shift;
   my $deprec=shift;
 
   if (my ($indicolid)=$fullfieldname=~m/^indicol_([0-9]{5,10})$/){
      if ($self->IsMemberOf("admin")){
         my $indivAttr=$self->genIndivAttr();
         if (exists($indivAttr->{$fullfieldname})){
            return($indivAttr->{$fullfieldname});
         }
      }
   }
   return($self->SUPER::getField($fullfieldname,$deprec));
}


sub getTeamBossID
{
   my $self=shift;
   my $current=shift;
   my $teamfieldname=$self->{depend}->[0];
   my $teamfield=$self->getParent->getField($teamfieldname);
   my $teamid=$teamfield->RawValue($current);
   my @teambossid=();
   if ($teamid ne ""){
      my $lnk=getModuleObject($self->getParent->Config,
                              "base::lnkgrpuser");
      $lnk->SetFilter({grpid=>\$teamid,
                       rawnativroles=>'RBoss'});
      foreach my $rec ($lnk->getHashList("userid")){
         if ($rec->{userid} ne ""){
            push(@teambossid,$rec->{userid});
         }
      }
   }
   return(\@teambossid);
}

sub getTeamBossEMail
{
   my $self=shift;
   my $current=shift;
   my $teambossfieldname=$self->{depend}->[0];
   my $teambossfield=$self->getParent->getField($teambossfieldname);
   my $teambossid=$teambossfield->RawValue($current);
   my @teamboss;
   if ($teambossid ne "" && ref($teambossid) eq "ARRAY" && $#{$teambossid}>-1){
      my $user=getModuleObject($self->getParent->Config,"base::user");
      $user->SetFilter({userid=>$teambossid});
      foreach my $rec ($user->getHashList("email")){
         if ($rec->{email} ne ""){
            push(@teamboss,$rec->{email});
         }
      }
   }
   return(\@teamboss);
}



sub calcPhyCpuCount   #calculates the relative physical cpucount
{
   my $self=shift;
   my $current=shift;

   my $assetid=$current->{assetid};

   my $sys=getModuleObject($self->getParent->Config,"itil::system");
   $sys->SetFilter({assetid=>\$assetid,cistatusid=>[qw(3 4 5)]});
   my $syscount;
   my $syscpucount;
   foreach my $subsysrec ($sys->getHashList(qw(cpucount))){
      $syscount++;
      $syscpucount+=$subsysrec->{cpucount};
   }
   if ($syscount==1){
      return($current->{hwcpucount});
   }
   else{
      my $lcpucount=$current->{cpucount};
      if ($current->{hwcpucount}>0 && $syscpucount>0 && $lcpucount>0){
         return($current->{hwcpucount}/$syscpucount*$lcpucount); 
      }
      return(undef);
   }  
   return(undef);
}


sub PhoneUsage
{
   my $self=shift;
   return('phoneRB',$self->T("phoneRB","itil::appl"));
}



sub getTeamBoss
{  
   my $self=shift;
   my $current=shift;
   my $teambossfieldname=$self->{depend}->[0];
   my $teambossfield=$self->getParent->getField($teambossfieldname);
   my $teambossid=$teambossfield->RawValue($current);
   my @teamboss;
   if ($teambossid ne "" && ref($teambossid) eq "ARRAY" && $#{$teambossid}>-1){
      my $user=getModuleObject($self->getParent->Config,"base::user");
      $user->SetFilter({userid=>$teambossid});
      foreach my $rec ($user->getHashList("fullname")){
         if ($rec->{fullname} ne ""){
            push(@teamboss,$rec->{fullname});
         }
      }
   }
   return(\@teamboss);
}


sub getRecordImageUrl
{
   my $self=shift;
   my $cgi=new CGI({HTTP_ACCEPT_LANGUAGE=>$ENV{HTTP_ACCEPT_LANGUAGE}});
   return("../../../public/itil/load/system.jpg?".$cgi->query_string());
}

sub initSearchQuery
{
   my $self=shift;
   if (!defined(Query->Param("search_cistatus"))){
     Query->Param("search_cistatus"=>
                  "\"!".$self->T("CI-Status(6)","base::cistatus")."\"");
   }
}

sub getFieldObjsByView
{
   my $self=shift;
   my $view=shift;
   my %param=@_;

   my @l=$self->SUPER::getFieldObjsByView($view,%param);

   #
   # hack to prevent display of "itnormodel" in outputs other then
   # Standard-Detail
   #
   if (defined($param{current}) && exists($param{current}->{itnormodel})){
      if ($param{output} ne "kernel::Output::HtmlDetail"){
         if (!$self->IsMemberOf("admin") &&
             !$self->IsMemberOf("w5base.itil.system.securityread")){
            @l=grep({$_->{name} ne "itnormodel"} @l);
         }
      }
   }
   return(@l);
}




sub SecureSetFilter
{
   my $self=shift;
   my @flt=@_;

   if (!$self->IsMemberOf([qw(admin w5base.itil.system.read w5base.itil.read)],
                          "RMember")){
      my @mandators=$self->getMandatorsOf($ENV{REMOTE_USER},"read");
      my %grps=$self->getGroupsOf($ENV{REMOTE_USER},
               [orgRoles(),qw(RMember RCFManager RCFManager2 RAuditor RMonitor)],
               "both");
      my @grpids=keys(%grps);
      my $userid=$self->getCurrentUserId();

      my @addflt=(
                 {sectargetid=>\$userid,sectarget=>\'base::user',
                  secroles=>"*roles=?write?=roles* *roles=?privread?=roles* ".
                            "*roles=?read?=roles*"},
                 {sectargetid=>\@grpids,sectarget=>\'base::grp',
                  secroles=>"*roles=?write?=roles* *roles=?privread?=roles* ".
                            "*roles=?read?=roles*"}
                );
      if ($ENV{REMOTE_USER} ne "anonymous"){
         push(@addflt,
                    {mandatorid=>\@mandators},
                    {databossid=>\$userid},
                    {admid=>$userid},       {adm2id=>$userid},
                    {adminteamid=>\@grpids}
                   );
      }
      $self->itil::appl::addApplicationSecureFilter(['secsystem'],\@addflt);

      push(@flt,\@addflt);
   }
   if (!$self->isDirectFilter(@flt)){
      my @addflt=({cistatusid=>"!7"});
      push(@flt,\@addflt);
   }
   return($self->SetFilter(@flt));
}


sub prepareToWasted
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;

   $newrec->{srcsys}=undef;
   $newrec->{srcid}=undef;
   $newrec->{srcload}=undef;
   my $id=effVal($oldrec,$newrec,"id");

   my $o=getModuleObject($self->Config,"itil::lnkapplsystem");
   if (defined($o)){
      $o->BulkDeleteRecord({systemid=>\$id});
   }
   my $o=getModuleObject($self->Config,"itil::lnksoftwaresystem");
   if (defined($o)){
      $o->BulkDeleteRecord({systemid=>\$id});
   }
   my $o=getModuleObject($self->Config,"itil::ipaddress");
   if (defined($o)){
      $o->BulkDeleteRecord({systemid=>\$id});
   }

   return(1);   # if undef, no wasted Transfer is allowed
}


sub jsExploreObjectMethods
{
   my $self=shift;
   my $methods=shift;

   my $label=$self->T("add applications");
   $methods->{'m500addSystemApplications'}="
       label:\"$label\",
       cssicon:\"basket_add\",
       exec:function(){
          console.log(\"call m500addSystemApplications on \",this);
          var dataobjid=this.dataobjid;
          var dataobj=this.dataobj;
          var app=this.app;
          app.Config().then(function(cfg){
             var w5obj=getModuleObject(cfg,dataobj);
             w5obj.SetFilter({
                id:dataobjid
             });
             w5obj.findRecord(\"id,applications\",function(data){
                for(recno=0;recno<data.length;recno++){
                   for(ifno=0;ifno<data[recno].applications.length;ifno++){
                      var ifrec=data[recno].applications[ifno];
                      app.addNode('itil::appl',ifrec.applid,ifrec.appl);
                      app.addEdge(app.toObjKey(dataobj,dataobjid),
                                  app.toObjKey('itil::appl',ifrec.applid),
                                  {noAcross:true});
                   }
                }
                app.processOpStack(function(arrayOfResults){
                   console.log(\"OK, all interfaces loaded arrayOfResults=\",arrayOfResults);
                });

             });
          });
       }
   ";

}



sub Validate
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;

   if (effChangedVal($oldrec,$newrec,"cistatusid")==7){
      $newrec->{systemid}=undef;
      return(1);
   }


   my $name=trim(effVal($oldrec,$newrec,"name"));
   if (length($name)<3 || haveSpecialChar($name) ||
       ($name=~m/^\d+$/)){  # only a number as system name ist not ok
      $self->LastMsg(ERROR,"invalid system name '%s' specified",$name);
      return(0);
   }
   $newrec->{name}=lc($name) if (exists($newrec->{name}) &&
                                 $newrec->{name} ne lc($name));
   my $systemid=trim(effVal($oldrec,$newrec,"systemid"));
   if (exists($newrec->{systemid}) && $newrec->{systemid} ne $systemid){
      $newrec->{systemid}=$systemid; # keine Ahnung, was das Darstellen soll HV
   }
   $newrec->{systemid}=undef if (exists($newrec->{systemid}) &&
                                 $newrec->{systemid} eq "");
   if (defined($newrec->{systemid})){
      if (!($newrec->{systemid}=~m/^[A-Z0-9]+$/)){
         $self->LastMsg(ERROR,"invalid systemid '%s' specified",
                        $newrec->{systemid});
         return(0);
      }
   }

   {
      my $dsid=trim(effVal($oldrec,$newrec,"dsid"));
      my $name=trim(effVal($oldrec,$newrec,"name"));
      if ($dsid eq "" || $dsid eq $name){
         if (defined($oldrec) && $oldrec->{"rawdsid"} ne ""){
            $newrec->{dsid}=undef;
         }
      }
      else{
         if (length($dsid)<3 || haveSpecialChar($dsid) ||
             ($dsid=~m/^\d+$/)){ 
            $self->LastMsg(ERROR,"invalid directory identifier '%s' specified",
                           $dsid);
            return(0);
         }
      }
   }

   my $clusemberror=0;
   if (effChangedVal($oldrec,$newrec,"isembedded")){
      if (effVal($oldrec,$newrec,"isclusternode")){
         $clusemberror=1;
      }
      if (ref($oldrec->{swinstances}) eq "ARRAY" &&
          $#{$oldrec->{swinstances}}!=-1){
         $self->LastMsg(ERROR,
                    "an embedded systems can not have software instances");
         return(0);
      }
      if (ref($oldrec->{software}) eq "ARRAY" &&
          $#{$oldrec->{software}}!=-1){
         $self->LastMsg(ERROR,
                    "an embedded systems can not have software installations");
         return(0);
      }
   }
   if (effChangedVal($oldrec,$newrec,"isclusternode")){
      if (effVal($oldrec,$newrec,"isembedded")){
         $clusemberror=1;
      }
   }
   if ($clusemberror){
      $self->LastMsg(ERROR,"a clusternode can not be an embedded system");
      return(0);
   }


   if (defined($newrec->{asset}) && $newrec->{asset} eq ""){
      $newrec->{asset}=undef;
   }
   if (exists($newrec->{isclusternode})){
      if (effVal($oldrec,$newrec,"isclusternode")!=1){
         $newrec->{itclustid}=undef;
      }
   }
   if (!effVal($oldrec,$newrec,"isclusternode")){
      if (exists($newrec->{itclustid})){
         delete($newrec->{itclust}); # ensure, not itclust is specified
         $newrec->{itclustid}=undef;
      }
   }

   if (exists($newrec->{conumber}) && $newrec->{conumber} ne ""){
      if (!$self->finance::costcenter::ValidateCONumber(
          $self->SelfAsParentObject(),"conumber",
          $oldrec,$newrec)){
         $self->LastMsg(ERROR,
             $self->T("invalid number format '\%s' specified",
                      "finance::costcenter"),$newrec->{conumber});
         return(0);
      }
   }

   ########################################################################
   # standard security handling
   #
   if ($self->isDataInputFromUserFrontend() && !$self->IsMemberOf("admin")){
      my $userid=$self->getCurrentUserId();
      if (!defined($oldrec)){
         if (!defined($newrec->{databossid}) ||
             $newrec->{databossid}==0){
            $newrec->{databossid}=$userid;
         }
      }
      if (!$self->IsMemberOf("admin") &&
          (defined($newrec->{databossid}) &&
           $newrec->{databossid}!=$userid &&
           $newrec->{databossid}!=$oldrec->{databossid})){
         $self->LastMsg(ERROR,"you are not authorized to set other persons ".
                              "as databoss");
         return(0);
      }
   }
   ########################################################################

   if (!$self->itil::lib::Listedit::updateDenyHandling($oldrec,$newrec)){
      return(0);
   }


   return(0) if (!$self->HandleCIStatusModification($oldrec,$newrec,"name"));
   return(1);
}


sub getSqlFrom
{
   my $self=shift;
   my $mode=shift;
   my @flt=@_;
   my ($worktable,$workdb)=$self->getWorktable();
   my $from="$worktable ";

   $from.="left outer join lnkcontact ".
          "on lnkcontact.parentobj='itil::system' ".
          "and $worktable.id=lnkcontact.refid ".
          "left outer join asset on system.asset=asset.id ".
          "left outer join system as vsystem on system.vhostsystem=vsystem.id ".
          "left outer join asset as vasset on vsystem.asset=vasset.id ".

          "left outer join lnkapplsystem as secsystemlnkapplsystem ".
          "on $worktable.id=secsystemlnkapplsystem.system ".
          "left outer join appl as secsystemappl ".
          "on secsystemlnkapplsystem.id=secsystemappl.id and secsystemappl.cistatus<6 ".

          "left outer join lnkcontact secsystemlnkcontact ".
          "on secsystemlnkcontact.parentobj='itil::appl' ".
          "and system.id=secsystemlnkcontact.refid ".

          "left outer join costcenter secsystemcostcenter ".
          "on secsystemappl.conumber=secsystemcostcenter.name ";


   return($from);
}


sub FinishWrite
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;
   my $bak=$self->SUPER::FinishWrite($oldrec,$newrec);
   $self->NotifyOnCIStatusChange($oldrec,$newrec);
   return($bak);
}

sub FinishDelete
{
   my $self=shift;
   my $oldrec=shift;
   my $bak=$self->SUPER::FinishDelete($oldrec);

   my $refobj=getModuleObject($self->Config,"itil::systemnfsnas");
   if (defined($refobj)){
      my $idname=$self->IdField->Name();
      my $id=$oldrec->{$idname};
      $refobj->SetFilter({'systemid'=>\$id});
      $refobj->SetCurrentView(qw(ALL));
      $refobj->ForeachFilteredRecord(sub{
                         $refobj->ValidatedDeleteRecord($_);
                      });
   }


   return($bak);
}


sub SelfAsParentObject    # this method is needed because existing derevations
{
   return("itil::system");
}


sub needVMHost
{
   my $self=shift;

   return([]);
   return(['vmware','vPartition']);
}



sub isViewValid
{
   my $self=shift;
   my $rec=shift;
   return("header","default") if (!defined($rec));
   return(qw(header default)) if (defined($rec) && $rec->{cistatusid}==7);
   my @all=qw(header default swinstances 
              software admin logsys contacts monisla misc opmode 
              physys ipaddresses phonenumbers sec applications
              location source customer history upd
              attachments control systemclass interview qc);
   if (defined($rec) && in_array($self->needVMHost(),$rec->{'systemtype'})){
      push(@all,"vhost");
   }
   if (defined($rec) && $rec->{'systemtype'} eq "abstract"){
      @all=grep(!/^physys$/,@all);
      @all=grep(!/^location$/,@all);
   }
   if (defined($rec) && $rec->{'isclusternode'}){
      push(@all,"cluster");
   }
   if (defined($rec) && $rec->{'isclusternode'}){
      push(@all,"cluster");
   }
   if (defined($rec) && $rec->{'isembedded'}){
      @all=grep(!/^cluster$/,@all);
      @all=grep(!/^attachments$/,@all);
      @all=grep(!/^phonenumbers$/,@all);
      @all=grep(!/^swinstances$/,@all);
      @all=grep(!/^software$/,@all);
   }
   #if ($self->IsMemberOf("admin")){
   #   push(@all,"qc");
   #}
   return(@all);
}

sub isWriteValid
{
   my $self=shift;
   my $rec=shift;
   my $userid=$self->getCurrentUserId();

   my @databossedit=qw(default software admin logsys contacts 
                       monisla misc opmode upd
                       physys ipaddresses phonenumbers sec cluster autodisc
                       attachments control systemclass interview);
   if (defined($rec) && $rec->{'systemtype'} eq "abstract"){
      @databossedit=grep(!/^physys$/,@databossedit);
   }
   if (defined($rec) && in_array($self->needVMHost(),$rec->{'systemtype'})){
      @databossedit=grep(!/^physys$/, @databossedit);
      push(@databossedit,"vhost");
   }
   if (!defined($rec)){
      return("default","physys","admin","monisla","misc","cluster",
             "opmode","control","systemclass","sec");
   }
   else{
      if ($rec->{databossid}==$userid){
         return(@databossedit);
      }
      if ($self->IsMemberOf("admin")){
         return(@databossedit);
      }
      if (defined($rec->{contacts}) && ref($rec->{contacts}) eq "ARRAY"){
         my %grps=$self->getGroupsOf($ENV{REMOTE_USER},
                                     ["RMember"],"both");
         my @grpids=keys(%grps);
         foreach my $contact (@{$rec->{contacts}}){
            if ($contact->{target} eq "base::user" &&
                $contact->{targetid} ne $userid){
               next;
            }
            if ($contact->{target} eq "base::grp"){
               my $grpid=$contact->{targetid};
               next if (!grep(/^$grpid$/,@grpids));
            }
            my @roles=($contact->{roles});
            @roles=@{$contact->{roles}} if (ref($contact->{roles}) eq "ARRAY");
            return(@databossedit) if (grep(/^write$/,@roles));
         }
      }
      if ($rec->{mandatorid}!=0 &&
         $self->IsMemberOf($rec->{mandatorid},["RCFManager","RCFManager2"],
                           "down")){
         return(@databossedit);
      }
      if ($rec->{adminteamid}!=0 &&
         $self->IsMemberOf($rec->{adminteamid},["RCFManager","RCFManager2"],
                           "down")){
         return(@databossedit);
      }
   }
   return(undef);
}


sub getHtmlDetailPages
{
   my $self=shift;
   my ($p,$rec)=@_;

   my @l=$self->SUPER::getHtmlDetailPages($p,$rec);
   if (defined($rec)){
      if ($rec->{perf1url} ne "" ||
          $rec->{perf2url} ne "" ||
          $rec->{perf3url} ne ""){
         push(@l,"PerfDat"=>$self->T("Performance"));
      }
      if ($self->IsMemberOf("w5base.softwaremgmt.read") ||
          $self->isAutoDiscManagementAllowed($rec)){
         my $id=Query->Param("id");
         if ($id ne ""){
            my $ad=getModuleObject($self->Config,'itil::autodiscrec');
            $ad->SetFilter({disc_on_systemid=>\$id,
                            processable=>\'1'});
            if ($ad->CountRecords()>0){
               push(@l,"HtmlAutoDiscManager"=>$self->T("Autodiscovery"));
            }
         }
      }
   }
   return(@l);
}

sub isAutoDiscManagementAllowed
{
   my $self=shift;
   my $rec=shift;

   my @write=$self->isWriteValid($rec);
   if (grep(/^(ALL|default)$/,@write)){
      return(1);
   }
   return(0);
}


sub getHtmlDetailPageContent
{
   my $self=shift;
   my ($p,$rec)=@_;

   my $page;
   my $idname=$self->IdField->Name();
   my $idval=$rec->{$idname};



   if ($p eq "PerfDat"){
      my $perfurl;
      $perfurl=$rec->{perf3url} if ($rec->{perf3url} ne "");
      $perfurl=$rec->{perf2url} if ($rec->{perf2url} ne "");
      $perfurl=$rec->{perf1url} if ($rec->{perf1url} ne "");

      $page.=<<EOF;
<script language="JavaScript" type="text/javascript">
addEvent(window,"load",function(){
   setIFrameUrl();
});
addEvent(window,"resize",function(){
   setIFrameUrl();
});

function setIFrameUrl(){
   var f=document.getElementById("DISP01");
   var w=window.innerWidth-20;
   if (!w){
      w=document.body.clientWidth-25;
   }
   if (w<580){
      w=580;
   }
   f.src="$perfurl&width="+w;
}

</script>
EOF

      $page.="<iframe class=HtmlDetailPage name=HtmlDetailPage id=DISP01 ".
            "src=\"Empty\"></iframe>";
      $page.=$self->HtmlPersistentVariables($idname);
      return($page);
   }

   return($self->SUPER::getHtmlDetailPageContent($p,$rec));
}


sub HtmlAutoDiscManager
{
   my $self=shift;
   my $ad=getModuleObject($self->Config,'itil::autodiscrec');

   my $id=Query->Param("id");
   my $view=Query->Param("view");
   $view="SelUnproc" if ($view eq "");

   print $ad->HtmlAutoDiscManager({view=>$view},[{disc_on_systemid=>\$id}]);
   return(1);
}


sub getDetailBlockPriority
{
   my $self=shift;
   return(
          qw(header default admin phonenumbers logsys location 
             vhost physys systemclass cluster
             opmode sec applications customer software 
             swinstances ipaddresses
             contacts monisla misc upd 
             attachments control source));
}


sub getValidWebFunctions
{
   my ($self)=@_;

   my @l=$self->SUPER::getValidWebFunctions();
   push(@l,"HtmlAutoDiscManager");
   return(@l);
}

sub preQualityCheckRecord
{
   my $self=shift;

   return($self->itil::lib::Listedit::preQualityCheckRecord(@_));
}

sub getHtmlPublicDetailFields
{
   my $self=shift;
   my $rec=shift;

   my @l=qw(mandator name systemid adm adm2 databoss
            adminteam applications);
   return(@l);
}


sub HtmlPublicDetail   # for display record in QuickFinder or with no access
{
   my $self=shift;
   my $rec=shift;
   my $header=shift;   # create a header with fullname or name

   my $htmlresult="";
   if ($header){
      $htmlresult.="<table style='margin:5px'>\n";
      $htmlresult.="<tr><td colspan=2 align=center><h1>";
      $htmlresult.=$self->findtemplvar({current=>$rec,mode=>"Html"},
                                      "name","formated");
      $htmlresult.="</h1></td></tr>";
   }
   else{
      $htmlresult.="<table>\n";
   }
   my @l=$self->getHtmlPublicDetailFields($rec);
   foreach my $v (@l){
      if ($v eq "applications"){
         my $name=$self->getField($v)->Label();
         my $data;
         if (ref($rec->{$v}) eq "ARRAY" &&
             $#{$rec->{$v}}!=-1){
            $data=join("; ",sort(map({$_->{appl}} @{$rec->{$v}})));
            if ($data ne ""){
               $htmlresult.="<tr><td nowrap valign=top width=1%>$name:</td>".
                            "<td valign=top>$data</td></tr>\n";
            }
         }
      }
      elsif ($rec->{$v} ne ""){
         my $name=$self->getField($v)->Label();
         my $data=$self->findtemplvar({current=>$rec,mode=>"Html"},
                                      $v,"formated");
         $htmlresult.="<tr><td nowrap valign=top width=1%>$name:</td>".
                      "<td valign=top>$data</td></tr>\n";
      }
   }

   if (ref($rec->{phonenumbers}) eq "ARRAY" &&
       $#{$rec->{phonenumbers}}!=-1){
      if (my $pn=$self->getField("phonenumbers")){
         $htmlresult.=$pn->FormatForHtmlPublicDetail($rec,["phoneRB"]);
      }
   }
   $htmlresult.="</table>\n";
   return($htmlresult);

}


sub jsExploreFormatLabelMethod
{
   my $self=shift;
   return("newlabel=newlabel.replace(' - ','\\n');");
}








1;
