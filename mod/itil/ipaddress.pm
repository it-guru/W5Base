package itil::ipaddress;
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
use kernel::Field;
use kernel::CIStatusTools;
use itil::lib::Listedit;
@ISA=qw(kernel::App::Web::Listedit itil::lib::Listedit
        kernel::DataObj::DB kernel::CIStatusTools);

sub new
{
   my $type=shift;
   my %param=@_;
   $param{MainSearchFieldLines}=4;
   my $self=bless($type->SUPER::new(%param),$type);

   $self->AddFields(
      new kernel::Field::Linenumber(
                name          =>'linenumber',
                label         =>'No.'),

      new kernel::Field::Id(
                name          =>'id',
                sqlorder      =>'desc',
                label         =>'W5BaseID',
                dataobjattr   =>'ipaddress.id'),

      new kernel::Field::Text(
                name          =>'fullname',
                depend        =>['name'],
                uivisible     =>0,
                label         =>'IP-Address',
                searchable    =>0,
                onRawValue    =>sub{   # compress IPV6 Adresses
                   my $self=shift;
                   my $current=shift;
                   my $d=$current->{name};
                      $d=~s/0000:/0:/g;
                      $d=~s/:0000/:0/g;
                      $d=~s/(:)0+?([a-f1-9])/$1$2/gi;
                      $d=~s/^0+?([a-f1-9])/$1$2/gi;
                      $d=~s/:0:/::/gi;
                      $d=~s/:0:/::/gi;
                      $d=~s/:::::/:0:0:0:0:/gi;
                      $d=~s/::::/:0:0:0:/gi;
                      $d=~s/:::/:0:0:/gi;
                   return($d);
                }),

      new kernel::Field::Text(
                name          =>'name',
                label         =>'IP-Address',
                dataobjattr   =>'ipaddress.name'),

      new kernel::Field::Select(
                name          =>'cistatus',
                htmleditwidth =>'60%',
                label         =>'CI-State',
                vjoineditbase =>{id=>">0 AND <7"},
                vjointo       =>'base::cistatus',
                vjoinon       =>['cistatusid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::TextDrop(
                name          =>'system',
                htmlwidth     =>'150px',
                group         =>'relatedto',
                label         =>'assigned to System',
                uivisible     =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   my $current=$param{current};

                   return(1) if (!defined($current));
                   return(0) if ($current->{systemid} eq "");
                   return(1);
                },
                vjointo       =>'itil::system',
                vjoinon       =>['systemid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Link(
                name          =>'systemid',
                selectfix     =>1,
                label         =>'SystemID',
                group         =>'relatedto',
                dataobjattr   =>'ipaddress.system'),
                                                  
      new kernel::Field::Link(
                name          =>'binnamekey',
                label         =>'Binary IP-Adress',
                group         =>'relatedto',
                dataobjattr   =>'ipaddress.binnamekey'),
                                                  
      new kernel::Field::Boolean(
                name          =>'is_primary',
                label         =>'is primary',
                htmldetail    =>1,
                searchable    =>0,
                group         =>'further',
                dataobjattr   =>'ipaddress.is_primary'),
                                                  
      new kernel::Field::Boolean(
                name          =>'is_notdeleted',
                label         =>'is notdeleted',
                htmldetail    =>1,
                searchable    =>0,
                group         =>'further',
                dataobjattr   =>'ipaddress.is_notdeleted'),
                                                  
      new kernel::Field::TextDrop(
                name          =>'itclustsvc',
                htmlwidth     =>'150px',
                group         =>'relatedto',
                label         =>'assigned to Cluster Service',
                uivisible     =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   my $current=$param{current};

                   return(1) if (!defined($current));
                   return(0) if ($current->{itclustsvcid} eq "");
                   return(1);
                },
                vjointo       =>'itil::lnkitclustsvc',
                vjoinon       =>['itclustsvcid'=>'id'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Link(
                name          =>'itclustsvcid',
                selectfix     =>1,
                label         =>'ClusterserviceID',
                group         =>'relatedto',
                dataobjattr   =>'ipaddress.lnkitclustsvc'),
                                                  
      new kernel::Field::Link(
                name          =>'furthersystemid',
                label         =>'SystemID for further informations',
                group         =>'further',
                dataobjattr   =>'ipaddress.system'
                ),
                                                  
      new kernel::Field::TextDrop(
                name          =>'systemlocation',
                htmlwidth     =>'280px',
                group         =>'further',
                htmldetail    =>0,
                uivisible     =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   my $current=$param{current};

                   return(0) if ($current->{systemid} eq "");
                   return(1);
                },
                label         =>'Systems location',
                vjointo       =>'itil::system',
                vjoinon       =>['furthersystemid'=>'id'],
                vjoindisp     =>'location'),

      new kernel::Field::TextDrop(
                name          =>'systemsystemid',
                htmlwidth     =>'280px',
                group         =>'further',
                htmldetail    =>0,
                readonly      =>1,
                uivisible     =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   my $current=$param{current};

                   return(0) if ($current->{systemid} eq "");
                   return(1);
                },
                label         =>'Systems SystemID',
                vjointo       =>'itil::system',
                vjoinon       =>['furthersystemid'=>'id'],
                vjoindisp     =>'systemid'),

      new kernel::Field::TextDrop(
                name          =>'systemcistatus',
                htmlwidth     =>'280px',
                group         =>'further',
                htmldetail    =>0,
                readonly      =>1,
                uivisible     =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   my $current=$param{current};

                   return(0) if ($current->{systemid} eq "");
                   return(1);
                },
                label         =>'Systems CI-Status',
                vjointo       =>'itil::system',
                vjoinon       =>['furthersystemid'=>'id'],
                vjoindisp     =>'cistatus'),

      new kernel::Field::Text(
                name          =>'applicationnames',
                label         =>'Applicationnames',
                group         =>'further',
                readonly      =>1,
                searchable    =>0,
                weblinkto     =>'NONE',
                vjointo       =>'itil::lnkapplip',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'ipaddressid'],
                vjoindisp     =>['appl']),

      new kernel::Field::SubList(
                name          =>'applications',
                label         =>'Applications',
                group         =>'further',
                htmldetail    =>0,
                readonly      =>1,
                vjointo       =>'itil::lnkapplip',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'ipaddressid'],
                vjoininhash   =>['appl','applid'],
                vjoindisp     =>['appl']),

      new kernel::Field::Text(
                name          =>'applcustomer',
                label         =>'Application Customer',
                readonly      =>1,
                weblinkto     =>'NONE',
                group         =>'further',
                vjointo       =>'itil::lnkapplip',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['id'=>'ipaddressid'],
                vjoindisp     =>'customer'),

      new kernel::Field::Boolean(
                name          =>'ciactive',
                label         =>'relevant CI is alive',
                group         =>'further',
                readonly      =>1,
                htmldetail    =>0,
                searchable    =>sub{
                   my $self=shift;
                   my $app=$self->getParent;
                   return(1) if ($app->IsMemberOf("admin"));
                   return(0);
                },
                dataobjattr   =>'(select '.
                   'if (system.id is not null,if (system.cistatus<6,1,0),'.
                   'if (lnkitclustsvc.id is not null,1,0)) '.
                   ' from ipaddress as ip '.
                   'left outer join system on system.id=ip.system '.
                   'left outer join lnkitclustsvc on '.
                         'lnkitclustsvc.id=ip.lnkitclustsvc '.
                   'where ip.id=ipaddress.id limit 1)'),

      new kernel::Field::Text(
                name          =>'tsmemail',
                label         =>'Systems TSM E-Mail',
                group         =>'further',
                readonly      =>1,
                htmldetail    =>0,
                searchable    =>0,
                uivisible     =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   return(1) if (!exists($param{current}));
                   my $current=$param{current};

                   return(0) if ($current->{systemid} eq "");
                   return(1);
                },
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['furthersystemid'=>'systemid'],
                vjoindisp     =>['tsmemail']),

      new kernel::Field::Text(
                name          =>'class',
                label         =>'classification',
                group         =>'further',
                readonly      =>1,
                htmldetail    =>0,
                dataobjattr   =>'(select '.
                   'concat_ws(",",'.
                   'if (system.is_applserver=1,"\'APPL\'",NULL),'.
                   'if (system.id is null and lnkitclustsvc is not null,'.
                       '"\'CLUSTERPACKAGE\'",NULL),'.
                   'if (system.is_webserver=1,"\'WEBSRV\'",NULL), '.
                   'if (system.is_mailserver=1,"\'MAILSRV\'",NULL), '.
                   'if (system.is_router=1,"\'ROUTER\'",NULL), '.
                   'if (system.is_netswitch=1,"\'NETSWITCH\'",NULL), '.
                   'if (system.is_nas=1,"\'NAS\'",NULL), '.
                   'if (system.is_terminalsrv=1,"\'TS\'",NULL), '.
                   'if (system.is_loadbalacer=1,"\'LOADBALANCER\'",NULL), '.
                   'if (system.is_clusternode=1,"\'CLUSTERNODE\'",NULL), '.
                   'if (system.is_databasesrv=1,"\'DB\'",NULL)) '.
                   ' from ipaddress as ip '.
                   'left outer join system on system.id=ip.system '.
                   'left outer join lnkitclustsvc on '.
                         'lnkitclustsvc.id=ip.lnkitclustsvc '.
                   'where ip.id=ipaddress.id limit 1)'),

      new kernel::Field::Text(
                name          =>'tsm2email',
                label         =>'Systems deputy TSM E-Mail',
                group         =>'further',
                readonly      =>1,
                htmldetail    =>0,
                searchable    =>0,
                uivisible     =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   my $current=$param{current};

                   return(0) if ($current->{systemid} eq "");
                   return(1);
                },
                vjointo       =>'itil::lnkapplsystem',
                vjoinbase     =>[{applcistatusid=>"<=4"}],
                vjoinon       =>['furthersystemid'=>'systemid'],
                vjoindisp     =>['tsm2email']),

      new kernel::Field::Select(
                name          =>'network',
                htmleditwidth =>'280px',
                label         =>'Network',
                vjointo       =>'itil::network',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['networkid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::SubList(
                name          =>'dnsaliases',
                label         =>'DNS-Aliases',
                group         =>'dnsaliases',
                vjointo       =>'itil::dnsalias',
                vjoinon       =>['dnsname'=>'dnsname'],
                vjoinbase     =>{'cistatusid'=>"<=5"},
                vjoindisp     =>['fullname']),

      new kernel::Field::Link(
                name          =>'networkid',
                label         =>'NetworkID',
                dataobjattr   =>'ipaddress.network'),

      new kernel::Field::Link(
                name          =>'uniqueflag',
                label         =>'UniqueFlag',
                dataobjattr   =>'ipaddress.uniqueflag'),
                                                  
      new kernel::Field::Text(
                name          =>'dnsname',
                label         =>'DNS-Name',
                dataobjattr   =>'ipaddress.dnsname'),

      new kernel::Field::Select(
                name          =>'type',
                htmleditwidth =>'190px',
                label         =>'Typ',
                default       =>1,
                transprefix   =>'iptyp.',
                value         =>[qw(0 1 2 3 4 5 8 9 6 7)],
                dataobjattr   =>'ipaddress.addresstyp'),

      new kernel::Field::Boolean(
                name          =>'is_monitoring',
                label         =>'use this ip for system monitoring',
                htmldetail    =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   if (defined($param{current})){
                      return(0) if ($param{current}->{itclustsvcid} ne "");
                   }
                   return(1);
                },
                depend        =>['itclustsvcid'],
                group         =>'default',
                dataobjattr   =>'ipaddress.is_monitoring'),
                                                  
      new kernel::Field::Text(
                name          =>'ifname',
                htmlwidth     =>'130px',
                label         =>'Interface name',
                dataobjattr   =>'ipaddress.ifname'),

      new kernel::Field::Text(
                name          =>'accountno',
                htmlwidth     =>'130px',
                label         =>'Account Number',
                dataobjattr   =>'ipaddress.accountno'),

      new kernel::Field::Link(
                name          =>'addresstyp',
                htmlwidth     =>'5px',
                dataobjattr   =>'ipaddress.addresstyp'),

      new kernel::Field::DynWebIcon(
                name          =>'webaddresstyp',
                searchable    =>0,
                depend        =>['type','name','dnsname'],
                htmlwidth     =>'5px',
                htmldetail    =>0,
                weblink       =>sub{
                   my $self=shift;
                   my $current=shift;
                   my $mode=shift;
                   my $typeo=$self->getParent->getField("type");
                   my $d=$typeo->FormatedDetail($current,"AscV01");

                   my $ipo=$self->getParent->getField("dnsname");
                   my $ipname=$ipo->RawValue($current);
                   if ($ipname eq ""){
                      $ipo=$self->getParent->getField("name");
                      $ipname=$ipo->RawValue($current);
                   }
                   $ipname=~s/"//g;

                   my $e=$self->RawValue($current);
                   my $name=$self->Name();
                   my $app=$self->getParent();
                   if ($mode=~m/html/i){
                      return("<a href=\"ssh://$ipname\"><img ".
                         "src=\"../../itil/load/iptyp${e}.gif\" ".
                         "title=\"$d\" border=0></a>");
                   }
                   return($d);
                },
                dataobjattr   =>'ipaddress.addresstyp'),

#      new kernel::Field::Select(
#                name          =>'isjobserverpartner',
#                transprefix   =>'boolean.',
#                htmleditwidth =>'30%',
#                label         =>'JobServer Partner',
#                value         =>[0,1],
#                dataobjattr   =>'ipaddress.is_controllpartner'),

      new kernel::Field::Link(
                name          =>'cistatusid',
                label         =>'CI-StateID',
                dataobjattr   =>'ipaddress.cistatus'),

      new kernel::Field::Textarea(
                name          =>'comments',
                label         =>'Comments',
                dataobjattr   =>'ipaddress.comments'),

      new kernel::Field::Text(
                name          =>'shortcomments',
                label         =>'Short Comments',
                readonly      =>1,
                htmldetail    =>0,
                htmlwidth     =>'190px',
                onRawValue    =>sub{
                                   my $self=shift;
                                   my $current=shift;
                                   my $d=$current->{comments};
                                   $d=~s/\n/ /g;
                                   $d=substr($d,0,24);
                                   if (length($current->{comments})>
                                       length($d)){
                                      $d.="...";
                                   }
                                   return($d);
                                },
                depend        =>['comments']),

      new kernel::Field::Container(
                name          =>'additional',
                label         =>'Additionalinformations',
                dataobjattr   =>'ipaddress.additional'),

      new kernel::Field::SubList(
                name          =>'ipnets',
                label         =>'IP-Networks',
                group         =>'ipnets',
                vjointo       =>'itil::lnkipaddressipnet',
                vjoinbase     =>[{ipnetcistatusid=>"<=4",
                                  activesubipnets=>'0'}],
                vjoinon       =>['id'=>'ipaddressid'],
                vjoindisp     =>['ipnetname','ipnet']),

      new kernel::Field::Text(
                name          =>'srcsys',
                group         =>'source',
                label         =>'Source-System',
                dataobjattr   =>'ipaddress.srcsys'),
                                                   
      new kernel::Field::Text(
                name          =>'srcid',
                group         =>'source',
                label         =>'Source-Id',
                dataobjattr   =>'ipaddress.srcid'),
                                                   
      new kernel::Field::Date(
                name          =>'srcload',
                group         =>'source',
                label         =>'Source-Load',
                dataobjattr   =>'ipaddress.srcload'),

      new kernel::Field::CDate(
                name          =>'cdate',
                group         =>'source',
                sqlorder      =>'desc',
                label         =>'Creation-Date',
                dataobjattr   =>'ipaddress.createdate'),
                                                  
      new kernel::Field::MDate(
                name          =>'mdate',
                group         =>'source',
                sqlorder      =>'desc',
                label         =>'Modification-Date',
                dataobjattr   =>'ipaddress.modifydate'),

      new kernel::Field::Creator(
                name          =>'creator',
                group         =>'source',
                label         =>'Creator',
                dataobjattr   =>'ipaddress.createuser'),

      new kernel::Field::Owner(
                name          =>'owner',
                group         =>'source',
                label         =>'last Editor',
                dataobjattr   =>'ipaddress.modifyuser'),

      new kernel::Field::Editor(
                name          =>'editor',
                group         =>'source',
                label         =>'Editor Account',
                dataobjattr   =>'ipaddress.editor'),

      new kernel::Field::RealEditor(
                name          =>'realeditor',
                group         =>'source',
                label         =>'real Editor Account',
                dataobjattr   =>'ipaddress.realeditor'),

      new kernel::Field::Interface(
                name          =>'replkeypri',
                group         =>'source',
                label         =>'primary sync key',
                dataobjattr   =>"ipaddress.modifydate"),

      new kernel::Field::Interface(
                name          =>'replkeysec',
                group         =>'source',
                label         =>'secondary sync key',
                dataobjattr   =>"lpad(ipaddress.id,35,'0')")
   );
   $self->{history}={
      insert=>[
         'local',
         {dataobj=>'itil::system', id=>'systemid',
          field=>'name',as=>'ipaddresses'}
      ],
      update=>[
         'local',
         {dataobj=>'itil::system', id=>'systemid'}
      ],
      delete=>[
         {dataobj=>'itil::system', id=>'systemid',
          field=>'fullname',as=>'ipaddresses'}
      ]
   };
   $self->setDefaultView(qw(name system dnsname cistatus mdate));
   $self->setWorktable("ipaddress");
   return($self);
}


sub initSearchQuery
{
   my $self=shift;
   if (!defined(Query->Param("search_cistatus"))){
     Query->Param("search_cistatus"=>
                  "\"!".$self->T("CI-Status(6)","base::cistatus")."\"");
   }
}


sub prepareToWasted
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;

   $newrec->{srcid}=undef;
   $newrec->{srcload}=undef;

   my $id=effVal($oldrec,$newrec,"id");

   #my $o=getModuleObject($self->Config,"itil::system");
   #if (defined($o)){
   #   $o->BulkDeleteRecord({xxxxxxxx=>\$id});
   #}

   return(1);   # if undef, no wasted Transfer is allowed
}





sub Validate
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;
   
   return(1) if (effChangedVal($oldrec,$newrec,"cistatusid")==7);

   my $cistatusid=trim(effVal($oldrec,$newrec,"cistatusid"));
   if (!defined($cistatusid) || $cistatusid==0){
      $newrec->{cistatusid}=4;
   }


   #
   # Generierung der Typ Flags (Eindeutigkeitssicherung)
   #
   my $cistatusid=effVal($oldrec,$newrec,"cistatusid");
   my $is_primary=effVal($oldrec,$newrec,"is_primary");
   my $is_notdeleted=effVal($oldrec,$newrec,"is_notdeleted");
   my $type=effVal($oldrec,$newrec,"type");
   if ($type eq ""){  # if no type is specified - use secondary
      $newrec->{type}=1;
      $type=1;
   }
   if ($type eq "0" && $is_primary ne "1"){
      $newrec->{is_primary}=1;
   }
   if ($type ne "0" && $is_primary ne ""){
      $newrec->{is_primary}=undef;
   }
   if ($cistatusid<=5 && $is_notdeleted ne "1"){
      $newrec->{is_notdeleted}=1;
   }
   if ($cistatusid>5 && $is_notdeleted ne ""){
      $newrec->{is_notdeleted}=undef;
   }
   my $is_monitoring=effVal($oldrec,$newrec,"is_monitoring");
   if ($is_monitoring ne "1" && $is_monitoring ne "" &&
       defined($oldrec) && $oldrec->{is_monitoring} ne "0"){
      $newrec->{is_monitoring}=undef;
   }
   ##################################################################



   my $name=trim(effVal($oldrec,$newrec,"name"));
   my $binnamekey="";
   $name=~s/\s//g;
   my $ip6str="";
   if ($cistatusid<=5){
      $name=~s/\[\d*\]$//;
   }

   if ($name=~m/\./){
      $name=~s/^[0]+([1-9])/$1/g;
      $name=~s/\.[0]+([1-9])/.$1/g;
   }
   my $chkname=lc($name);
   if ($cistatusid>5){
      $chkname=~s/\[\d+\]$//;
   }

   my $errmsg;
   my $type=$self->IPValidate($chkname,\$errmsg);
   if ($type eq "IPv4"){
      my ($o1,$o2,$o3,$o4)=$chkname=~m/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
      $ip6str="0000:0000:0000:0000:0000:ffff:".
              unpack("H2",pack('C',$o1)).
              unpack("H2",pack('C',$o2)).":".
              unpack("H2",pack('C',$o3)).
              unpack("H2",pack('C',$o4));
   }
   elsif ($type eq "IPv6"){
       $ip6str=$chkname;
   }
   else{
      $self->LastMsg(ERROR,$self->T($errmsg,"itil::lib::Listedit"));
      return(0);
   }

   foreach my $okt (split(/:/,$ip6str)){
      $binnamekey.=unpack("B16",pack("H4",$okt));
   }
   if ($oldrec->{binnamekey} ne $binnamekey){
      $newrec->{'binnamekey'}=$binnamekey;
   }
   if ($oldrec->{name} ne lc($name)){
      $newrec->{'name'}=lc($name);
   }

   #######################################################################
   # unique IP-Handling
   $newrec->{'uniqueflag'}=1;
   my $networkid=effVal($oldrec,$newrec,"networkid");
   if ($networkid eq ""){
      $self->LastMsg(ERROR,"no network specified");
      return(0);
   }
   my $n=getModuleObject($self->Config,"itil::network");
   $n->SetFilter({id=>\$networkid,cistatusid=>[3,4]});
   my ($nrec,$msg)=$n->getOnlyFirst(qw(uniquearea));
   if (!defined($nrec)){
      $self->LastMsg(ERROR,"no networkid specified");
      return(0);
   }
   if (!$nrec->{uniquearea}){
      $newrec->{'uniqueflag'}=undef;
   }


   if (exists($newrec->{'dnsname'})){
      my $dnsname=lc(trim(effVal($oldrec,$newrec,"dnsname")));
      $dnsname=~s/[^a-z0-9\[\]]*$//;
      $dnsname=~s/^[^a-z0-9]*//;
      $newrec->{'dnsname'}=$dnsname;
      if ($dnsname ne ""){
         if (($dnsname=~m/\s/) || !($dnsname=~m/.+\..+/)){
            $self->LastMsg(ERROR,"invalid dns name");
            return(0);
         }
      }
      $newrec->{'dnsname'}=undef if ($newrec->{'dnsname'} eq "");
   }

   my $accountno=trim(effVal($oldrec,$newrec,"accountno"));
   if ($accountno=~m/\s/){
      $self->LastMsg(ERROR,"invalid account number specified");
      return(0);
   }

#   msg(INFO,sprintf("iprec=%s\n",Dumper($newrec)));

   if (!defined($oldrec) && !exists($newrec->{'type'}) &&
                            !exists($newrec->{'addresstyp'})){
      $newrec->{'addresstyp'}=1;
   }
   return(0) if (!($self->isParentSpecified($oldrec,$newrec)));
   #return(1) if ($self->IsMemberOf("admin"));
   return(0) if (!$self->HandleCIStatusModification($oldrec,$newrec,"name","dnsname"));

   return(1);
}

sub isParentSpecified
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;

   my $itclustsvcid=effVal($oldrec,$newrec,"itclustsvcid");
   my $systemid=effVal($oldrec,$newrec,"systemid");
   if ($systemid<=0 && $itclustsvcid <=0){
      $self->LastMsg(ERROR,"invalid parent object reference specified");
      return(0);
   } 
   return(0) if (!($self->isParentWriteable($systemid,$itclustsvcid)));
   return(1);

}





sub isParentWriteable
{
   my $self=shift;
   my $systemid=shift;
   my $itclustsvcid=shift;

   return($self->isParentOPvalid("write",$systemid,$itclustsvcid));

}

sub isParentReadable
{
   my $self=shift;
   my $systemid=shift;
   my $itclustsvcid=shift;

   return($self->isParentOPvalid("read",$systemid,$itclustsvcid));

}

sub isParentOPvalid
{
   my $self=shift;
   my $mode=shift;
   my $systemid=shift;
   my $itclustsvcid=shift;

   if ($systemid ne ""){
      my $p=$self->getPersistentModuleObject("itil::system");
      my $idname=$p->IdField->Name();
      my %flt=($idname=>\$systemid);
      $p->ResetFilter();
      if (isDataInputFromUserFrontend()){
         $p->SecureSetFilter(\%flt,\%flt);  # verhindert isDirectFilter true
      }
      else{
         $p->SetFilter(\%flt,\%flt);        # verhindert isDirectFilter true
      }
      my @l=$p->getHashList(qw(ALL));
      if ($#l!=0){
         $self->LastMsg(ERROR,"invalid system reference") if ($mode eq "write");
         return(0);
      }
      my @blkl;
      if ($mode eq "write"){ 
         @blkl=$p->isWriteValid($l[0]);
      }
      if ($mode eq "read"){ 
         @blkl=$p->isViewValid($l[0]);
      }
      if (isDataInputFromUserFrontend()){
         if (!grep(/^ALL$/,@blkl) && !grep(/^ipaddresses$/,@blkl)){
            $self->LastMsg(ERROR,"no access") if ($mode eq "write");
            return(0);
         }
      }
   }
   if ($itclustsvcid ne ""){
      my $p=$self->getPersistentModuleObject("itil::lnkitclustsvc");
      my $idname=$p->IdField->Name();
      my %flt=($idname=>\$itclustsvcid);
      $p->ResetFilter();
      $p->SecureSetFilter(\%flt,\%flt);
      my @l=$p->getHashList(qw(ALL));
      if ($#l!=0){
         $self->LastMsg(ERROR,"invalid itclust reference") if ($mode eq "write");
         return(0);
      }
      my @blkl;
      if ($mode eq "write"){ 
         @blkl=$p->isWriteValid($l[0]);
      }
      if ($mode eq "read"){ 
         @blkl=$p->isViewValid($l[0]);
      }
      if (isDataInputFromUserFrontend()){
         if (!grep(/^ALL$/,@blkl) && !grep(/^ipaddresses$/,@blkl)){
            $self->LastMsg(ERROR,"no access") if ($mode eq "write");
            return(0);
         }
      }
   }
   return(1);
}

sub SecureSetFilter
{
   my $self=shift;
   my @flt=@_;

   if (!$self->isDirectFilter(@flt)){
      my @addflt=({cistatusid=>"!7"});
      push(@flt,\@addflt);

   }
   return($self->SetFilter(@flt));
}


sub isViewValid
{
   my $self=shift;
   my $rec=shift;
   my @def=("header","default");
   return(@def) if (!defined($rec));
   return(qw(header default)) if (defined($rec) && $rec->{cistatusid}==7);
   push(@def,"source");
   if ($self->IsMemberOf("admin") ||
       $self->IsMemberOf("w5base.itil.ipaddress.read") ||
       $self->isParentReadable($rec->{systemid},$rec->{itclustsvcid})){
      push(@def,"history");
      push(@def,"ipnets");
      push(@def,"relatedto","further");
      push(@def,"dnsaliases",) if ($rec->{dnsname} ne "");
   }
   else{
      return();
   }
   return(@def);
}

sub isWriteValid
{
   my $self=shift;
   my $rec=shift;

   if (defined($rec)){
      return("default","relatedto") if ($self->IsMemberOf("admin"));
      return(undef) if (!$self->isParentSpecified($rec));
   }

   return("default","relatedto");
}

sub getRecordHtmlIndex
{ 
   my $self=shift;

   return; 
}

sub getDetailBlockPriority
{
   my $self=shift;
   return(qw(header default relatedto dnsaliases ipnets further source));
}






1;
