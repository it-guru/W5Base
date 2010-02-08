package itil::swinstance;
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
@ISA=qw(kernel::App::Web::Listedit kernel::DataObj::DB kernel::CIStatusTools);

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
                searchable    =>0,
                label         =>'W5BaseID',
                dataobjattr   =>'swinstance.id'),
                                                  
      new kernel::Field::Text(
                name          =>'fullname',
                label         =>'Fullname',
                htmlwidth     =>'300px',
                readonly      =>'1',
                dataobjattr   =>'swinstance.fullname'),

      new kernel::Field::Mandator(),

      new kernel::Field::Link(
                name          =>'mandatorid',
                dataobjattr   =>'swinstance.mandator'),

      new kernel::Field::Select(
                name          =>'cistatus',
                htmleditwidth =>'40%',
                label         =>'CI-State',
                vjoineditbase =>{id=>">0"},
                vjointo       =>'base::cistatus',
                vjoinon       =>['cistatusid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::TextDrop(
                name          =>'databoss',
                label         =>'Databoss',
                vjointo       =>'base::user',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['databossid'=>'userid'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Link(
                name          =>'databossid',
                dataobjattr   =>'swinstance.databoss'),

      new kernel::Field::Select(
                name          =>'swnature',
                htmleditwidth =>'40%',
                label         =>'Instance type',
                value         =>['Apache',
                                 'Apple WebObjects',
                                 'BEA WebLogic',
                                 'BEA Tuxedo',
                                 'CICS',
                                 'DB2',
                                 'IIS',
                                 'Informix',
                                 'JacORB',
                                 'JBoss',
                                 'MuleSource',
                                 'MQSeries',
                                 'MSSQL',
                                 'MySQL',
                                 'Oracle',
                                 'Oracle Appl Server',
                                 'PostgeSQL',
                                 'SAP/R2',
                                 'SAP/R3',
                                 'SunONE',
                                 'Tomcat',
                                 'Visibroker',
                                 'WebSphere Appl Server',
                                 'WebSphere Business Monitor',
                                 'WebSphere Message Broker',
                                 'WebSphere Process Server',
                                 'WebSphere Service Registry/Repository',
                                 'Other'],
                dataobjattr   =>'swinstance.swnature'),

      new kernel::Field::TextDrop(
                name       =>'appl',
                htmlwidth  =>'150px',
                label      =>'Application',
                vjointo    =>'itil::appl',
                vjoinon    =>['applid'=>'id'],
                vjoindisp  =>'name'),

      new kernel::Field::Link(
                name          =>'applid',
                label         =>'ApplicationID',
                dataobjattr   =>'swinstance.appl'),

      new kernel::Field::Text(
                name          =>'applconumber',
                htmlwidth     =>'100px',
                label         =>'Application CO-Number',
                weblinkto     =>'itil::costcenter',
                weblinkon     =>['applconumber'=>'name'],
                readonly      =>'1',
                dataobjattr   =>'appl.conumber'),

      new kernel::Field::Text(
                name          =>'name',
                htmlwidth     =>'250px',
                label         =>'Instance-Name',
                dataobjattr   =>'swinstance.name'),

      new kernel::Field::Text(
                name          =>'addname',
                htmlwidth     =>'250px',
                label         =>'Additional-Tag',
                dataobjattr   =>'swinstance.addname'),

      new kernel::Field::Select(
                name          =>'swtype',
                htmleditwidth =>'40%',
                label         =>'Instance operation type',
                value         =>['primary',
                                 'secondary',
                                 'standby'],
                dataobjattr   =>'swinstance.swtype'),


      new kernel::Field::Number(
                name          =>'swport',
                label         =>'TCP/IP-Port',
                dataobjattr   =>'swinstance.swport'),

      new kernel::Field::TextDrop(
                name          =>'swteam',
                label         =>'Instance guardian team',
                vjointo       =>'base::grp',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['swteamid'=>'grpid'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Text(
                name          =>'swinstanceid',
                htmlwidth     =>'100px',
                label         =>'Instance ID',
                dataobjattr   =>'swinstance.swinstanceid'),

      new kernel::Field::Link(
                name          =>'swteamid',
                dataobjattr   =>'swinstance.swteam'),

      new kernel::Field::Link(
                name          =>'cistatusid',
                label         =>'CI-StateID',
                dataobjattr   =>'swinstance.cistatus'),

      new kernel::Field::Link(
                name          =>'servicesupportid',
                dataobjattr   =>'swinstance.servicesupport'),


      new kernel::Field::TextDrop(
                name          =>'adm',
                label         =>'Instance Administrator',
                group         =>'adm',
                vjointo       =>'base::user',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['admid'=>'userid'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Link(
                name          =>'admid',
                dataobjattr   =>'swinstance.adm'),

      new kernel::Field::TextDrop(
                name          =>'adm2',
                label         =>'Deputy Instance Administrator',
                group         =>'adm',
                vjointo       =>'base::user',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['adm2id'=>'userid'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Link(
                name          =>'adm2id',
                dataobjattr   =>'swinstance.adm2'),

      new kernel::Field::SubList(
                name          =>'systems',
                label         =>'Systems',
                group         =>'systems',
                allowcleanup  =>1,
                subeditmsk    =>'subedit.swinstance',
                vjointo       =>'itil::lnkswinstancesystem',
                vjoinbase     =>[{systemcistatusid=>"<=5"}],
                vjoinon       =>['id'=>'swinstanceid'],
                vjoindisp     =>['system','systemsystemid','systemcistatus',
                                 'shortdesc'],
                vjoininhash   =>['system','systemsystemid','systemcistatus',
                                 'systemid']),

      new kernel::Field::TextDrop(
                name          =>'servicesupport',
                label         =>'Service&Support Class',
                group         =>'misc',
                vjointo       =>'itil::servicesupport',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['servicesupportid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::TextDrop(
                name          =>'servicesupportsapservicename',
                label         =>'Service&Support Class - SAP Service name',
                group         =>'misc',
                htmldetail    =>0,
                readonly      =>1,
                vjointo       =>'itil::servicesupport',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['servicesupportid'=>'id'],
                vjoindisp     =>'sapservicename'),

      new kernel::Field::Boolean(
                name          =>'issox',
                readonly      =>1,
                group         =>'sec',
                htmleditwidth =>'30%',
                label         =>'mangaged by rules of SOX',
                dataobjattr   =>
                'if (swinstance.no_sox_inherit,0,appl.is_soxcontroll)'),

      new kernel::Field::Select(
                name          =>'nosoxinherit',
                group         =>'sec',
                label         =>'SOX state',
                searchable    =>0,
                transprefix   =>'ApplInherit.',
                htmleditwidth =>'180px',
                value         =>['0','1'],
                translation   =>'itil::appl',
                dataobjattr   =>'swinstance.no_sox_inherit'),


      new kernel::Field::Boolean(
                name          =>'custcostalloc',
                label         =>'Customer cost allocation',
                group         =>'misc',
                dataobjattr   =>'swinstance.custcostalloc'),

      new kernel::Field::Text(
                name          =>'autoname',
                group         =>'misc',
                label         =>'Automationsname/IP-Address',
                dataobjattr   =>'swinstance.autompartner'),

      new kernel::Field::Text(
                name          =>'sslurl',
                group         =>'ssl',
                label         =>'SSL Check URL',
                dataobjattr   =>'swinstance.ssl_url'),

      new kernel::Field::Date(
                name          =>'sslbegin',
                history       =>0,
                readonly      =>1,
                group         =>'ssl',
                label         =>'SSL Certificate Begin',
                dataobjattr   =>'swinstance.ssl_cert_begin'),

      new kernel::Field::Date(
                name          =>'sslend',
                history       =>0,
                readonly      =>1,
                group         =>'ssl',
                label         =>'SSL Certificate End',
                dataobjattr   =>'swinstance.ssl_cert_end'),

      new kernel::Field::Date(
                name          =>'sslcheck',
                history       =>0,
                readonly      =>1,
                group         =>'ssl',
                label         =>'SSL last Certificate check',
                dataobjattr   =>'swinstance.ssl_cert_check'),

      new kernel::Field::Text(
                name          =>'sslstate',
                readonly      =>1,
                group         =>'ssl',
                label         =>'SSL State',
                dataobjattr   =>'swinstance.ssl_state'),

      new kernel::Field::Textarea(
                name          =>'comments',
                group         =>'misc',
                label         =>'Comments',
                dataobjattr   =>'swinstance.comments'),

#      new kernel::Field::FileList(
#                name          =>'attachments',
#                label         =>'Attachments',
#                parentobj     =>'itil::swinstance',
#                group         =>'attachments'),

      new kernel::Field::Container(
                name          =>'additional',
                label         =>'Additionalinformations',
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
                dataobjattr   =>'swinstance.additional'),

      new kernel::Field::ContactLnk(
                name          =>'contacts',
                label         =>'Contacts',
                vjoinbase     =>[{'parentobj'=>\'itil::swinstance'}],
                vjoininhash   =>['mdate','targetid','target','roles'],
                group         =>'contacts'),

#      new kernel::Field::PhoneLnk(
#                name          =>'phonenumbers',
#                label         =>'Phonenumbers',
#                group         =>'phonenumbers',
#                vjoinbase     =>[{'parentobj'=>\'itil::swinstance'}],
#                subeditmsk    =>'subedit'),

      new kernel::Field::Text(
                name          =>'srcsys',
                group         =>'source',
                label         =>'Source-System',
                dataobjattr   =>'swinstance.srcsys'),
                                                   
      new kernel::Field::Text(
                name          =>'srcid',
                group         =>'source',
                label         =>'Source-Id',
                dataobjattr   =>'swinstance.srcid'),
                                                   
      new kernel::Field::Date(
                name          =>'srcload',
                history       =>0,
                group         =>'source',
                label         =>'Source-Load',
                dataobjattr   =>'swinstance.srcload'),

      new kernel::Field::CDate(
                name          =>'cdate',
                group         =>'source',
                sqlorder      =>'desc',
                label         =>'Creation-Date',
                dataobjattr   =>'swinstance.createdate'),
                                                  
      new kernel::Field::MDate(
                name          =>'mdate',
                group         =>'source',
                sqlorder      =>'desc',
                label         =>'Modification-Date',
                dataobjattr   =>'swinstance.modifydate'),

      new kernel::Field::Creator(
                name          =>'creator',
                group         =>'source',
                label         =>'Creator',
                dataobjattr   =>'swinstance.createuser'),

      new kernel::Field::Owner(
                name          =>'owner',
                group         =>'source',
                label         =>'Owner',
                dataobjattr   =>'swinstance.modifyuser'),

      new kernel::Field::Editor(
                name          =>'editor',
                group         =>'source',
                label         =>'Editor',
                dataobjattr   =>'swinstance.editor'),

      new kernel::Field::RealEditor(
                name          =>'realeditor',
                group         =>'source',
                label         =>'RealEditor',
                dataobjattr   =>'swinstance.realeditor'),

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

      new kernel::Field::QualityText(),
      new kernel::Field::QualityState(),
      new kernel::Field::QualityOk(),
      new kernel::Field::QualityLastDate(
                dataobjattr   =>'swinstance.lastqcheck'),
   );
   $self->{history}=[qw(insert modify delete)];
   $self->{use_distinct}=1;
   $self->setDefaultView(qw(fullname mandator cistatus mdate));
   $self->setWorktable("swinstance");
   return($self);
}

sub isCopyValid
{
   my $self=shift;

   return(1);
}

sub InitCopy
{
   my ($self,$copyfrom,$newrec)=@_;
   delete($newrec->{'Formated_databoss'});
}





sub getRecordImageUrl
{
   my $self=shift;
   my $cgi=new CGI({HTTP_ACCEPT_LANGUAGE=>$ENV{HTTP_ACCEPT_LANGUAGE}});
   return("../../../public/itil/load/swinstance.jpg?".$cgi->query_string());
}

sub getSqlFrom
{
   my $self=shift;
   my $mode=shift;
   my @flt=@_;
   my ($worktable,$workdb)=$self->getWorktable();
   my $from="$worktable";

   $from.=" left outer join lnkcontact ".
          "on lnkcontact.parentobj='itil::swinstance' ".
          "and $worktable.id=lnkcontact.refid ".
          "left outer join appl on $worktable.appl=appl.id";

   return($from);
}

sub initSearchQuery
{
   my $self=shift;
   if (!defined(Query->Param("search_cistatus"))){
     Query->Param("search_cistatus"=>
                  "\"!".$self->T("CI-Status(6)","base::cistatus")."\"");
   }
}




sub SecureSetFilter
{
   my $self=shift;
   my @flt=@_;

   if (!$self->isDirectFilter(@flt) && 
       !$self->IsMemberOf([qw(admin w5base.itil.swinstance.read 
                              w5base.itil.read)],
                          "RMember")){
      my @mandators=$self->getMandatorsOf($ENV{REMOTE_USER},"read");
      my %grps=$self->getGroupsOf($ENV{REMOTE_USER},
                                  [orgRoles(),qw(RCFManager)],"both");
      my @grpids=keys(%grps);
      my $userid=$self->getCurrentUserId();
      push(@flt,[
                 {mandatorid=>\@mandators},
                 {databossid=>$userid},
                 {admid=>$userid},       {adm2id=>$userid},
                 {swteamid=>\@grpids},
                 {sectargetid=>\$userid,sectarget=>\'base::user',
                  secroles=>"*roles=?write?=roles* *roles=?read?=roles*"},
                 {sectargetid=>\@grpids,sectarget=>\'base::grp',
                  secroles=>"*roles=?write?=roles* *roles=?read?=roles*"}
                ]);
   }
   return($self->SetFilter(@flt));
}


         

sub Validate
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;


   my $autoname=trim(effVal($oldrec,$newrec,"autoname"));
   if ($autoname ne ""){
      if ($autoname=~m/\s/ ||
          !($autoname=~m/^[a-z,A-Z,0-9,_,\-,\.]+$/) ||
          !($autoname=~m/\./) ||
           ($autoname=~m/^\./) ||
           ($autoname=~m/\.$/)){
         $self->LastMsg(ERROR,"invalid Automationsname");
         return(0);
      }
      $newrec->{autoname}=lc($autoname);
   }
   else{
      $newrec->{autoname}=undef;
   }

   my $swnature=trim(effVal($oldrec,$newrec,"swnature"));
   my $name=trim(effVal($oldrec,$newrec,"name"));
   my $addname=trim(effVal($oldrec,$newrec,"addname"));
   my $swtype=trim(effVal($oldrec,$newrec,"swtype"));
   my $swport=trim(effVal($oldrec,$newrec,"swport"));
   my $swinstanceid=trim(effVal($oldrec,$newrec,"swinstanceid"));
   if ($swnature=~m/^\s*$/){
      $self->LastMsg(ERROR,"invalid swnature");
      return(0);
   }
   if (exists($newrec->{name})){
      $newrec->{name}=$name;
   }
   $name=~s/\./_/g;
   if ($name eq "" || ($name=~m/[^-a-z0-9\._]/i)){
      $self->LastMsg(ERROR,"invalid instance name");
      return(0);
   }

   my $fname=$name;
   $fname.=($fname ne "" && $swnature ne "" ? "." : "").$swnature;
   $fname.=($fname ne "" && $swtype   ne "" ? "." : "").$swtype;
   $fname.=($fname ne "" && $swport   ne "" ? "." : "").$swport;
   $fname.=($fname ne "" && $addname  ne "" ? "." : "").$addname;
   $fname=~s/�/ue/g;
   $fname=~s/�/oe/g;
   $fname=~s/�/ae/g;
   $fname=~s/�/Ue/g;
   $fname=~s/�/Oe/g;
   $fname=~s/�/Ae/g;
   $fname=~s/�/ss/g;
   $fname=~s/\s/_/g;
   $newrec->{'fullname'}=$fname;

   my $fname=trim(effVal($oldrec,$newrec,"fullname"));
   
   if ($fname eq "" || $fname=~m/[;,\s\&\\]/){
      $self->LastMsg(ERROR,
           sprintf($self->T("invalid swinstance name '%s' specified"),$fname));
      return(0);
   }

   ########################################################################
   # standard security handling
   #
   if ($self->isDataInputFromUserFrontend() && !$self->IsMemberOf("admin")){
      my $userid=$self->getCurrentUserId();
      if (!defined($oldrec)){
         if (!defined($newrec->{databossid}) ||
             $newrec->{databossid}==0){
            my $userid=$self->getCurrentUserId();
            $newrec->{databossid}=$userid;
         }
      }
      if (defined($newrec->{databossid}) &&
          $newrec->{databossid}!=$userid &&
          $newrec->{databossid}!=$oldrec->{databossid}){
         $self->LastMsg(ERROR,"you are not authorized to set other persons ".
                              "as databoss");
         return(0);
      }
   }
   if ($swinstanceid eq ""){
      $newrec->{swinstanceid}=undef;
   }
   ########################################################################
   if (effVal($oldrec,$newrec,"swport")=~m/^\s*$/){
      $newrec->{swport}=undef;
   }
   ########################################################################
   if (effChanged($oldrec,$newrec,"sslurl")){
      $newrec->{sslbegin}=undef;
      $newrec->{sslend}=undef;
      $newrec->{sslstate}=undef;
      $newrec->{sslcheck}=undef;
   }


   return(0) if (!$self->HandleCIStatusModification($oldrec,$newrec,"fullname"));
   return(1);
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


sub isViewValid
{
   my $self=shift;
   my $rec=shift;
   return("header","default") if (!defined($rec));
   return("ALL");
}


sub isWriteValid
{
   my $self=shift;
   my $rec=shift;
   my $userid=$self->getCurrentUserId();

   my @databossedit=qw(default adm systems contacts ssl misc sec);
   if (!defined($rec)){
      return(@databossedit);
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
            if (grep(/^write$/,@roles)){
               return(@databossedit);
            }
         }
      }
      if ($rec->{mandatorid}!=0 && 
         $self->IsMemberOf($rec->{mandatorid},"RCFManager","down")){
         return(@databossedit);
      }
      if ($rec->{swteam}!=0 && 
         $self->IsMemberOf($rec->{swteam},"RCFManager","down")){
         return(@databossedit);
      }
   }
   return(undef);
}

sub getDetailBlockPriority
{
   my $self=shift;
   return(qw(header default adm systems sec ssl misc contacts source));
}






1;
