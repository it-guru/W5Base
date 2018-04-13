package itil::lnkapplurl;
#  W5Base Framework
#  Copyright (C) 2013  Hartmut Vogler (it@guru.de)
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
use itil::lib::Listedit;
@ISA=qw(kernel::App::Web::Listedit itil::lib::Listedit kernel::DataObj::DB);


sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   $self->{history}={
      insert=>[
         {dataobj=>'itil::appl', id=>'applid',
          field=>'name',as=>'applurl'}
      ],
      update=>[
         'local',
         {dataobj=>'itil::appl', id=>'applid',
          field=>'name',as=>'applurl'}
      ],
      delete=>[
         {dataobj=>'itil::appl', id=>'applid',
          field=>'name',as=>'applurl'}
      ]
   };

   $self->AddFields(
      new kernel::Field::Linenumber(
                name          =>'linenumber',
                label         =>'No.'),

      new kernel::Field::Id(
                name          =>'id',
                label         =>'URL ID',
                searchable    =>0,
                dataobjattr   =>'accessurl.id'),
      new kernel::Field::RecordUrl(),
                                                 
      new kernel::Field::Text(
                name          =>'fullname',
                readonly      =>1,
                htmldetail    =>0,
                label         =>'URL fullname',
                dataobjattr   =>"concat(appl.name,': ',accessurl.fullname)"),

      new kernel::Field::Text(
                name          =>'name',
                label         =>'URL',
                dataobjattr   =>'accessurl.fullname'),

      new kernel::Field::TextDrop(
                name          =>'appl',
                htmlwidth     =>'250px',
                label         =>'provided by Application',
                vjoineditbase =>{'cistatusid'=>"<5"},
                vjointo       =>'itil::appl',
                vjoinon       =>['applid'=>'id'],
                vjoindisp     =>'name',
                dataobjattr   =>'appl.name'),
                                                   
      new kernel::Field::Select(
                name          =>'applcistatus',
                readonly      =>1,
                group         =>'applinfo',
                label         =>'Application CI-State',
                vjointo       =>'base::cistatus',
                vjoinon       =>['applcistatusid'=>'id'],
                vjoindisp     =>'name'),
                                                  
      new kernel::Field::Select(
                name          =>'network',
                htmleditwidth =>'280px',
                label         =>'Network',
                vjointo       =>'itil::network',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['networkid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Link(
                name          =>'networkid',
                label         =>'NetworkID',
                dataobjattr   =>'accessurl.network'),

      new kernel::Field::Textarea(
                name          =>'comments',
                searchable    =>0,
                label         =>'Comments',
                dataobjattr   =>'accessurl.comments'),

      new kernel::Field::Boolean(
                name          =>'is_userfrontend',
                group         =>'class',
                label         =>'Accessed by endusers (Application Frontend)',
                dataobjattr   =>'accessurl.is_userfrontend'),

      new kernel::Field::Boolean(
                name          =>'is_interface',
                group         =>'class',
                label         =>'Accessed by interface applications',
                dataobjattr   =>'accessurl.is_interface'),

      new kernel::Field::Boolean(
                name          =>'is_interal',
                group         =>'class',
                label         =>'only for internal communication in application',
                dataobjattr   =>'accessurl.is_internal'),


      new kernel::Field::TextDrop(
                name          =>'lnkapplappl',
                group         =>'urlinfo',
                readonly      =>1,
                label         =>'Interface',
                vjointo       =>'itil::lnkapplappl',
                vjoinon       =>['lnkapplapplid'=>'id'],
                vjoindisp     =>'fullname'),

      new kernel::Field::Link(
                name          =>'lnkapplapplid',
                selectfix     =>1,
                label         =>'InterfaceID',
                dataobjattr   =>'accessurl.lnkapplappl'),

      new kernel::Field::Text(
                name          =>'scheme',
                group         =>'urlinfo',
                readonly      =>1,
                label         =>'Scheme',
                dataobjattr   =>'accessurl.scheme'),
                                                   
      new kernel::Field::Text(
                name          =>'hostname',
                group         =>'urlinfo',
                readonly      =>1,
                label         =>'Hostname',
                dataobjattr   =>'accessurl.hostname'),

      new kernel::Field::SubList(
                name          =>'lastipaddresses',
                label         =>'last known IP-Adresses',
                group         =>'lastipaddresses',
                vjointo       =>'itil::lnkapplurlip',
                vjoinon       =>['id'=>'lnkapplurlid'],
                vjoindisp     =>['name','srcload']),

      new kernel::Field::Number(
                name          =>'ipport',
                group         =>'urlinfo',
                readonly      =>1,
                label         =>'IP-Port',
                dataobjattr   =>'accessurl.ipport'),
                                                   
      new kernel::Field::Creator(
                name          =>'creator',
                group         =>'source',
                label         =>'Creator',
                dataobjattr   =>'accessurl.createuser'),
                                   
      new kernel::Field::Owner(
                name          =>'owner',
                group         =>'source',
                label         =>'last Editor',
                dataobjattr   =>'accessurl.modifyuser'),
                                   
      new kernel::Field::Text(
                name          =>'srcsys',
                group         =>'source',
                label         =>'Source-System',
                dataobjattr   =>'accessurl.srcsys'),
                                                   
      new kernel::Field::Text(
                name          =>'srcid',
                group         =>'source',
                label         =>'Source-Id',
                dataobjattr   =>'accessurl.srcid'),
                                                   
      new kernel::Field::Date(
                name          =>'srcload',
                group         =>'source',
                label         =>'Last-Load',
                dataobjattr   =>'accessurl.srcload'),

      new kernel::Field::Interface(
                name          =>'replkeypri',
                group         =>'source',
                label         =>'primary sync key',
                dataobjattr   =>"accessurl.modifydate"),

      new kernel::Field::Interface(
                name          =>'replkeysec',
                group         =>'source',
                label         =>'secondary sync key',
                dataobjattr   =>"lpad(accessurl.id,35,'0')"),

      new kernel::Field::CDate(
                name          =>'cdate',
                group         =>'source',
                label         =>'Creation-Date',
                dataobjattr   =>'accessurl.createdate'),
                                                
      new kernel::Field::MDate(
                name          =>'mdate',
                group         =>'source',
                label         =>'Modification-Date',
                dataobjattr   =>'accessurl.modifydate'),
                                                   
      new kernel::Field::Editor(
                name          =>'editor',
                group         =>'source',
                label         =>'Editor Account',
                dataobjattr   =>'accessurl.editor'),
                                                  
      new kernel::Field::RealEditor(
                name          =>'realeditor',
                group         =>'source',
                label         =>'real Editor Account',
                dataobjattr   =>'accessurl.realeditor'),

      new kernel::Field::Mandator(
                group         =>'applinfo',
                readonly      =>1),

      new kernel::Field::Link(
                name          =>'mandatorid',
                label         =>'ApplMandatorID',
                group         =>'applinfo',
                dataobjattr   =>'appl.mandator'),

      new kernel::Field::Import( $self,
                vjointo       =>'itil::appl',
                dontrename    =>1,
                readonly      =>1,
                group         =>'applinfo',
                uploadable    =>0,
                fields        =>[qw(databoss databossid applmgr applmgrid)]),

      new kernel::Field::Link(
                name          =>'databossid',
                label         =>'DatabossID',
                group         =>'applinfo',
                dataobjattr   =>'appl.databoss'),

      new kernel::Field::Text(
                name          =>'applapplid',
                label         =>'ApplicationID',
                readonly      =>1,
                uploadable    =>0,
                group         =>'applinfo',
                dataobjattr   =>'appl.applid'),

      new kernel::Field::TextDrop(
                name          =>'customer',
                label         =>'Customer',
                readonly      =>1,
                group         =>'applinfo',
                translation   =>'itil::appl',
                vjointo       =>'base::grp',
                vjoineditbase =>{'cistatusid'=>[3,4]},
                vjoinon       =>['customerid'=>'grpid'],
                vjoindisp     =>'fullname'),
                                                   
      new kernel::Field::Text(
                name          =>'applcustomerprio',
                label         =>'Customers Application Prioritiy',
                readonly      =>1,
                translation   =>'itil::appl',
                group         =>'applinfo',
                dataobjattr   =>'appl.customerprio'),

      new kernel::Field::Link(
                name          =>'applcistatusid',
                label         =>'ApplCiStatusID',
                dataobjattr   =>'appl.cistatus'),

      new kernel::Field::Link(
                name          =>'customerid',
                label         =>'CustomerID',
                dataobjattr   =>'appl.customer'),

      new kernel::Field::Link(
                name          =>'applid',
                label         =>'ApplID',
                wrdataobjattr =>'accessurl.appl',
                dataobjattr   =>"if (accessurl.appl is not null,accessurl.appl,".
                                "lnkapplappl.fromappl)"),

      new kernel::Field::Date(
                name          =>'expiration',
                label         =>'Expiration-Date',
                group         =>'source',
                htmldetail    =>'NotEmpty',
                dataobjattr   =>'accessurl.expiration'),

      new kernel::Field::QualityText(),
      new kernel::Field::IssueState(),
      new kernel::Field::QualityState(),
      new kernel::Field::QualityOk(),
      new kernel::Field::QualityLastDate(
                dataobjattr   =>'accessurl.lastqcheck'),
      new kernel::Field::QualityResponseArea(),

   );
   $self->setDefaultView(qw(name network appl applcistatus cdate));
   $self->setWorktable("accessurl");
   return($self);
}

sub getSqlFrom
{
   my $self=shift;
   my $from="accessurl ".
            "left outer join lnkapplappl ".
            "on accessurl.lnkapplappl=lnkapplappl.id ".
            "left outer join appl ".
            "on appl.id=if (accessurl.appl is not null,".
            "accessurl.appl,lnkapplappl.fromappl) ".
            "join (select min(id) ugroupedid ".
                  "from accessurl ".
                  "where (appl is not null or target_is_fromappl=1) ".
                  "group by fullname,network,appl) ugrouped ".
            "on accessurl.id=ugrouped.ugroupedid";
   return($from);
}


sub initSearchQuery
{
   my $self=shift;
   if (!defined(Query->Param("search_applcistatus"))){
     Query->Param("search_applcistatus"=>
                  "\"!".$self->T("CI-Status(6)","base::cistatus")."\"");
   }
}




sub SecureSetFilter
{
   my $self=shift;
   my @flt=@_;

   if (!$self->isDirectFilter(@flt) &&
       !$self->IsMemberOf([qw(admin w5base.itil.appl.read w5base.itil.read)],
                          "RMember")){
      my $userid=$self->getCurrentUserId();
      my @mandators=$self->getMandatorsOf($ENV{REMOTE_USER},"read");
      push(@flt,[
                 {databossid=>\$userid},
                 {mandatorid=>\@mandators},
                ]);
   }
   return($self->SetFilter(@flt));
}




sub Validate
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;
   my $origrec=shift;


   my $name=effVal($oldrec,$newrec,"name");

   my $uri=$self->URLValidate($name);
   if ($uri->{error}) {
      $self->LastMsg(ERROR,$uri->{error});
      return(undef);
   }
   if (effVal($oldrec,$newrec,"hostname") ne $uri->{host}){
         $newrec->{hostname}=$uri->{host};
      }
   if (effVal($oldrec,$newrec,"ipport") ne $uri->{port}){
         $newrec->{ipport}=$uri->{port};
   }

   my $applid=effVal($oldrec,$newrec,"applid");
   if ($applid eq ""){
      $self->LastMsg(ERROR,"no valid application specifed");
      return(undef);
   }
   if ($self->isDataInputFromUserFrontend()){
      if (!$self->isWriteToApplValid($applid)){
         $self->LastMsg(ERROR,"no write access to requested application");
         return(undef);
      }
   }
   if ((!defined($oldrec) ||
        exists($newrec->{is_userfrontend}) ||
        exists($newrec->{is_interface}) ||
        exists($newrec->{is_interal}))
       &&
       (effVal($oldrec,$newrec,"is_userfrontend") eq "0" &&
        effVal($oldrec,$newrec,"is_interface") eq "0" &&
        effVal($oldrec,$newrec,"is_internal") eq "0" )){
      $self->LastMsg(ERROR,"no classification specified");
      return(undef);

   }

   if (effVal($oldrec,$newrec,"name") ne $name){
      $newrec->{name}=$name;
   }
   if (effVal($oldrec,$newrec,"scheme") ne $uri->{scheme}){
      $newrec->{scheme}=$uri->{scheme};
   }
   return(1);
}

sub getDetailBlockPriority
{
   my $self=shift;
   return(
          qw(header default class applinfo urlinfo lastipaddresses source));
}




sub isViewValid
{
   my $self=shift;
   my $rec=shift;
   return("header","default") if (!defined($rec));

   my @l=qw(header default history class applinfo urlinfo source history);

   if ($#{$rec->{lastipaddresses}}!=-1){
      push(@l,"lastipaddresses");
   }

   if ($self->IsMemberOf("admin")){
      push(@l,"qc");
   }
   return(@l);
}

sub isWriteValid
{
   my $self=shift;
   my $rec=shift;

   return(undef) if ($rec->{lnkapplapplid} ne "");

   my $applid=defined($rec) ? $rec->{applid} : undef;

   my $wrok=$self->isWriteToApplValid($applid);

   return("default","class") if ($wrok);
   return(undef);
}


sub isWriteToApplValid
{
   my $self=shift;
   my $applid=shift;

   my $userid=$self->getCurrentUserId();
   my $wrok=0;
   $wrok=1 if (!defined($applid));
  # $wrok=1 if ($self->IsMemberOf("admin"));
   if ($self->itil::lib::Listedit::isWriteOnApplValid($applid,"default")){
      $wrok=1;
   }
   return($wrok);
}











1;
