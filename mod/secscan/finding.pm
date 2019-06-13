package secscan::finding;
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
use kernel::App::Web;
use kernel::DataObj::DB;
use kernel::Field;
use tsacinv::system;
@ISA=qw(kernel::App::Web::Listedit kernel::DataObj::DB);

=head1

#
# Generierung der Support-Views in der pw5repo Kennung


create or replace view "W5I_secscan__findingbase" as
select  'OpSha-' || "w5secscan_ShareData"."W5_id"             as id,
        "w5secscan_ShareData"."W5_isdel"                      as isdel,
        "w5secscan_ShareData"."C01_SecToken"                  as sectoken,
        "w5secscan_ShareData"."C05_SecItem"                   as secitem,
        "w5secscan_ShareData"."C04_TreadRules"                as sectreadrules,
        TO_DATE("w5secscan_ShareData"."C02_ScanDate",
                'YYYY-MM-DD HH24:MI:SS')                      as fndscandate,
        "w5secscan_ShareData"."W5_cdate"                      as fndcdate,
        "w5secscan_ShareData"."W5_mdate"                      as fndmdate,
        LOWER(REPLACE(REGEXP_SUBSTR(
              "w5secscan_ShareData"."C03_HostName",
              '^.*?\.'),'.',''))                              as hostname,
        "W5FTPGW1"."w5secscan_ShareData"."C03_HostName"       as fqdns,
        "w5secscan_ComputerIP"."C02_IPAddress"                as ipaddr,
        'Share=' || "w5secscan_ShareData"."C06_ShareName" || 
         chr(13) ||
        'Files=' || "w5secscan_ShareData"."C09_foundFiles" ||
         chr(13) ||
        'Items=' || "w5secscan_ShareData"."C08_foundItems"    as detailspec,
        'w5sharescan'                                         as srcsys,
        "w5secscan_ShareData"."W5_id"                         as srcid
from "W5FTPGW1"."w5secscan_ShareData"
   join "W5FTPGW1"."w5secscan_ComputerIP"
      on "w5secscan_ComputerIP"."C01_NetComputer"=
         "w5secscan_ShareData"."C03_HostName";


create table "W5I_secscan__finding_of" (
   refid               varchar2(80) not null,
   comments            varchar2(4000),
   wfhandeled          number(*,0) default '0',
   wfref               varchar2(256),
   respemail           varchar2(128),
   modifyuser          number(*,0),
   modifydate          date,
   constraint "W5I_secscan_finding_of_pk" primary key (refid)
);

grant select,update,insert on "W5I_secscan__finding_of" to W5I;
create or replace synonym W5I.secscan__finding_of for "W5I_secscan__finding_of";


create or replace view "W5I_secscan__finding" as
select "W5I_secscan__findingbase".id,
       "W5I_secscan__findingbase".isdel,
       "W5I_secscan__findingbase".sectoken,
       "W5I_secscan__findingbase".secitem,
       "W5I_secscan__findingbase".sectreadrules,
       "W5I_secscan__findingbase".fndscandate,
       "W5I_secscan__findingbase".fndcdate,
       "W5I_secscan__findingbase".fndmdate,
       "W5I_secscan__findingbase".hostname,
       "W5I_secscan__findingbase".fqdns,
       "W5I_secscan__findingbase".ipaddr,
       "W5I_secscan__findingbase".detailspec,
       "W5I_secscan__findingbase".srcsys,
       "W5I_secscan__findingbase".srcid,
       "W5I_secscan__finding_of".refid of_id,
       "W5I_secscan__finding_of".comments,
       decode("W5I_secscan__finding_of".wfhandeled,
              NULL,'0',"W5I_secscan__finding_of".wfhandeled) wfhandeled,
       "W5I_secscan__finding_of".wfref,
       "W5I_secscan__finding_of".respemail,
       "W5I_secscan__finding_of".modifyuser,
       "W5I_secscan__finding_of".modifydate
from "W5I_secscan__findingbase"
     left outer join "W5I_secscan__finding_of"
        on "W5I_secscan__findingbase".id=
           "W5I_secscan__finding_of".refid;


grant select on "W5I_secscan__finding" to W5I;
create or replace synonym W5I.secscan__finding for "W5I_secscan__finding";


=cut

sub new
{
   my $type=shift;
   my %param=@_;
   $param{MainSearchFieldLines}=4;
   my $self=bless($type->SUPER::new(%param),$type);
   $self->{useMenuFullnameAsACL}=$self->Self();

   
   $self->AddFields(
      new kernel::Field::Linenumber(
                name          =>'linenumber',
                label         =>'No.'),

      new kernel::Field::Id(
                name          =>'id',
                label         =>'ID',
                group         =>'source',
                align         =>'left',
                history       =>0,
                htmldetail    =>0,
                dataobjattr   =>"id",
                wrdataobjattr =>"refid"),

      new kernel::Field::Text(
                name          =>'name',
                label         =>'Security Token',
                lowersearch   =>1,
                size          =>'16',
                readonly      =>1,
                dataobjattr   =>'sectoken'),

      new kernel::Field::Boolean(
                name          =>'isdel',
                group         =>'source',
                label         =>'marked as deleted',
                dataobjattr   =>'isdel'),

      new kernel::Field::Text(
                name          =>'secitem',
                label         =>'SecurityItem',
                group         =>'source',
                selectfix     =>1,
                readonly      =>1,
                dataobjattr   =>'secitem'),

      new kernel::Field::Text(
                name          =>'sectreadrules',
                label         =>'TreadRules',
                group         =>'source',
                selectfix     =>1,
                readonly      =>1,
                dataobjattr   =>'sectreadrules'),

      new kernel::Field::Date(
                name          =>'findscandate',
                sqlorder      =>'desc',
                label         =>'Scan-Date',
                dataobjattr   =>'fndscandate'),

      new kernel::Field::Date(
                name          =>'findcdate',
                sqlorder      =>'desc',
                group         =>'source',
                label         =>'Create-Date',
                dataobjattr   =>'fndcdate'),

      new kernel::Field::Text(
                name          =>'hostname',
                label         =>'Systemname',
                dataobjattr   =>'hostname'),

      new kernel::Field::Text(
                name          =>'fqdns',
                label         =>'fullqualified DNS',
                dataobjattr   =>'fqdns'),

      new kernel::Field::Text(
                name          =>'ipaddr',
                label         =>'IP-Address',
                dataobjattr   =>'ipaddr'),

      new kernel::Field::Textarea(
                name          =>'spec',
                readonly      =>1,
                label         =>'Specification',
                searchable    =>0,
                onRawValue    =>sub{
                   my $self=shift;
                   my $current=shift;
                   my $app=$self->getParent;
                   my $d=trim($app->T($current->{secitem},"secscan::item"));
                   $d.="\n";
                   $d.=$current->{detailspec};
                   return($d);
                }),

      new kernel::Field::Textarea(
                name          =>'detailspec',
                htmldetail    =>0,
                readonly      =>1,
                selectfix     =>1,
                label         =>'Detail-Spec',
                dataobjattr   =>'detailspec'),

      new kernel::Field::Date(
                name          =>'findmdate',
                sqlorder      =>'desc',
                group         =>'source',
                label         =>'Modification-Date',
                dataobjattr   =>'fndmdate'),

      new kernel::Field::Link(
                name          =>'ofid',
                label         =>'Overflow ID',
                dataobjattr   =>'of_id'),

      new kernel::Field::Textarea(
                name          =>'comments',
                group         =>'handling',
                label         =>'Comments',
                dataobjattr   =>'comments'),

      new kernel::Field::MDate(
                name          =>'mdate',
                group         =>'handlingsource',
                sqlorder      =>'desc',
                label         =>'Modification-Date',
                dataobjattr   =>'modifydate'),

      new kernel::Field::Owner(
                name          =>'owner',
                history       =>0,
                group         =>'handlingsource',
                label         =>'last Editor',
                dataobjattr   =>'modifyuser'),

      new kernel::Field::Text(
                name          =>'srcsys',
                selectfix     =>1,
                group         =>'source',
                label         =>'Source-System',
                dataobjattr   =>'srcsys'),

      new kernel::Field::Text(
                name          =>'srcid',
                group         =>'source',
                htmldetail    =>'NotEmpty',
                label         =>'Source-Id',
                dataobjattr   =>'srcid')
   );
   $self->{history}={
      update=>[
         'local'
      ],
      insert=>[
         'local'
      ]
   };

   $self->setWorktable("secscan__finding_of");
   $self->setDefaultView(qw(name secitem comments));
   return($self);
}



sub getSqlFrom
{
   my $self=shift;
   my $mode=shift;
   my @flt=@_;
   my $from="secscan__finding";

   return($from);
}

sub getDetailBlockPriority
{
   my $self=shift;
   return( qw(header default handling handlingsource source));
}


sub ValidatedUpdateRecord
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;
   my @filter=@_;

   $filter[0]={id=>\$oldrec->{id}};
   if (!defined($oldrec->{ofid})){ 
      $newrec->{id}=$oldrec->{id}; 
      return($self->SUPER::ValidatedInsertRecord($newrec));
   }
   return($self->SUPER::ValidatedUpdateRecord($oldrec,$newrec,@filter));
}


sub Validate
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;
   my $orgrec=shift;


   return(1);
}





sub Initialize
{
   my $self=shift;

   my @result=$self->AddDatabase(DB=>new kernel::database($self,"w5warehouse"));
   return(@result) if (defined($result[0]) eq "InitERROR");
   return(1) if (defined($self->{DB}));
   return(0);
}


sub initSearchQuery
{
   my $self=shift;

   if (!defined(Query->Param("search_isdel"))){
     Query->Param("search_isdel"=>"\"".$self->T("no")."\"");
   }

}


sub isViewValid
{
   my $self=shift;
   my $rec=shift;

   if ($self->IsMemberOf(["admin",
                          "w5base.secscan.read",
                          "w5base.secscan.write"])){
      return(qw(ALL));
   }
   return(undef);
}


sub isWriteValid
{
   my $self=shift;
   my $rec=shift;  # if $rec is not defined, insert is validated

   if ($self->IsMemberOf(["admin",
                          "w5base.secscan.write"])){
      return("handling");
   }
   return(undef);
}

sub isDeleteValid
{
   my $self=shift;
   my $rec=shift;

   return(0);
}


sub isQualityCheckValid
{
   my $self=shift;
   my $rec=shift;
   return(0);
}








1;
