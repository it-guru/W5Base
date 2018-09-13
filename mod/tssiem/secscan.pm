package tssiem::secscan;
#  W5Base Framework
#  Copyright (C) 2018  Hartmut Vogler (it@guru.de)
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
@ISA=qw(kernel::App::Web::Listedit kernel::DataObj::DB);

sub new
{
   my $type=shift;
   my %param=@_;
   $param{MainSearchFieldLines}=3 if (!exists($param{MainSearchFieldLines}));
   my $self=bless($type->SUPER::new(%param),$type);

   $self->AddFields(
      new kernel::Field::Id(
                name          =>'id',
                sqlorder      =>'desc',
                label         =>'ID',
                searchable    =>0,
                group         =>'source',
                dataobjattr   =>"ref"),

      new kernel::Field::Link(
                name          =>'qref',
                label         =>'Qualys Ref',
                group         =>'source',
                dataobjattr   =>"ref"),

      new kernel::Field::Text(
                name          =>'name',
                htmlwidth     =>'200px',
                ignorecase    =>1,
                label         =>'Title',
                dataobjattr   =>"title"),

      new kernel::Field::Text(
                name          =>'ictono',
                label         =>'ICTO-ID',
                dataobjattr   =>"ictoid"),

      new kernel::Field::Text(
                name          =>'stype',
                htmlwidth     =>'200px',
                label         =>'Scan type',
                dataobjattr   =>"type"),

      new kernel::Field::Date(
                name          =>'sdate',
                label         =>'Scan date',
                dataobjattr   =>'launch_datetime'),


      new kernel::Field::Text(
                name          =>'sduration',
                label         =>'Scan duration',
                group         =>'results',
                sqlorder      =>'ASC',
                dataobjattr   =>"to_char(duration,'HH24:MI')"),

      new kernel::Field::SubList(
                name          =>'secents',
                label         =>'Security Entries',
                group         =>'results',
                vjointo       =>'tssiem::secent',
                htmllimit     =>10,
                forwardSearch =>1,
                vjoinbase     =>[{pci_vuln=>'yes'}],
                vjoinon       =>['qref'=>'qref'],
                vjoindisp     =>['ipaddress','name']),

      new kernel::Field::Number(
                name          =>'secentcnt',
                label         =>'SecEnt count',
                readonly      =>1,
                group         =>'results',
                htmldetail    =>0,
                uploadable    =>0,
                dataobjattr   =>"(select count(*) from W5SIEM_secent ".
                                "where W5SIEM_secscan.ref=W5SIEM_secent.ref ".
                                " and W5SIEM_secent.pci_vuln='yes')"),

      new kernel::Field::Textarea(
                name          =>'starget',
                label         =>'Scan Target',
                dataobjattr   =>"target"),

      new kernel::Field::File(
                name          =>'pdfstdfull',
                label         =>'PDF Report Standard Full',
                searchable    =>0,
                uploadable    =>0,
                readonly      =>1,
                htmldetail    =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   if (defined($param{current}) &&
                       $param{current}->{pdfstdfull_valid}){
                      return(1);
                   }
                   return(0);
                },
                types         =>['pdf'],
                mimetype      =>'pdfstdfull_mime',
                filename      =>'pdfstdfull_name',
                group         =>'results',
                dataobjattr   =>'pdfstdfull'),

      new kernel::Field::Link(
                name          =>'pdfstdfull_mime',
                label         =>'PDF Standard Full mime',
                group         =>'results',
                dataobjattr   =>"'application/pdf'"),

      new kernel::Field::Boolean(
                name          =>'pdfstdfull_valid',
                selectfix     =>'1',
                htmldetail    =>0,
                group         =>'results',
                label         =>'PDF Standard Full valid',
                dataobjattr   =>"decode(pdfstdfull_level,'2',1,0)"),

      new kernel::Field::Link(
                name          =>'pdfstdfull_name',
                label         =>'PDF Standard Full name',
                group         =>'results',
                dataobjattr   =>"('Qualys_'||ictoid||".
                                "'_'||".
                                "to_char(launch_datetime,'YYYYMMDDHH24MISS')||".
                                "'_standard_full'||'.pdf')"),

      new kernel::Field::File(
                name          =>'pdfstddelta',
                label         =>'PDF Report Standard Delta',
                searchable    =>0,
                uploadable    =>0,
                readonly      =>1,
                htmldetail    =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   if (defined($param{current}) &&
                       $param{current}->{pdfstddelta_valid}){
                      return(1);
                   }
                   return(0);
                },
                types         =>['pdf'],
                mimetype      =>'pdfstddelta_mime',
                filename      =>'pdfstddelta_name',
                group         =>'results',
                dataobjattr   =>'pdfstddelta'),

      new kernel::Field::Link(
                name          =>'pdfstddelta_mime',
                label         =>'PDF Standard Delta mime',
                group         =>'results',
                dataobjattr   =>"'application/pdf'"),

      new kernel::Field::Boolean(
                name          =>'pdfstddelta_valid',
                selectfix     =>'1',
                htmldetail    =>0,
                group         =>'results',
                label         =>'PDF Standard Delta valid',
                dataobjattr   =>"decode(pdfstddelta_level,'2',1,0)"),

      new kernel::Field::Link(
                name          =>'pdfstddelta_name',
                label         =>'PDF Standard Delta name',
                group         =>'results',
                dataobjattr   =>"('Qualys_'||ictoid||".
                                "'_'||".
                                "to_char(launch_datetime,'YYYYMMDDHH24MISS')||".
                                "'_standard_delta'||'.pdf')"),

      new kernel::Field::File(
                name          =>'pdfvfwifull',
                label         =>'PDF Report SmiplifiedFW Full',
                searchable    =>0,
                uploadable    =>0,
                readonly      =>1,
                htmldetail    =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   if (defined($param{current}) &&
                       $param{current}->{pdfvfwifull_valid}){
                      return(1);
                   }
                   return(0);
                },
                types         =>['pdf'],
                mimetype      =>'pdfvfwifull_mime',
                filename      =>'pdfvfwifull_name',
                group         =>'results',
                dataobjattr   =>'pdfvfwifull'),

      new kernel::Field::Link(
                name          =>'pdfvfwifull_mime',
                label         =>'PDF SmiplifiedFW Full mime',
                group         =>'results',
                dataobjattr   =>"'application/pdf'"),

      new kernel::Field::Boolean(
                name          =>'pdfvfwifull_valid',
                selectfix     =>'1',
                htmldetail    =>0,
                group         =>'results',
                label         =>'PDF SmiplifiedFW Full valid',
                dataobjattr   =>"decode(pdfvfwifull_level,'2',1,0)"),

      new kernel::Field::Link(
                name          =>'pdfvfwifull_name',
                label         =>'PDF SmiplifiedFW Full name',
                group         =>'results',
                dataobjattr   =>"('Qualys_'||ictoid||".
                                "'_'||".
                                "to_char(launch_datetime,'YYYYMMDDHH24MISS')||".
                                "'_SmiplifiedFW_full'||'.pdf')"),

      new kernel::Field::File(
                name          =>'pdfvfwidelta',
                label         =>'PDF Report SmiplifiedFW Delta',
                searchable    =>0,
                uploadable    =>0,
                readonly      =>1,
                htmldetail    =>sub{
                   my $self=shift;
                   my $mode=shift;
                   my %param=@_;
                   if (defined($param{current}) &&
                       $param{current}->{pdfvfwidelta_valid}){
                      return(1);
                   }
                   return(0);
                },
                types         =>['pdf'],
                mimetype      =>'pdfvfwidelta_mime',
                filename      =>'pdfvfwidelta_name',
                group         =>'results',
                dataobjattr   =>'pdfvfwidelta'),

      new kernel::Field::Link(
                name          =>'pdfvfwidelta_mime',
                label         =>'PDF SmiplifiedFW Delta mime',
                group         =>'results',
                dataobjattr   =>"'application/pdf'"),

      new kernel::Field::Boolean(
                name          =>'pdfvfwidelta_valid',
                selectfix     =>'1',
                htmldetail    =>0,
                group         =>'results',
                label         =>'PDF SmiplifiedFW Delta valid',
                dataobjattr   =>"decode(pdfvfwidelta_level,'2',1,0)"),

      new kernel::Field::Link(
                name          =>'pdfvfwidelta_name',
                label         =>'PDF SmiplifiedFW Delta name',
                group         =>'results',
                dataobjattr   =>"('Qualys_'||ictoid||".
                                "'_'||".
                                "to_char(launch_datetime,'YYYYMMDDHH24MISS')||".
                                "'_SmiplifiedFW_delta'||'.pdf')"),

      new kernel::Field::TextDrop(
                name          =>'applmgr',
                group         =>'contact',
                label         =>'ApplicationManager',
                vjointo       =>'TS::appl',
                weblinkto     =>'NONE',
                vjoinbase     =>{cistatusid=>"<6",applmgrid=>'!""'},
                vjoinon       =>['ictono'=>'ictono'],
                vjoindisp     =>'applmgr'),

      new kernel::Field::Text(
                name          =>'srcsys',
                group         =>'source',
                label         =>'Source-System',
                dataobjattr   =>"'Qualys'"),

      new kernel::Field::Text(
                name          =>'srcid',
                group         =>'source',
                label         =>'Source-Id',
                dataobjattr   =>'ref'),

      new kernel::Field::Date(
                name          =>'srcload',
                history       =>0,
                group         =>'source',
                label         =>'Source-Load',
                dataobjattr   =>'importdate'),

   );
   $self->{use_distinct}=0;
   $self->setDefaultView(qw(sdate ictono name sduration secentcnt));
   $self->setWorktable("W5SIEM_secscan");
   return($self);
}


sub Initialize
{
   my $self=shift;

   my @result=$self->AddDatabase(DB=>new kernel::database($self,"w5warehouse"));
   return(@result) if (defined($result[0]) eq "InitERROR");
   return(1) if (defined($self->{DB}));
   return(0);
}

#sub initSearchQuery
#{
#   my $self=shift;
#   if (!defined(Query->Param("search_operational"))){
#     Query->Param("search_operational"=>"\"".$self->T("yes")."\"");
#   }
#}


sub addICTOSecureFilter
{
   my $self=shift;
   my $addflt=shift;

   my @mandators=$self->getMandatorsOf($ENV{REMOTE_USER},"read");
   my %grps=$self->getGroupsOf($ENV{REMOTE_USER},
            [orgRoles(),qw(RMember RCFManager RCFManager2 RAuditor RMonitor)],
            "both");
   my @grpids=keys(%grps);
   my $userid=$self->getCurrentUserId();

   my $appl=$self->getPersistentModuleObject("TS::appl");
   $appl->SetFilter({cistatusid=>"<6",
                     applmgrid=>\$userid});
   my @l=$appl->getHashList(qw(ictoid ictono));
   my %ictono=();
   map({$ictono{$_->{ictono}}++ } @l);
   if ($ENV{REMOTE_USER} ne "anonymous" && keys(%ictono)>0){
      push(@$addflt,
                 {ictono=>[keys(%ictono)]}
      );
   }
   else{
      push(@$addflt,
                 {ictono=>['-99']}
      );
   }
}



sub SecureSetFilter
{
   my $self=shift;
   my @flt=@_;

   if (!$self->IsMemberOf([qw(admin w5base.tssiem.secscan.read)],
                          "RMember")){
      my @addflt;
      $self->addICTOSecureFilter(\@addflt);
      push(@flt,\@addflt);
   }
   return($self->SetFilter(@flt));
}





sub getDetailBlockPriority
{
   my $self=shift;
   my $grp=shift;
   my %param=@_;
   return("header","default",'contact',"results","source");
}


sub getRecordImageUrl
{
   my $self=shift;
   my $cgi=new CGI({HTTP_ACCEPT_LANGUAGE=>$ENV{HTTP_ACCEPT_LANGUAGE}});
   return("../../../public/tssiem/load/qualys_secscan.jpg?".$cgi->query_string());
}


sub isQualityCheckValid
{
   my $self=shift;
   my $rec=shift;
   return(0);
}




sub isWriteValid
{
   my $self=shift;
   my $rec=shift;
   return(undef);
}

         



1;
