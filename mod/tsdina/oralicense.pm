package tsdina::oralicense;
#  W5Base Framework
#  Copyright (C) 2014  Hartmut Vogler (it@guru.de)
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
   #$param{MainSearchFieldLines}=4;
   my $self=bless($type->SUPER::new(%param),$type);

   $self->AddFields(
      new kernel::Field::Linenumber(
                name          =>'linenumber',
                htmlwidth     =>'1%',
                label         =>'No.'),

      new kernel::Field::Id(
                name          =>'instanceid',
                label         =>'Instance ID',
                htmldetail    =>0,
                dataobjattr   =>'dina_inst_id'),

      new kernel::Field::Text(
                name          =>'edition',
                label         =>'Edition',
                dataobjattr   =>'edition'),

      new kernel::Field::Date(
                name          =>'monitordate',
                label         =>'Monitor Date',
                dataobjattr   =>'monitor_date'),

      new kernel::Field::Text(
                name          =>'name',
                group         =>'system',
                label         =>'Systemname',
                dataobjattr   =>'host_name'),

      new kernel::Field::Text(
                name          =>'systemid',
                group         =>'system',
                label         =>'SystemID',
                dataobjattr   =>'systemid'),

      new kernel::Field::Text(
                name          =>'platform',
                group         =>'system',
                label         =>'Platform',
                dataobjattr   =>'platform_name'),

      new kernel::Field::Number(
                name          =>'physicalcores',
                group         =>'system',
                label         =>'Physical Cores',
                dataobjattr   =>'numberphysicalcores'),

      new kernel::Field::Number(
                name          =>'onlinevirtcpu',
                group         =>'system',
                label         =>'Online Virtual CPUs',
                dataobjattr   =>'online_virtual_cpus'),

      new kernel::Field::Text(
                name          =>'lpartype',
                group         =>'lpar',
                label         =>'LPAR Type',
                dataobjattr   =>'lpar_type'),

      new kernel::Field::Text(
                name          =>'lparmode',
                group         =>'lpar',
                label         =>'LPAR Mode',
                dataobjattr   =>'lpar_mode'),

      new kernel::Field::Number(
                name          =>'lparsharedpoolid',
                group         =>'lpar',
                label         =>'LPAR Shared Pool ID',
                dataobjattr   =>'lpar_mode'),

   );
   $self->setDefaultView(qw(linenumber name id));

   return($self);
}

sub Initialize
{
   my $self=shift;

   my @result=$self->AddDatabase(DB=>new kernel::database($self,"tsdina"));
   return(@result) if (defined($result[0]) eq "InitERROR");
   return(1) if (defined($self->{DB}));
   return(0);
}

sub getSqlFrom
{
   my $self=shift;
   my $from="darwin_ora_license_info_vw";
   return($from);
}


sub getDetailBlockPriority
{
   my $self=shift;
   my $grp=shift;
   my %param=@_;
   return("header","default");
}

sub isQualityCheckValid
{
   my $self=shift;
   my $rec=shift;
   return(0);
}

sub getRecordImageUrl
{
   my $self=shift;
   my $cgi=new CGI({HTTP_ACCEPT_LANGUAGE=>$ENV{HTTP_ACCEPT_LANGUAGE}});
   return("../../../public/itil/load/licproduct.jpg?".$cgi->query_string());
}

sub isViewValid
{
   my $self=shift;
   my $rec=shift;
   return("ALL");
}

sub isUploadValid
{
   return(undef);
}


1;
