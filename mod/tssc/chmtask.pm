package tssc::chmtask;
#  W5Base Framework
#  Copyright (C) 2011  Hartmut Vogler (it@guru.de)
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
   my $self=bless($type->SUPER::new(%param),$type);
   
   $self->AddFields(
      new kernel::Field::Linenumber(
                name          =>'linenumber',
                label         =>'No.'),

      new kernel::Field::Text(
                name          =>'changenumber',
                label         =>'Change No.',
                align         =>'left',
                weblinkto     =>'tssc::chm',
                weblinkon     =>['changenumber'=>'changenumber'],
                dataobjattr   =>'cm3tm1.parent_change'),

      new kernel::Field::Id(
                name          =>'tasknumber',
                label         =>'Task No.',
                searchable    =>1,
                align         =>'left',
                dataobjattr   =>'cm3tm1.numberprgn'),

      new kernel::Field::Text(
                name          =>'name',
                label         =>'Task Brief Description',
                ignorecase    =>1,
                dataobjattr   =>'cm3tm1.brief_description'),

      new kernel::Field::Text(
                name          =>'status',
                group         =>'status',
                label         =>'Status',
                ignorecase    =>1,
                dataobjattr   =>'cm3tm1.status'),

      new kernel::Field::Text(
                name          =>'approvalstatus',
                label         =>'approval status',
                group         =>'status',
                ignorecase    =>1,
                dataobjattr   =>'cm3tm1.approval_status'),

      new kernel::Field::Date(
                name          =>'plannedstart',
                timezone      =>'CET',
                label         =>'Planed Start',
                dataobjattr   =>'cm3tm1.planned_start'),

      new kernel::Field::Date(
                name          =>'plannedend',
                timezone      =>'CET',
                label         =>'Planed End',
                dataobjattr   =>'cm3tm1.planned_end'),

      new kernel::Field::Date(
                name          =>'downstart',
                timezone      =>'CET',
                label         =>'Down Start',
                dataobjattr   =>'cm3tm1.down_start'),

      new kernel::Field::Date(
                name          =>'downend',
                timezone      =>'CET',
                label         =>'Down End',
                dataobjattr   =>'cm3tm1.down_end'),

      new kernel::Field::Textarea(
                name          =>'description',
                label         =>'Description',
                searchable    =>0,
                htmlwidth     =>300,
                dataobjattr   =>'cm3tm1.description'),

      new kernel::Field::Text(
                name          =>'assingedto',
                label         =>'Assigned to',
                group         =>'contact',
                ignorecase    =>1,
                dataobjattr   =>'cm3tm1.assigned_to'),

      new kernel::Field::Text(
                name          =>'editor',
                group         =>'status',
                label         =>'Editor',
                dataobjattr   =>'cm3tm1.sysmoduser'),

      new kernel::Field::Date(
                name          =>'sysmodtime',
                group         =>'status',
                timezone      =>'CET',
                label         =>'SysModTime',
                dataobjattr   =>'cm3tm1.sysmodtime'),

      new kernel::Field::Date(
                name          =>'createtime',
                group         =>'status',
                timezone      =>'CET',
                label         =>'Create time',
                dataobjattr   =>'cm3tm1.orig_date_entered'),

   );
   $self->{use_distinct}=1;


   $self->setDefaultView(qw(linenumber changenumber name));
   return($self);
}

sub Initialize
{
   my $self=shift;

   my @result=$self->AddDatabase(DB=>new kernel::database($self,"tssc"));
   return(@result) if (defined($result[0]) eq "InitERROR");
   return(1) if (defined($self->{DB}));
   return(0);
}


sub getSqlFrom
{
   my $self=shift;
   my $from="cm3tm1";
   return($from);
}

#sub initSqlWhere
#{
#   my $self=shift;
#   my $where="not cm3ra25.affected_device is null";
#   return($where);
#}




sub isViewValid
{
   my $self=shift;
   my $rec=shift;
   return("ALL");
}

sub isWriteValid
{
   my $self=shift;
   my $rec=shift;
   return(undef);
}


1;
