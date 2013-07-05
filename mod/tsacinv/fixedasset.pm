package tsacinv::fixedasset;
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
use Data::Dumper;
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

      new kernel::Field::Id(
                name          =>'name',
                label         =>'FixedAssetId',
                size          =>'20',
                uppersearch   =>1,
                align         =>'left',
                dataobjattr   =>'amfixedasset.fixedastno'),

      new kernel::Field::Text(
                name          =>'description',
                htmlwidth     =>'250px',
                label         =>'Name',
                dataobjattr   =>'amfixedasset.name'),

      new kernel::Field::Text(
                name          =>'assetid',
                label         =>'AssetId',
                size          =>'20',
                uppersearch   =>1,
                align         =>'left',
                dataobjattr   =>'amfixedasset.assettag'),

      new kernel::Field::Date(
                name          =>'deprstart',
                label         =>'Deprecation Start',
                htmlwidth     =>'80px',
                timezone      =>'CET',
                dataobjattr   =>'amfixedasset.ddeprstart'),

      new kernel::Field::Date(
                name          =>'deprend',
                label         =>'Deprecation End',
                htmlwidth     =>'80px',
                timezone      =>'CET',
                dataobjattr   =>'amfixedasset.ddeprend'),

      new kernel::Field::Currency(
                name          =>'deprbase',
                htmlwidth     =>'80px',
                label         =>'Deprecation Base',
                dataobjattr   =>'amfixedasset.mdeprbasis'),

      new kernel::Field::Currency(
                name          =>'residualvalue',
                label         =>'residual value',
                size          =>'20',
                dataobjattr   =>'amfixedasset.mresidualvalue'),

      new kernel::Field::Currency(
                name          =>'deprrate',
                label         =>'monthly Deprecation',
                dataobjattr   =>'amfixedasset.mdeprrate'),

      new kernel::Field::Text(
                name          =>'inventoryno',
                label         =>'Inventory No.',
                dataobjattr   =>'amfixedasset.inventoryno'),

      new kernel::Field::Import( $self,
                vjointo       =>'tsacinv::system',
                vjoinon       =>['assetid'=>'assetassetid'],
                group         =>'systemdata',
                vjoinconcat   =>', ',
                fields        =>['systemid','systemname']),

      new kernel::Field::Link(
                name          =>'lassetid',
                noselect      =>'1',
                dataobjattr   =>'amrelfixedasset.lastid'),

   );
   $self->setDefaultView(qw(name assetid deprstart deprend deprbase inventoryno));
   return($self);
}

sub Initialize
{
   my $self=shift;

   my @result=$self->AddDatabase(DB=>new kernel::database($self,"tsac"));
   return(@result) if (defined($result[0]) eq "InitERROR");
   return(1) if (defined($self->{DB}));
   return(0);
}

sub getRecordImageUrl
{
   my $self=shift;
   my $cgi=new CGI({HTTP_ACCEPT_LANGUAGE=>$ENV{HTTP_ACCEPT_LANGUAGE}});
   return("../../../public/itil/load/fixedasset.jpg?".$cgi->query_string());
}

sub getSqlFrom
{
   my $self=shift;
   my $from="amfixedasset,amrelfixedasset";
   return($from);
}

sub initSqlWhere
{
   my $self=shift;
   my $where="amfixedasset.lfixedastid=amrelfixedasset.lfixedastid and ".
             "amfixedasset.bdelete='0'";
   #my $where="amfixedasset.bdelete='0' and amfixedasset.legalunit is not null";
   return($where);
}

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
