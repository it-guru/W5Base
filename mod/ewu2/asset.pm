package ewu2::asset;
#  W5Base Framework
#  Copyright (C) 118  Hartmut Vogler (it@guru.de)
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
   $param{MainSearchFieldLines}=3;

   my $self=bless($type->SUPER::new(%param),$type);
   $self->AddFields(
      new kernel::Field::Linenumber(
                name          =>'linenumber',
                label         =>'No.'),

      new kernel::Field::Id(
                name          =>'id',
                group         =>'source',
                label         =>"DevLabAssetID",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".".
                                "\"PHYSICAL_ELEMENT_ID\""),

      new kernel::Field::Text(
                name          =>'fullname',
                label         =>"full assetname",
                ignorecase    =>1,
                htmldetail    =>0,
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".".
                                "\"COMMON_NAME\" || ' (' || ".
                                "\"PHYSICAL_ELEMENTS\".".
                                "\"PHYSICAL_ELEMENT_ID\" ".
                                "||')'"),

      new kernel::Field::Text(
                name          =>'commonname',
                label         =>"Common Name",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"COMMON_NAME\""),

      new kernel::Field::Text(
                name          =>'model',
                label         =>"Model",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"MODEL\""),

      new kernel::Field::Boolean(
                name          =>'deleted',
                label         =>"marked as delete",
                htmldetail    =>0,
                dataobjattr   =>"decode(\"PHYSICAL_ELEMENTS\".".
                                "\"DELETED_AT\",NULL,0,1)"),
      new kernel::Field::Text(
                name          =>'partnumber',
                uivisible     =>0,
                label         =>"Part Number",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"PART_NUMBER\""),

      new kernel::Field::Text(
                name          =>'serialno',
                label         =>"Serialnumber",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"SERIAL_NUMBER\""),

      new kernel::Field::SubList(
                name          =>'systems',
                label         =>'Systems',
                group         =>'systems',
                vjointo       =>'ewu2::system',
                vjoinon       =>['id'=>'physicalelementid'],
                vjoindisp     =>[qw(systemname status type)]),

      new kernel::Field::Text(
                name          =>'assetowner',
                label         =>"Asset Owner",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"ASSET_OWNER\""),

      new kernel::Field::Text(
                name          =>'assetnumber',
                label         =>"Asset Number",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"ASSET_NUMBER\""),

      new kernel::Field::Text(
                name          =>'location',
                label         =>"Location",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"LOCATION\""),

      new kernel::Field::Date(
                name          =>'ddeliveredat',
                label         =>"Delivered At",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"DELIVERED_AT\""),

      new kernel::Field::Date(
                name          =>'ddecommissionedat',
                label         =>"Decommissioned At",
                htmldetail    =>'NotEmpty',
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"DECOMMISSIONED_AT\""),

      new kernel::Field::Text(
                name          =>'deliverynotelocation',
                uivisible     =>0,
                label         =>"Delivery Note Location",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"DELIVERY_NOTE_LOCATION\""),

      new kernel::Field::Textarea(
                name          =>'notes',
                label         =>"Notes",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"NOTES\""),

      new kernel::Field::Text(
                name          =>'lockversion',
                uivisible     =>0,
                label         =>"Lock Version",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"LOCK_VERSION\""),

      new kernel::Field::Text(
                name          =>'depreciationperiod',
                label         =>"Depreciation Period",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"DEPRECIATION_PERIOD\""),

      new kernel::Field::Text(
                name          =>'paymentperiod',
                label         =>"Payment Period",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"PAYMENT_PERIOD\""),

      new kernel::Field::Text(
                name          =>'utilisationperiod',
                label         =>"Utilisation Period",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"UTILISATION_PERIOD\""),

      new kernel::Field::Date(
                name          =>'dcommissionedat',
                timezone      =>'CET',
                uivisible     =>0,
                label         =>"Commissioned At",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"COMMISSIONED_AT\""),

      new kernel::Field::Text(
                name          =>'ager',
                uivisible     =>0,
                label         =>"Ager",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"AGER\""),

      new kernel::Field::CDate(
                name          =>'cdate',
                group         =>'source',
                timezone      =>'CET',
                label         =>"Creation-Date",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"CREATED_AT\""),

      new kernel::Field::MDate(
                name          =>'mdate',
                group         =>'source',
                timezone      =>'CET',
                label         =>"Modification-Date",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"UPDATED_AT\""),

      new kernel::Field::Date(
                name          =>'ddate',
                group         =>'source',
                timezone      =>'CET',
                htmldetail    =>'NotEmpty',
                label         =>"Deletion-Date",
                dataobjattr   =>"\"PHYSICAL_ELEMENTS\".\"DELETED_AT\""),

   );
   $self->{use_distinct}=0;
   #$self->{workflowlink}={ };
   $self->setDefaultView(qw(linenumber fullname model 
                            serialno location assetnumber));
   $self->setWorktable("\"PHYSICAL_ELEMENTS\"");
   return($self);
}



sub Initialize
{
   my $self=shift;

   my @result=$self->AddDatabase(DB=>new kernel::database($self,"ewu2"));
   return(@result) if (defined($result[0]) eq "InitERROR");
   return(1) if (defined($self->{DB}));
   return(0);
}



sub getDetailBlockPriority
{
   my $self=shift;
   my $grp=shift;
   my %param=@_;
   return("header","default",
          "systems","source");
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
   return("../../../public/itil/load/asset.jpg?".$cgi->query_string());
}



sub initSearchQuery
{
   my $self=shift;
   if (!defined(Query->Param("search_deleted"))){
     Query->Param("search_deleted"=>$self->T("no"));
   }

}



sub isViewValid
{
   my $self=shift;
   my $rec=shift;

   return("ALL");
}


1;

