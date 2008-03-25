package itil::workflow::base;
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
use kernel::WfClass;
@ISA=qw(kernel::WfClass);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);
   return($self);
}

sub Init
{
   my $self=shift;
   my $parent=$self->getParent();

   $parent->AddFields(
      new kernel::Field::Text( 
                name       =>'involvedresponseteam',
                htmldetail =>0,
                searchable =>0,
                container  =>'headref',
                group      =>'affected',
                label      =>'Involved Response Team'),

      new kernel::Field::Text( 
                name       =>'involvedbusinessteam',
                htmldetail =>0,
                searchable =>0,
                container  =>'headref',
                group      =>'affected',
                label      =>'Involved Business Team'),

      new kernel::Field::Text( 
                name       =>'involvedcustomer',
                htmldetail =>0,
                searchable =>0,
                container  =>'headref',
                group      =>'affected',
                label      =>'Involved Customer'),

      new kernel::Field::Text( 
                name       =>'involvedcostcenter',
                htmldetail =>0,
                searchable =>0,
                container  =>'headref',
                group      =>'affected',
                label      =>'Involved CostCenter'),

      new kernel::Field::KeyText( 
                name       =>'affectedcontract',
                translation=>'itil::workflow::base',
                keyhandler =>'kh',
                weblinkto  =>'itil::custcontract',
                weblinkon  =>['name'],
                container  =>'headref',
                group      =>'affected',
                label      =>'Affected Customer Contract'),

      new kernel::Field::KeyText( 
                name       =>'affectedcontractid',
                htmldetail =>0,
                translation=>'itil::workflow::base',
                searchable =>0,
                keyhandler =>'kh',
                container  =>'headref',
                group      =>'affected',
                label      =>'Affected Customer Contract ID'),

      new kernel::Field::KeyText( 
                name       =>'affectedapplication',
                translation=>'itil::workflow::base',
                keyhandler =>'kh',
                weblinkto  =>'itil::appl',
                weblinkon  =>['name'],
                container  =>'headref',
                group      =>'affected',
                label      =>'Affected Application'),

      new kernel::Field::KeyText(
                name       =>'affectedapplicationid',
                htmldetail =>0,
                translation=>'itil::workflow::base',
                searchable =>0,
                keyhandler =>'kh',
                container  =>'headref',
                group      =>'affected',
                label      =>'Affected Application ID'),

      new kernel::Field::KeyText( 
                name       =>'affectedsystem',
                translation=>'itil::workflow::base',
                keyhandler =>'kh',
                weblinkto  =>'itil::system',
                weblinkon  =>['name'],
                container  =>'headref',
                group      =>'affected',
                label      =>'Affected System'),

      new kernel::Field::KeyText( 
                name       =>'affectedsystemid',
                translation=>'itil::workflow::base',
                htmldetail =>0,
                searchable =>0,
                keyhandler =>'kh',
                container  =>'headref',
                group      =>'affected',
                label      =>'Affected System ID'),

   );
   $self->AddGroup("affected",translation=>'itil::workflow::base');

   return(0);
}


1;
