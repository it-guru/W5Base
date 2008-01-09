package tsacinv::menu::root;
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
use Data::Dumper;
use kernel;
use kernel::MenuRegistry;
@ISA=qw(kernel::MenuRegistry);

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

   $self->RegisterObj("ac",
                      "tmpl/welcome",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.appl",
                      "tsacinv::appl",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.appl.lnkapplappl",
                      "tsacinv::lnkapplappl",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.appl.lnkapplsystem",
                      "tsacinv::lnkapplsystem",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.system",
                      "tsacinv::system",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.system.ipaddress",
                      "tsacinv::ipaddress",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.asset",
                      "tsacinv::asset",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.asset.fixedasset",
                      "tsacinv::fixedasset",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.user",
                      "tsacinv::user",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.user.groups",
                      "tsacinv::lnkusergroup",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.group",
                      "tsacinv::group",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.krn",
                      "tmpl/welcome",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.krn.mandator",
                      "tsacinv::mandator",
                      defaultacl=>['admin']);
   
   $self->RegisterObj("ac.krn.model",
                      "tsacinv::model",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.krn.service",
                      "tsacinv::service",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.krn.location",
                      "tsacinv::location",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.krn.costcenter",
                      "tsacinv::costcenter",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.krn.customer",
                      "tsacinv::customer",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.krn.accountno",
                      "tsacinv::accountno",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.quality",
                      "tsacinv::quality_appl",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("ac.quality.appl",
                      "tsacinv::quality_appl",
                      defaultacl=>['valid_user']);
   
   return(1);
}




1;
