package tsotc::menu::root;
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

   $self->RegisterObj("itu.tsotc",
                      "tmpl/welcome",
                      defaultacl=>['valid_user']);
   
   $self->RegisterObj("itu.tsotc.domain",
                      "tsotc::domain",
                      defaultacl=>['valid_user']);

   $self->RegisterObj("itu.tsotc.project",
                      "tsotc::project",
                      defaultacl=>['valid_user']);

   $self->RegisterObj("itu.tsotc.project.lnksystem",
                      "tsotc::lnkprojectsystem",
                      defaultacl=>['valid_user']);

   $self->RegisterObj("itu.tsotc.system",
                      "tsotc::system",
                      defaultacl=>['valid_user']);

   $self->RegisterObj("itu.tsotc.system.request",
                      "tsotc::sysreq",
                      defaultacl=>['admin']);

   $self->RegisterObj("itu.tsotc.system.request.new",
                      "tsotc::sysreq",
                      func=>'New',
                      defaultacl=>['admin']);

   $self->RegisterObj("itu.tsotc.system.ipaddress",
                      "tsotc::ipaddress",
                      defaultacl=>['valid_user']);

   $self->RegisterObj("itu.tsotc.system.ipaddress",
                      "tsotc::ipaddress",
                      defaultacl=>['valid_user']);

   $self->RegisterObj("itu.tsotc.system.lnkiaascontact",
                      "tsotc::lnksystemiaascontact",
                      defaultacl=>['valid_user']);

   $self->RegisterObj("itu.tsotc.system.lnkiaccontact",
                      "tsotc::lnksystemiaccontact",
                      defaultacl=>['valid_user']);

   $self->RegisterObj("AL_TCom.system.import.OTC",
                      "tsotc::system",
                      func=>'ImportSystem',
                      prio=>30000,
                      defaultacl=>['valid_user']);
   return($self);
}



1;
