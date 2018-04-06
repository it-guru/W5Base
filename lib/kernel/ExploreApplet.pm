package kernel::ExploreApplet;
#  W5Base Framework
#  Copyright (C) 2017  Hartmut Vogler (it@guru.de)
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
#
use vars qw(@ISA);
use strict;
use kernel;
use kernel::Universal;

@ISA=qw(kernel::Universal);

sub new
{
   my $type=shift;
   my $self=bless({@_},$type);
   return($self);
}



sub getObjectPrio
{
   my $self=shift;
   my $app=shift;
   my $lang=shift;

   return(500);
}



sub getObjectInfo
{
   my $self=shift;
   my $app=shift;
   my $lang=shift;

   return({
      label=>$app->T($self->Self,$self->Self),
      description=>$app->T("description",$self->Self),
      sublabel=>$app->T("sublabel",$self->Self),
      prio=>$self->getObjectPrio($app,$lang)
   });
}


1;

