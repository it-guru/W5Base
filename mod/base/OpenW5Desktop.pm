package base::OpenW5Desktop;
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
use strict;
use vars qw(@ISA);
use kernel;
use kernel::App::Web;
use JSON;
@ISA=qw(kernel::App::Web);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);
   $self->LoadSubObjsOnDemand("OpenW5Desktop","OpenW5Desktop");
   return($self);
}

sub getValidWebFunctions
{
   my ($self)=@_;
   return(qw(Main jsApplets));
}


#
# OpenW5Desktop Engine
#

sub Main
{
   my ($self)=@_;

   print $self->HttpHeader("text/html",charset=>'UTF-8');

   my $getAppTitleBar=$self->getAppTitleBar();
   my $BASE=$ENV{REQUEST_URI};
   $BASE=~s#/OpenW5Desktop/Main.*?$#/OpenW5Desktop/Main#;

   my $opt={
      static=>{
         BASE=>$BASE
      }
   };

   my $prog=$self->getParsedTemplate("tmpl/base.OpenW5Desktop.js",$opt);
   utf8::encode($prog);
   print($prog);
}


1;
