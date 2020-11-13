package itil::lnkadditionalci;
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
@ISA=qw(kernel::App::Web::Listedit kernel::DataObj::DB);

sub new
{
   my $type=shift;
   my %param=@_;
   $param{MainSearchFieldLines}=4 if (!defined($param{MainSearchFieldLines}));
   my $self=bless($type->SUPER::new(%param),$type);
   

   $self->AddFields(
      new kernel::Field::Id(
                name          =>'id',
                label         =>'LinkID',
                searchable    =>0,
                dataobjattr   =>'addci.id'),
                                                 
      new kernel::Field::Text(
                name          =>'name',
                label         =>'CI-Name',
                htmlwidth     =>'400px',
                weblinkto     =>sub{
                                  my $self=shift;
                                  my $d=shift;
                                  my $current=shift;
                                  return("none",undef) if (!defined($current));

                                  if ($current->{target} ne "" &&
                                      $current->{targetid} ne ""){
                                     return($current->{target},
                                            ['targetid'=>'id']);
                                  }
                                  return("none",undef);
                                },
                dataobjattr   =>'addci.name'),
                                                   
      new kernel::Field::Text(
                name          =>'ciusage',
                label         =>'CI-Usage',
                dataobjattr   =>'addci.ciusage'),
                                                   
      new kernel::Field::TextDrop(
                name          =>'appl',
                htmlwidth     =>'100px',
                label         =>'Application',
                vjointo       =>'itil::appl',
                vjoinon       =>['applid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Link(
                name          =>'target',
                selectfix     =>1,
                label         =>'target object',
                dataobjattr   =>'addci.target'),

      new kernel::Field::Link(
                name          =>'targetid',
                selectfix     =>1,
                label         =>'target objectid',
                dataobjattr   =>'addci.targetid'),

      new kernel::Field::Link(
                name          =>'applid',
                label         =>'Link to applid',
                dataobjattr   =>'addci.appl'),

      new kernel::Field::TextDrop(
                name          =>'system',
                htmlwidth     =>'100px',
                label         =>'System',
                vjointo       =>'itil::system',
                vjoinon       =>['systemid'=>'id'],
                vjoindisp     =>'name'),

      new kernel::Field::Link(
                name          =>'systemid',
                label         =>'Link to systemid',
                dataobjattr   =>'addci.system'),

      new kernel::Field::Textarea(
                name          =>'comments',
                searchable    =>0,
                group         =>'misc',
                label         =>'Comments',
                dataobjattr   =>'addci.comments'),

      new kernel::Field::Creator(
                name          =>'creator',
                group         =>'source',
                label         =>'Creator',
                dataobjattr   =>'addci.createuser'),
                                   
      new kernel::Field::Owner(
                name          =>'owner',
                group         =>'source',
                label         =>'last Editor',
                dataobjattr   =>'addci.modifyuser'),
                                   
      new kernel::Field::Text(
                name          =>'srcsys',
                group         =>'source',
                label         =>'Source-System',
                dataobjattr   =>'addci.srcsys'),
                                                   
      new kernel::Field::Text(
                name          =>'srcid',
                group         =>'source',
                label         =>'Source-Id',
                dataobjattr   =>'addci.srcid'),
                                                   
      new kernel::Field::Date(
                name          =>'srcload',
                group         =>'source',
                label         =>'Last-Load',
                dataobjattr   =>'addci.srcload'),
                                                   
      new kernel::Field::CDate(
                name          =>'cdate',
                group         =>'source',
                label         =>'Creation-Date',
                dataobjattr   =>'addci.createdate'),
                                                
      new kernel::Field::MDate(
                name          =>'mdate',
                group         =>'source',
                label         =>'Modification-Date',
                dataobjattr   =>'addci.modifydate'),
                                                   
      new kernel::Field::Editor(
                name          =>'editor',
                group         =>'source',
                label         =>'Editor Account',
                dataobjattr   =>'addci.editor'),
                                                  
      new kernel::Field::RealEditor(
                name          =>'realeditor',
                group         =>'source',
                label         =>'real Editor Account',
                dataobjattr   =>'addci.realeditor'),
                                                   
   );
   $self->setDefaultView(qw(id name ciusage appl srcsys srcid));

   $self->setWorktable("lnkadditionalci");
   return($self);
}


sub getSqlFrom
{
   my $self=shift;
   my $mode=shift;
   my @filter=@_;

   my $from="
      (select id,
             appl,system,swinstance,name,ciusage,comments,
             target,targetid,
             createdate,modifydate,createuser,modifyuser,editor,realeditor,
             srcsys,srcid,srcload
       from lnkadditionalci
       union
       select null id,
              appl.id appl,
              null system,
              swinstance.id swinstance,
              swinstance.fullname name,
              swinstancerule.ruletype ciusage,
              null comments,
              'itil::swinstance' target,
              swinstancerule.swinstance targetid,
              swinstancerule.createdate createdate,
              swinstancerule.modifydate modifydate,
              swinstancerule.createuser createuser,
              swinstancerule.modifyuser modifyuser,
              swinstancerule.editor editor,
              swinstancerule.realeditor realeditor,
              'itil::swinstancerule' srcsys,
              swinstancerule.id srcid,
              now() srcload
        from swinstancerule 
           join appl 
              on swinstancerule.refid=appl.id
           join swinstance 
              on swinstancerule.swinstance=swinstance.id
        where parentobj='itil::appl' and swinstance.cistatus in (3,4,5)
     ) addci";
   return($from);
}


sub Validate
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;
   my $origrec=shift;

   return(1);
}


sub isViewValid
{
   my $self=shift;
   my $rec=shift;
   return("default","header") if (!defined($rec));
   return("ALL");
}

sub isWriteValid
{
   my $self=shift;
   my $rec=shift;

   return(undef);  # Write access only allowed for server processes
}


sub getDetailBlockPriority
{
   my $self=shift;
   return(qw(header default misc link source));
}








1;
