package tsotc::event::CloudAreaSync;
#  W5Base Framework
#  Copyright (C) 2019  Hartmut Vogler (it@guru.de)
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
use kernel::Event;
@ISA=qw(kernel::Event);




sub Init
{
   my $self=shift;


   $self->RegisterEvent("CloudAreaSync","CloudAreaSync",timeout=>600);
}




sub CloudAreaSync
{
   my $self=shift;
   my $queryparam=shift;

   my $inscnt=0;

   my @a;
   my %itcloud;

   my $appans=getModuleObject($self->Config,"tsotc::appagilenamespace");
   my $otcpro=getModuleObject($self->Config,"tsotc::project");
   my $itcloudobj=getModuleObject($self->Config,"itil::itcloud");

   if (!($appans->Ping()) ||
       !($otcpro->Ping()) ||
       !($itcloudobj->Ping())){
      msg(ERROR,"not all dataobjects available");
      return(undef);
   }

   $appans->SetFilter({
      cluster=>'![EMPTY]',
      name=>'![EMPTY]'
   });
   foreach my $appansrec ($appans->getHashList(qw(
                           name fullname cluster id applid appl))){
       $itcloud{$appansrec->{cluster}}++;
       my $fullname=$appansrec->{cluster}.".".$appansrec->{name};
       my %carec=(
          itcloud=>$appansrec->{cluster},
          fullname=>$fullname,
          name=>$appansrec->{name},
          srcid=>undef,
          srcsys=>$appans->Self(),
          applid=>$appansrec->{applid},
          appl=>$appansrec->{appl}
       );
       push(@a,\%carec);
   }

   $otcpro->SetFilter({
      name=>'![EMPTY]'
   });
   {
      my %otcpname;
      my $itcloud="OTC";
      foreach my $otcprorec ($otcpro->getHashList(qw(
                              name cluster id applid appl domain fullname))){
          my $fullname=$itcloud.".".$otcprorec->{name};
          $itcloud{$itcloud}++;
          $otcpname{$otcprorec->{name}}++;
          my $altname=$otcprorec->{domain}."_".$otcprorec->{fullname};
          my $altfullname=$itcloud.".".$altname;
          my %carec=(
             itcloud=>$itcloud,
             fullname=>$fullname,
             altname=>$altname,
             altfullname=>$altfullname,
             name=>$otcprorec->{name},
             srcid=>$otcprorec->{id},
             srcsys=>$otcpro->Self(),
             applid=>$otcprorec->{applid},
             appl=>$otcprorec->{appl}
          );
          push(@a,\%carec);
      }
      my @dupotcpname=grep({$otcpname{$_}>1} keys(%otcpname));
    
      foreach my $name (@dupotcpname){
         foreach my $arec (@a){
            if ($arec->{itcloud} eq $itcloud &&
                $arec->{name} eq $name){   # rename it
               $arec->{name}=$arec->{altname};
               $arec->{fullname}=$arec->{altfullname};
            }
         }
      }
   }

   # load all relevant itcloud records
   $itcloudobj->SetFilter({
      name=>[keys(%itcloud)],
      cistatusid=>[3,4]
   });
   $itcloudobj->SetCurrentView(qw(name id databossid cistatusid));
   my $itcloud=$itcloudobj->getHashIndexed("id","name");

   foreach my $cloudname (sort(keys(%itcloud))){
      if (!exists($itcloud->{name}->{$cloudname})){
         #msg(ERROR,"missing itcloud '$cloudname' to admin");
      }
   }

   # load all relevant itcloudarea records
   my $itcloudareaobj=getModuleObject($self->Config,"itil::itcloudarea");

   $itcloudareaobj->SetFilter({
      cloud=>[keys(%itcloud)],
   });
   $itcloudareaobj->SetCurrentView(qw(name fullname id itcloudid srcsys srcid));
   my $itcloudarea=$itcloudareaobj->getHashIndexed("id","fullname","name");



   #print Dumper(\%itcloud);
   #print Dumper($itcloud);
   #print Dumper($itcloudarea);



   foreach my $a (@a){
      last if ($inscnt>9);
      my $fullname=$a->{fullname};
      my $currec;
      if (exists($itcloudarea->{fullname}->{$fullname})){
         $currec=$itcloudarea->{fullname}->{$fullname};
      }
      #{
      #   # try to find currec by srcid/srcsys
      #}
      if (!defined($currec)){
         if (exists($itcloud->{name}->{$a->{itcloud}})){
            if ($a->{appl} ne ""){
               if (length($a->{name})<70 && length($a->{name})>1){
                  my $newrec={
                     cloud=>$a->{itcloud},
                     name=>$a->{name},
                     applid=>$a->{applid},
                     cistatusid=>'3',
                     srcsys=>$a->{srcsys}
                  };
                  if ($a->{srcid} ne ""){
                     $newrec->{srcid}=$a->{srcid}; # srcid not always set!
                  }
                  $itcloudareaobj->ValidatedInsertRecord($newrec);
                  sleep(1);
                  $inscnt++;
               }
               else{
                   msg(ERROR,"invalid area name at $fullname for ".
                             $itcloud->{name}->{$a->{itcloud}}->{databossid});
               }
            }
            else{
             # msg(ERROR,"missing valid application W5BaseID in $fullname for ".
             #           $itcloud->{name}->{$a->{itcloud}}->{databossid});
            }
         }
      }
      else{
         # check, if updates needs to be done
         my $updrec;
         if ($currec->{srcsys} ne $a->{srcsys}){
            $updrec->{srcsys}=$a->{srcsys};
         }
         if ($currec->{name} ne $a->{name}){
            $updrec->{name}=$a->{name};
         }
         if (exists($a->{srcid}) && $a->{srcid} ne "" &&
             $currec->{srcid} ne $a->{srcid}){
            $updrec->{srcid}=$a->{srcid};
         }
         if (keys(%$updrec)){
            $itcloudareaobj->ValidatedUpdateRecord($currec,$updrec,
                                                   {id=>$currec->{id}});
         }
      }
   }
   




   return({exitcode=>0,exitmsg=>'ok'});
}






1;
