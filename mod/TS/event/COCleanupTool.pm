package TS::event::COCleanupTool;
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
use kernel::Event;
use finance::costcenter;
@ISA=qw(kernel::Event);

our %src;
our %dst;


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

   $self->RegisterEvent("COCleanupTool","COCleanupTool");
   return(1);
}

sub COCleanupTool
{
   my $self=shift;
   my $filename=shift;
   my $exitcode=0;

   $ENV{REMOTE_USER}="service/COCleanupTool";

   $self->{costcenter}=getModuleObject($self->Config,"finance::costcenter");
   $self->{custcontract}=getModuleObject($self->Config,"finance::custcontract");
   $self->{appl}=getModuleObject($self->Config,"itil::appl");
   $self->{system}=getModuleObject($self->Config,"itil::system");
   $self->{asset}=getModuleObject($self->Config,"itil::asset");

   my $opobj=$self->{costcenter}->Clone();


   my $o=$self->{costcenter};

   $o->SetFilter({
      cistatusid=>"<6",
      mdate=>"<now-30d"
   });
   $o->SetCurrentView(qw(ALL));

   my ($rec,$msg)=$o->getFirst();
   if (defined($rec)){
      do{
         msg(INFO,"Process CO-Record $rec->{fullname}");
         $self->AnalyseAndProcessRec($opobj,$rec);
         ($rec,$msg)=$o->getNext();
      } until(!defined($rec));
   }



   return({exitcode=>$exitcode});
}

sub AnalyseAndProcessRec
{
   my $self=shift;
   my $opobj=shift;
   my $rec=shift;


   my $newrec={};
   my $co=$rec->{name};
   msg(INFO,"Searching $co ...");
   my $logcol=2;

   my $total=0;
   my %to=();
   my %cc=(11634953080001=>1,   #hv
           11634955570001=>1,   #cj
           11634955470001=>1,   #pm
           12762475160001=>1,   #ag
   );


   my $msg="";
   my $EventJobBaseUrl=$self->Config->Param("EventJobBaseUrl");


   my $covalid=1;

   if (($rec->{name}=~m/^\s*$/) ||
       ($rec->{name}=~m/\*/)){
      $covalid=0;
   }



   if ($covalid){
      foreach my $o (qw(appl custcontract system asset)){ 
         $self->{$o}->ResetFilter();
         $self->{$o}->SetFilter({conumber=>\$co,
                                 cistatusid=>"<=5"});
         foreach my $rec ($self->{$o}->getHashList(qw(ALL))){
            $total++;
         }
      }
   }
   if ($total == 0){
      print STDERR ("no references found for $co\n");
      if ($opobj->ValidatedUpdateRecord($rec,{cistatusid=>6},
                                             {id=>\$rec->{id}})){
         print STDERR ("$co set to deleted\n");
      }
   }
   else{
      if ($rec->{cistatusid}!=4){
         print STDERR ("found references for $co but cistatus is $rec->{cistatusid}\n");
         if ($opobj->ValidatedUpdateRecord($rec,{cistatusid=>4},
                                                {id=>\$rec->{id}})){
            print STDERR ("$co set to active\n");
         }
      }
   }


#   if ($total>0){
#      my $wfa=getModuleObject($self->Config,"base::workflowaction");
#      my $contact=
#           "\nFMB One ERP Rollout TSI ".
#           "One.ERP_Rollout_TSI\@telekom.de".
#           "\n\n";
#
#      if (keys(%to)!=0){
#         $wfa->Notify("INFO",
#           "SAPP01 to OFI (One Finace) Migration - ".
##           $data->[0]." -> ".$data->[1],
#           "Sehr geehrte Damen und Herren,\n\n".
#           "aufgrund einer notwendigen Umstellung vom SAP P01 ".
#           "auf das konzerneinheitliche SAP OFI System ".
#           ", wurden in W5Base/Darwin ".
#           "Korrekturen an Config-Items durchgef�hrt, in denen Sie als ".
#           "Datenverantwortlicher gef�hrt werden.\n\n".
#           "Im konkreten Fall wurde der Kostenknoten ...\n".
##           "'<b>".$data->[0]."</b>' auf '<b>".$data->[1]."</b>'\n ".
#           "... umgestellt.\n\n".
#           "Diese Korrektur hat Auswirkungen auf die folgenden ".
#           "Config-Items:\n".$msg.
#           "\n\nBitte pr�fen Sie im Bedarfsfall, ob diese ".
#           "Umstellungen auch aus Ihrer Sicht korrekt sind. Bei ".
#           "R�ckfragen zu dieser Migration wenden Sie sich bitte ".
#           "an das Funktionspostfach ...\n".
#           $contact.
#           "... welches f�r Fragen im Zusammenhang mit der OFI Migration ".
#           "eingerichtet wurde.\n".
#           "\n".
#           "\n".
#           "               ---------------------------------------\n".
#           "\n".
#           "\n".
#           "Dear Ladies and Gentleman,\n\n".
#           "Because of the necessary migration from SAP P01 to the ".
#           "group-wide SAP OFI System corrections in W5Base/Darwin were ".
#           "made on the config-items where you are listed as the ".
#           "Databoss.\n\n".
#           "In this particular case the cost node ...\n ".
###           "'<b>".$data->[0]."</b>' was changed to '<b>".$data->[1]."</b>'\n ".
#           "\n".
#           "This correction affects the following config-items:\n".
#           $msg.
#           "\n\nPlease check if this change is correct from your point of ".
#           "view. In case of further questions please contact the ".
#           "functional mailbox ...\n".
#           $contact.
#           "... which was set up for enquiries regarding the ".
#           "OFI Migration.\n"
#           ,
#           emailto=>[keys(%to)],
#           emailcc=>[keys(%cc)]);
#      }
#   }
   
}


##########################################################################
##########################################################################
##########################################################################
##########################################################################






1;
