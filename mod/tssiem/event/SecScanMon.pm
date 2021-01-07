package tssiem::event::SecScanMon;
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
@ISA=qw(kernel::Event);



# Modul to detect expiered SSL Certs based on Qualys scan data
sub SecScanMon
{
   my $self=shift;
   my $queryparam=shift;


   my $firstDayRange=14;
   my $maxDeltaDayRange="15";

   my $StreamDataobj="tssiem::secscan";


   my $joblog=getModuleObject($self->Config,"base::joblog");
   my $datastream=getModuleObject($self->Config,$StreamDataobj);
   my $appl=getModuleObject($self->Config,"TS::appl");
   my $wfa=getModuleObject($self->Config,"base::workflowaction");
   my $user=getModuleObject($self->Config,"base::user");


   my $eventlabel='IncStreamAnalyse::'.$datastream->Self;
   my $method=(caller(0))[3];

   $joblog->SetFilter({name=>\$method,
                       exitcode=>\'0',
                       exitmsg=>'last:*',
                       cdate=>">now-${maxDeltaDayRange}d", 
                       event=>\$eventlabel});
   $joblog->SetCurrentOrder('-cdate');

   $joblog->Limit(1);
   my ($firstrec,$msg)=$joblog->getOnlyFirst(qw(ALL));

   my %jobrec=(
      name=>$method,
      event=>$eventlabel,
      pid=>$$
   );
   my $jobid=$joblog->ValidatedInsertRecord(\%jobrec);
   msg(DEBUG,"jobid=$jobid");

   my $res={};

   my $lastSuccessRun;
   my $startstamp="now-${firstDayRange}d";        # intial scan over 14 days
   my $exitmsg="done";
   my $laststamp;
   my $lastid;
   my %flt;
   {    #analyse lastSuccessRun
      %flt=( 
         sdate=>">$startstamp"
      );
      if (defined($firstrec)){
         my $lastmsg=$firstrec->{exitmsg};
         if (($laststamp,$lastid)=
             $lastmsg=~m/^last:(\d+-\d+-\d+ \d+:\d+:\d+);(\S+)$/){
            $exitmsg=$lastmsg;
            $datastream->ResetFilter();
            $datastream->SetFilter({id=>\$lastid,sdate=>\$laststamp});
            my ($lastrec,$msg)=$datastream->getOnlyFirst(qw(id));
            if (!defined($lastrec)){
               msg(WARN,"record with id '$lastid' has been deleted or changed - using date only");
               $lastid=undef;
            }
            %flt=( 
               sdate=>">=\"$laststamp GMT\""
            );
         }
      }
   }

   { # process new records
      my $skiplevel=0;
      my $recno=0;
      $datastream->ResetFilter();
      $datastream->SetFilter(\%flt);
      $datastream->SetCurrentView(qw(ictono urlofcurrentrec
                                     name
                                     sdate id));
      $datastream->SetCurrentOrder("+sdate","+id");
      $datastream->Limit(1000);
      my ($rec,$msg)=$datastream->getFirst();

      if (defined($rec)){
         READLOOP: do{
            if ($skiplevel==2){
               if ($rec->{id} ne $lastid){
                  $skiplevel=3;
               }
            }
            if ($skiplevel==1){
               if ($rec->{sdate} ne $laststamp){
                  msg(WARN,"record with id '$lastid' missing in datastream");
                  msg(WARN,"this can result in skiped records!");
                  $skiplevel=3;
               }
            }
            if ($skiplevel==0){
               if (defined($laststamp) && defined($lastid)){
                  if ($laststamp eq $rec->{sdate}){
                     $skiplevel=1;
                  }
               }
               else{
                  $skiplevel=3;
               }
            }
            if ($skiplevel==1){
               if ($lastid eq $rec->{id}){
                  msg(INFO,"got ladid point $lastid");
                  $skiplevel=2;
               }
            }
            if ($skiplevel==0 ||  # = no records to skip
                $skiplevel==3){   # = all skips are done
               $self->analyseRecord($datastream,$rec,$res);
               $recno++;
               $exitmsg="last:".$rec->{sdate}.";".$rec->{id};
            }
            else{
               msg(INFO,"skip rec $rec->{sdate} - ".
                        "id=$rec->{id} ".
                        "skiplevel=$skiplevel recon=$recno");
            }
            ($rec,$msg)=$datastream->getNext();
            if (defined($msg)){
               msg(ERROR,"db record problem: %s",$msg);
               return({exitcode=>1,msg=>$msg});
            }
         }until(!defined($rec) || $recno>100);
      }
   }

   my $ncnt=0;
   {  # handle results

      my $a=1;
      if (keys(%{$res->{new}})){
         foreach my $icto (keys(%{$res->{new}})){
            $ncnt++;
            $self->doNotify($datastream,$wfa,$user,$appl,$icto,
                            $res->{new}->{$icto});
         }

      }
   }
   $joblog->ValidatedUpdateRecord({id=>$jobid},
                                 {exitcode=>"0",
                                  exitmsg=>$exitmsg,
                                  exitstate=>"ok - $ncnt messages"},
                                 {id=>\$jobid});
   return({exitcode=>0,exitmsg=>'ok'});
}


sub analyseRecord
{
   my $self=shift;
   my $dataobj=shift;
   my $rec=shift;
   my $res=shift;

   msg(INFO,"PROCESS: $rec->{id} $rec->{sdate} icto='$rec->{ictono}'");

   if ($rec->{ictono} eq ""){
      msg(ERROR,"found secscan with no ictono at $rec->{id} - abbort read");
      exit(1); 
   }

   $res->{new}->{$rec->{ictono}}->{$rec->{urlofcurrentrec}}={
      name=>$rec->{name}
   };
}


sub doNotify
{
   my $self=shift;
   my $datastream=shift;
   my $wfa=shift;
   my $user=shift;
   my $appl=shift;
   my $ictono=shift;
   my $rec=shift;
   my $debug="";


   $appl->ResetFilter();
   $appl->SetFilter({ictono=>\$ictono,cistatusid=>"<6"});

   my @l=$appl->getHashList(qw(id name applmgr tsmid contacts));

   my %uid;

   foreach my $arec (@l){
      $uid{cc}->{$arec->{tsmid}}++;
      $uid{to}->{$arec->{applmgrid}}++;
      foreach my $crec (@{$arec->{contacts}}){
         my $roles=$crec->{roles};
         $roles=[$roles] if (ref($roles) ne "ARRAY");
         if ($crec->{target} eq "base::user" &&
             in_array($roles,"applmgr2")){
            $uid{cc}->{$crec->{targetid}}++;
         }
      }
   }


   my @targetuids=grep(!/^$/,keys(%{$uid{to}}),keys(%{$uid{cc}}));

   my %nrec;

   $user->ResetFilter(); 
   $user->SetFilter({userid=>\@targetuids});
   foreach my $urec ($user->getHashList(qw(fullname userid lastlang lang))){
      my $lang=$urec->{lastlang};
      $lang=$urec->{lang} if ($lang eq "");
      $lang="en" if ($lang eq "");
      $nrec{$lang}->{$urec->{userid}}++;
   }
   my $lastlang;
   if ($ENV{HTTP_FORCE_LANGUAGE} ne ""){
      $lastlang=$ENV{HTTP_FORCE_LANGUAGE};
   }
   foreach my $lang (keys(%nrec)){
      $ENV{HTTP_FORCE_LANGUAGE}=$lang;
      my @emailto;
      my @emailcc;
      foreach my $userid (keys(%{$nrec{$lang}})){
         if (exists($uid{to}->{$userid})){
            push(@emailto,$userid);
         }
         if (exists($uid{cc}->{$userid})){
            push(@emailcc,$userid);
         }
      }
      my $subject=$datastream->T(
         "Qualys new security scan found for",
         'tssiem::qrule::SecScanMon').' '.$ictono;

      my @scans;
      foreach my $url (sort(keys(%$rec))){
         push(@scans,sprintf("<b>%s</b>\n%s\n",$rec->{$url}->{name},$url));
      }



      my $tmpl=$datastream->getParsedTemplate("tmpl/SecScanMon_MailNotify",{
         static=>{
            SCANLIST=>join("\n",@scans),
            ICTONO=>$ictono,
            DEBUG=>$debug
         }
      });

      $wfa->Notify("INFO",$subject,$tmpl, 
         emailto=>\@emailto, 
         emailcc=>\@emailcc, 
         emailcategory =>['Qualys',
                          'tssiem::event::SecScanMon',
                          'NewSecScan'],
         emailbcc=>[
         #   11634953080001, # HV
            12663941300002  # Roland
         ]
      );
   }
   if ($lastlang ne ""){
      $ENV{HTTP_FORCE_LANGUAGE}=$lastlang;
   }
   else{
      delete($ENV{HTTP_FORCE_LANGUAGE});
   }
}


1;
