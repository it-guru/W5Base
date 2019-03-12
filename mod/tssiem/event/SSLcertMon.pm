package tssiem::event::SSLcertMon;
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
sub SSLcertMon
{
   my $self=shift;
   my $queryparam=shift;


   my $firstDayRange=14;
   my $maxDeltaDayRange="15";

   my $StreamDataobj="tssiem::secent";


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
         sdate=>">$startstamp",
         qid=>\"86002"
      );
      if (defined($firstrec)){
         my $lastmsg=$firstrec->{exitmsg};
         if (($laststamp,$lastid)=
             $lastmsg=~m/^last:(\d+-\d+-\d+ \d+:\d+:\d+);(\d+)$/){
            $exitmsg=$lastmsg;
            %flt=( 
               sdate=>">=\"$laststamp GMT\"",
               qid=>\"86002"
            );
         }
      }
   }

   { # process new records
      my $skiplevel=0;
      my $recno=0;
      $datastream->SetFilter(\%flt);
      $datastream->SetCurrentView(qw(ictono ipaddress port protocol 
                                 sslparsedw5baseref sslparsedvalidtill
                                 sdate srcid));
      $datastream->SetCurrentOrder("+sdate","+srcid");
      $datastream->Limit(5000);
      my ($rec,$msg)=$datastream->getFirst();

      if (defined($rec)){
         READLOOP: do{
            if ($skiplevel==2){
               if ($rec->{srcid} ne $lastid){
                  $skiplevel=3;
               }
            }
            if ($skiplevel==2){
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
               if ($lastid eq $rec->{srcid}){
                  msg(INFO,"got ladid point $lastid");
                  $skiplevel=2;
               }
            }
            if ($skiplevel==0 ||  # = no records to skip
                $skiplevel==3){   # = all skips are done
               $self->analyseRecord($datastream,$rec,$res);
               $recno++;
               $exitmsg="last:".$rec->{sdate}.";".$rec->{srcid};
            }
            else{
               msg(INFO,"skip rec $rec->{sdate} - ".
                        "srcid=$rec->{srcid} ".
                        "skiplevel=$skiplevel recon=$recno");
            }
            ($rec,$msg)=$datastream->getNext();
            if (defined($msg)){
               msg(ERROR,"db record problem: %s",$msg);
               return({exitcode=>1,msg=>$msg});
            }
         }until(!defined($rec) || $recno>2000);
      }
   }

   my $ncnt=0;
   {  # handle results

      my $a=1;
      if (keys(%{$res->{invalid}})){
         foreach my $icto (keys(%{$res->{invalid}})){
            $ncnt++;
            $self->doNotify($datastream,$wfa,$user,$appl,$icto,
                            $res->{invalid}->{$icto});
         }
         #print Dumper($res);

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

   my $validtill=$rec->{sslparsedvalidtill};

   my $d=CalcDateDuration(NowStamp("en"),$validtill);

   if (!defined($d)){
      msg(ERROR,"can no handle sslparsedvalidtill '$validtill'");
      return();
   }

   msg(INFO,"PROCESS: $rec->{srcid} $rec->{sdate} validtil='$validtill'");

   if ($d->{days}<8*7 && $d->{days}>3){   # 8 weeks
      if (defined($rec->{sslparsedw5baseref})){
         msg(WARN,"ok - found sslparsedw5baseref for ".
                  "$rec->{ipaddress}:$rec->{port}");
      }
      else{  # store in result structure 
         $res->{invalid}->{$rec->{ictono}}->{$rec->{sslparsedserial}}={
            sslserial=>$rec->{sslparsedserial},
            sslvalidtill=>$rec->{sslparsedvalidtill},
            ipaddress=>$rec->{ipaddress},
            port=>$rec->{port},
            protocol=>$rec->{protocol},
            days=>$d->{days},
            ictono=>$rec->{ictono}
         };
      }
   }
   #print Dumper($d);
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

   #print STDERR "NOTIFY:".Dumper($rec);

   $appl->ResetFilter();
   $appl->SetFilter({ictono=>\$ictono,cistatusid=>"<6"});

   my @l=$appl->getHashList(qw(tsmid tsm2id applmgrid contacts opmid opm2id));

   my %uid;

   foreach my $arec (@l){
      $uid{$arec->{tsmid}}++;
      $uid{$arec->{tsm2id}}++;
      $uid{$arec->{opmid}}++;
      $uid{$arec->{opm2id}}++;
      $uid{$arec->{applmgrid}}++;
      foreach my $crec (@{$arec->{contacts}}){
         my $roles=$crec->{roles};
         $roles=[$roles] if (ref($roles) ne "ARRAY");
         if ($crec->{target} eq "base::user" &&
             in_array($roles,"applmgr2")){
            $uid{$crec->{targetid}}++;
         }
      }
   }


   my @targetuids=keys(%uid);    # now we got all target userids

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
      my @emailto=keys(%{$nrec{$lang}});
      my $subject=$datastream->T(
         "Qualys centificate near expiration detected at",
         'tssiem::qrule::SSLcertMon').' '.$ictono;

      my @certs;
      foreach my $ser (sort(keys(%$rec))){
         push(@certs,sprintf("%-22s expires in %d days",
                             $rec->{$ser}->{ipaddress}.":".$rec->{$ser}->{port},
                             $rec->{$ser}->{days})
         );
      }



      my $tmpl=$datastream->getParsedTemplate("tmpl/SSLcertMon_MailNotify",{
         static=>{
            CERTLIST=>join("\n",@certs),
            ICTONO=>$ictono,
            DEBUG=>$debug
         }
      });
      $wfa->Notify( "WARN",$subject,$tmpl, 
         emailto=>\@emailto, 
         emailbcc=>[
   #         11634953080001,   # HV
            12663941300002    # Roland
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
