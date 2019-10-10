package tsRMO::w5stat::base;
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
use kernel::Universal;
use kernel::date;
@ISA=qw(kernel::Universal);


sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless({%param},$type);

   $self->{Colors}=[
      red=>'not acceptable',
      yellow=>'problmeatic or soon problematic',
      blue=>'justified or not relevant',
      green=>'alright',
      gray=>'unidentifiable'
   ];
   return($self);
}

sub getPresenter
{
   my $self=shift;

   my @l=(
          'RMO'=>{
                         opcode=>\&displayRMO,
                         overview=>undef,
                         group=>['Group','Application'],
                         prio=>2100,
                      }
         );

}


sub processDataInit
{
   my $self=shift;
   my $datastream=shift;
   my $dstrangestamp=shift;
   my %param=@_;
   my $app=$self->getParent;


  my $o=getModuleObject($app->Config,"itil::softwareset");
   $o->SetFilter({name=>'"TEL-IT Patchmanagement*"',
                  cistatusid=>\'4'});
   my @nativeroadmapname=$o->getHashList(qw(id name));
   my @roadmapname;
   my @mroadmaps;     # Roadmaps on month base
   foreach my $r (@nativeroadmapname){
      if (my ($year,$month)=$r->{name}
          =~m/^TEL-IT Patchmanagement\s*([0-9]{4})[\/-]([0-9]{2})$/){
         push(@mroadmaps,{
            id=>$r->{id},
            name=>$r->{name},
            month=>$month,
            year=>$year,
            k=>sprintf("%04d%02d",$year,$month),
         });
      }
   }
   my ($cy,$cm)=Today_and_Now("GMT");
   my $ckey=sprintf("%04d%02d",$cy,$cm);
   if ($#mroadmaps!=-1){
      @mroadmaps=grep({$_->{k} le $ckey} sort({$a->{k}<=>$b->{k}} @mroadmaps));
      if ($#mroadmaps!=-1){
         @mroadmaps=($mroadmaps[-1]);
      }
   }
   if ($#mroadmaps==-1){
      @roadmapname=grep({$_->{name} eq "TEL-IT Patchmanagement"}
                        @nativeroadmapname);
   }
   else{
      @roadmapname=@mroadmaps;
   }
   #print Dumper(\@roadmapname);
   $self->{Roadmap}=\@roadmapname;
}
























sub SignImg
{
   my $name=shift;

   $name="gray" if ($name eq "");

   return("<img width=13 height=13 src=\"../../base/load/sign_$name.gif\">");
}

sub Legend
{
   my $self=shift;
   my @colors=@{$self->{Colors}};

   my $d="";
   $d.="<table class=statTab style=\"width:auto\">";
   while(my $color=shift(@colors)){
      my $legend=shift(@colors);
      $d.="<tr><td class=fixColor>".SignImg($color)."</td>";
      $d.="<td class=fixColor>".$self->getParent->T($legend)."</td></tr>";
   }
   $d.="</table>";

   return($d);
}


sub mkSegBar
{
   my $self=shift;
   my $name=shift;
   my $data=shift;

   my $d="<div id=\"$name\"></div>";
   $d.="<script language=JavaScript>\n";
   $d.='$(document).ready(function(){';
   $d.="\$(\"#$name\").segbar([\n";
   $d.='{';
   $d.=" data:[\n";
   for(my $c=0;$c<=$#{$data};$c++){
      $d.="," if ($c>0);
      $d.="{title:'".$data->[$c]->{value}."',";
      $d.="value:".$data->[$c]->{value}.",";
      $d.="color:'".$data->[$c]->{color}."'}";
   }
   $d.="],\n";
   $d.=' height:"40px"';
   $d.='}';
   $d.=']);';
   $d.='});';
   $d.='</script>';


   return($d);

}

sub mkSegBarDSet
{
   my $self=shift;
   my $appkpi=shift;
   my $namespace=shift;
   my @ds;

   my @colors=@{$self->{Colors}};
   while(my $color=shift(@colors)){
      my $legend=shift(@colors);
      my $v=$appkpi->{$namespace.".".$color};
      if ($v>0){
         my $rec={
            value=>$v,
            color=>$color
         };
         push(@ds,$rec);
      }
   }
   return(\@ds);
}

sub DIsplit
{
   my $DIstr=shift;

   if ($DIstr eq ""){
      return(undef,"green");
   }
   my $DIcolor="red";
   my $DIid=$DIstr;
   my @di=split(/,/,$DIstr);
   if ($di[1] ne ""){
      $DIcolor=$di[1];      
      $DIid=$di[0];      
   }
   return($DIid,$DIcolor);
}

sub displayRMO
{  
   my $self=shift;
   my ($primrec,$hist)=@_;


   my $rmostat;
   foreach my $substatstream (@{$primrec->{statstreams}}){
      if ($substatstream->{statstream} eq "RMO"){
         $rmostat=$substatstream;
      }
   }
   return() if (!defined($rmostat));


   my $app=$self->getParent();
   #my $user=$app->extractYear($primrec,$hist,"User",
   #                           setUndefZero=>1);

   my $d="";
   my $applcnt=0;
   if (exists($rmostat->{stats}->{'RMO.Appl.Count'})){
      $applcnt=$rmostat->{stats}->{'RMO.Appl.Count'}->[0];
   }


   my @s;
   my @a;
   my %a;
   my @i;
   my %DIid;
   if ($rmostat->{sgroup} eq "Application"){
      if ($applcnt){
         $d.=sprintf($app->T("APPISRELEVANT"),$primrec->{fullname});
      }
      else{
         $d.=sprintf($app->T("APPISNOTRELEVANT"),$primrec->{fullname});
      }
      if (exists($rmostat->{stats}->{'RMO.System'})){
         @s=map({
            my @fld=split(/;/,$_);
            my $pos=0; 
            my $rec={id=>$fld[$pos++]};
            $rec->{name}=$fld[$pos++];
            $rec->{dataissue}=$fld[$pos++];
            $rec->{assetid}=$fld[$pos++];
            $rec->{systemid}=$fld[$pos++];
            $rec->{productline}=$fld[$pos++];
            $rec->{tcccolor}=$fld[$pos++];
            $rec;
         } @{$rmostat->{stats}->{'RMO.System'}});

         @s=sort({
            my $bk=$a->{assetid} <=> $b->{assetid};
            if ($bk==0){
               $bk=$a->{name} cmp $b->{name};
            }
         } @s);
      }
      if (exists($rmostat->{stats}->{'RMO.Asset'})){
         @a=map({
            my @fld=split(/;/,$_);
            my $pos=0; 
            my $rec={id=>$fld[$pos++]};
            $rec->{assetid}=$fld[$pos++];
            $rec->{dataissue}=$fld[$pos++];
            $rec->{acqumode}=$fld[$pos++];
            $rec->{agecolorstring}=$fld[$pos++];
            $rec->{age}=$fld[$pos++];
            $a{$rec->{id}}=$rec;
            $rec->{agecolor}=$rec->{agecolorstring};
            $rec->{agecolor}=~s/\s.*$//;
            $rec;
         } @{$rmostat->{stats}->{'RMO.Asset'}});
          
      }
      if (exists($rmostat->{stats}->{'RMO.Instance'})){
         @i=map({
            my @fld=split(/;/,$_);
            my $pos=0; 
            my $rec={id=>$fld[$pos++]};
            $rec->{name}=$fld[$pos++];
               $rec->{dataissue}=$fld[$pos++];
            $rec;
         } @{$rmostat->{stats}->{'RMO.Instance'}});
      }

      { # Systems rowspan calculation in Asset columns
         for(my $i=0;$i<=$#s;$i++){
            my $rowspan=0;
            my $ii;
            for($ii=$i;$ii<=$#s;$ii++){ 
               if ($s[$i]->{assetid} eq $s[$ii]->{assetid}){
                  $rowspan++;
               }
               else{
                  last;
               }
            }
            $s[$i]->{rowspan}=$rowspan;
            if ($rowspan>1){
               $i=$ii-1;
            }
         }
      }



   }

   my $appkpi;
   my $showLegend=0;

   my %colors=@{$self->{Colors}};
   foreach my $color (keys(%colors)){
      foreach my $prefix (qw(RMO.System.TCC.os RMO.Asset.age)){
         $appkpi->{$prefix.".".$color}=0;
      }
   }
   if ($rmostat->{sgroup} eq "Application"){
      foreach my $rec (@a){
         my $color=$rec->{agecolor};
         $appkpi->{'RMO.Asset.age.'.$color}++;
         my ($DIid,$DIcol)=DIsplit($rec->{dataissue});
         $DIid{$DIid}++ if ($DIid ne "");
         $appkpi->{'RMO.DataIssue.'.$DIcol}++;
      }
      foreach my $rec (@s){
         my $color=$rec->{tcccolor};
         $appkpi->{'RMO.System.TCC.os.'.$color}++;
         my ($DIid,$DIcol)=DIsplit($rec->{dataissue});
         $DIid{$DIid}++ if ($DIid ne "");
         $appkpi->{'RMO.DataIssue.'.$DIcol}++;
      }
      foreach my $rec (@i){
         my $color=$rec->{tcccolor};
         my ($DIid,$DIcol)=DIsplit($rec->{dataissue});
         $DIid{$DIid}++ if ($DIid ne "");
         $appkpi->{'RMO.DataIssue.'.$DIcol}++;
      }
   }
   if ($rmostat->{sgroup} eq "Group"){
      foreach my $color (keys(%colors)){
         foreach my $prefix (qw(RMO.System.TCC.os RMO.Asset.age RMO.DataIssue)){
            if (exists($rmostat->{stats}->{$prefix.".".$color})){
               $appkpi->{$prefix.".".$color}=
                  $rmostat->{stats}->{$prefix.".".$color}->[0];
            }
         }
      }
   }
   foreach my $color (keys(%colors)){
      foreach my $prefix (qw(RMO.System.TCC.os RMO.Asset.age RMO.DataIssue)){
         if ($appkpi->{$prefix.".".$color}==0){
            delete($appkpi->{$prefix.".".$color});
         }
         else{
            $showLegend++;
         }
      }
   }


   if ($rmostat->{sgroup} eq "Group"){
      $d.="<table class=statTab style=\"width:70%\">";
      $d.=sprintf("<tr><td>RMO relevante Anwendungen:</td>".
                  "<td>%d</td></tr>",$applcnt);
      if (exists($rmostat->{stats}->{'RMO.System.Count'})){
         $d.=sprintf("<tr><td nowrap>von RMO relevanten Anwendungen ".
                     "verwendete logische Systeme:</td><td>%d</td></tr>",
                     $rmostat->{stats}->{'RMO.System.Count'}->[0]);
      }
      if (exists($rmostat->{stats}->{'RMO.Asset.Count'})){
         $d.=sprintf("<tr><td nowrap>von RMO relevanten Anwendungen ".
                     "verwendete Hardware-Items:</td><td>%d</td></tr>",
                     $rmostat->{stats}->{'RMO.Asset.Count'}->[0]);
      }
      if (exists($rmostat->{stats}->{'RMO.Instance.Count'})){
         $d.=sprintf("<tr><td nowrap>Instanzen an RMO relevanten ".
                     "Anwendungen:</td><td>%d</td></tr>",
                     $rmostat->{stats}->{'RMO.Instance.Count'}->[0]);
      }
      $d.="</table>";
      $d.="Die Kennzahlen werden immer bezogen auf eine Anwendung ermittelt ".
          "und dann bezogen auf Betriebsteam/Betriebsbereich und Mandant ".
          "auf alle dar�berliegenden Organisationsebenen agregiert. ".
          "Dies bedeutet, dass wenn z.B. einen Hardware von mehreren ".
          "Anwendungen verwendet wird, kann es zu Mehrfachz�hlungen kommen.";
   }



   $d.="<hr>";
   if (grep(/^RMO.Asset.age/,keys(%{$appkpi}))){
      $d.="<h3>Hardware-Alter:</h3>";
      $d.="Die Bewertung des Hardware-Alters erfolgt nach den in ";
      $d.="W5Base/Darwin hinterlegten Bewertungs-Regeln. ";
      $d.="Details dazu sind in der betreffenden QualityRule nachzulesen.";
      $d.=$self->mkSegBar("hwage",$self->mkSegBarDSet($appkpi,
                          "RMO.Asset.age"));
      $d.="<hr>";
   }
   if (grep(/^RMO.System.TCC.os/,keys(%{$appkpi}))){
      $d.="<h3>Betriebssystem Version (TCC bewertet):</h3>";
      $d.="Das installierte Betriebssystem wird nach dem TCC Report der ";
      $d.="T-Systems bewertet. Systeme die nicht von der TSI betreut werden ";
      $d.="sind folglich nicht bewertbar.";
      $d.=$self->mkSegBar("osst",$self->mkSegBarDSet($appkpi,
                          "RMO.System.TCC.os"));
      $d.="<hr>";
   }
   if (grep(/^RMO.DataIssue/,keys(%{$appkpi}))){
      $d.="<h3>DataIssues:</h3>";
      $d.="Bewertet wird das vorhanden sein von DataIssues an den in direkter ";
      $d.="Relation zur jeweiligen Anwendung befindlichen Config-Items. ";
      $d.="DataIssues die l�nger als 8 Wochen existieren, werden ";
      $d.="rot gewertet. DataIssues die k�rzer als 8 Wochen existieren, ".
          "werden ";
      $d.="gelb dargestellt.";
      $d.=$self->mkSegBar("dist",$self->mkSegBarDSet($appkpi,
                          "RMO.DataIssue"));
      $d.="<hr>";
   }


      
   if ($rmostat->{sgroup} eq "Application"){
      my $sById;
      my $aById;
      my $tccById;
      my $DIById;
      if ($#s!=-1){
         my $o=$app->getPersistentModuleObject("itil::system");
         $o->SetFilter({id=>[map({$_->{id}} @s)]});
         $sById=$o->getHashIndexed(qw(id));
         my @systemid=grep(!/^\s*$/,map({$_->{systemid}} @s));
         if ($#systemid!=-1){
            my $o=$app->getPersistentModuleObject("tssmartcube::tcc");
            $o->SetFilter({systemid=>\@systemid});
            $tccById=$o->getHashIndexed(qw(systemid));
         }
      }
      if ($#a!=-1){
         my $o=$app->getPersistentModuleObject("itil::asset");
         $o->SetFilter({id=>[map({$_->{id}} @a)]});
         $aById=$o->getHashIndexed(qw(id));
      }
      if (keys(%DIid)){
         my $o=$app->getPersistentModuleObject("base::workflow");
         $o->SetFilter({id=>[keys(%DIid)]});
         $DIById=$o->getHashIndexed(qw(id));
      }
      
      { # Systems
         for(my $i=0;$i<=$#s;$i++){
            if ($i==0){
               $d.="<table class=statTab>";
               $d.="<thead><tr><th width=1%>System</th><th>SystemID</th>".
                       "<th width=20>Productline</th>".
                       "<th width=20>OS</th><th>DI</th>".
                       "<th>Asset</th>".
                       "<th width=20>Hardware Alter</th>".
                       "<th width=20>HW</th>".
                       "<th width=20>DI</th>".
                       "</tr></thead>";
            }
            $d.="<tr>";
            $d.="<td nowrap>";
            if (exists($sById->{id}->{$s[$i]->{id}})){
               $d.=$app->OpenByIdWindow("itil::system",
                                        $s[$i]->{id},$s[$i]->{name});
            }
            else{
               $d.=$s[$i]->{name};
            }
            $d.="</td>";
            $d.="<td>".$s[$i]->{systemid}."</td>";
            $d.="<td>".$s[$i]->{productline}."</td>";
            $d.="<td align=center>";
            if ($s[$i]->{systemid} ne "" && 
               exists($tccById->{systemid}->{$s[$i]->{systemid}})){
              $d.=$app->OpenByIdWindow("tssmartcube::tcc",
                                        $s[$i]->{systemid},
                                        SignImg($s[$i]->{tcccolor}));
            }
            else{
              $d.=SignImg($s[$i]->{tcccolor});
            }
            $d.="</td>";
            {
               my $DItext="";
               if ($s[$i]->{dataissue} ne ""){
                  my ($DIid,$DIcol)=DIsplit($s[$i]->{dataissue});
                  if ($DIid ne "" && exists($DIById->{id}->{$DIid})){
                     $DItext=$app->OpenByIdWindow("base::workflow",
                                               $DIid,
                                               $DItext=SignImg($DIcol));
                  }
                  else{
                     $DItext=SignImg($DIcol);
                  }
               }
               $d.="<td align=center>".$DItext."</td>";
            }
            if (defined($s[$i]->{rowspan})){
               my $td="<td class=fixColor ".
                      "rowspan=$s[$i]->{rowspan} valign=top>";
               my $asset=$s[$i]->{assetid};
               if ($a{$s[$i]->{assetid}}->{assetid} ne ""){
                  $asset=$a{$s[$i]->{assetid}}->{assetid};
               }
               $d.=$td;
               if (exists($aById->{id}->{$s[$i]->{assetid}})){
                  $d.=$app->OpenByIdWindow("itil::asset",
                                           $s[$i]->{assetid},$asset);
               }
               else{
                  $d.=$asset;
               }
               $d.="</td>";
               my $age=$a{$s[$i]->{assetid}}->{age};
               if ($age ne ""){
                  my $ay=int($age/364);
                  my $am=int(($age-(365*$ay))/30);
                  $age="";
                  $age=" ${ay}Y";
                  if ($am>0){
                     $age.=" " if ($age ne "");
                     $age.="${am}M";
                  }
               }
               $d.=$td.$age."</td>";
               $d.="<td class=fixColor rowspan=$s[$i]->{rowspan} align=center>".
                   SignImg($a{$s[$i]->{assetid}}->{agecolor})."</td>";
               my $DItext="";
               if ($a{$s[$i]->{assetid}}->{dataissue} ne ""){
                  my ($DIid,$DIcol)=DIsplit($a{$s[$i]->{assetid}}->{dataissue});
                  if ($DIid ne "" && exists($DIById->{id}->{$DIid})){
                     $DItext=$app->OpenByIdWindow("base::workflow",
                                               $DIid,
                                               $DItext=SignImg($DIcol));
                  }
                  else{
                     $DItext=SignImg($DIcol);
                  }
               }
               $d.="<td class=fixColor rowspan=$s[$i]->{rowspan} align=center>".
                   $DItext."</td>";
            }

            $d.="</tr>";
         }
         $d.="</table>" if ($#s!=-1);
      }
      { # Instance
         for(my $i=0;$i<=$#i;$i++){
            if ($i==0){
               $d.="<table class=statTab>";
               $d.="<thead><tr><th>Instancename</th><th width=10>DI</th>".
                       "</tr></thead>";
            }
            $d.="<tr>";
            $d.="<td>".$i[$i]->{name}."</td>";
            {
               my $DItext="";
               if ($i[$i]->{dataissue} ne ""){
                  my ($DIid,$DIcol)=DIsplit($i[$i]->{dataissue});
                  if ($DIid ne "" && exists($DIById->{id}->{$DIid})){
                     $DItext=$app->OpenByIdWindow("base::workflow",
                                               $DIid,
                                               $DItext=SignImg($DIcol));
                  }
                  else{
                     $DItext=SignImg($DIcol);
                  }
               }
               $d.="<td align=center width=10>".$DItext."</td>";
            }
            $d.="</tr>";
         }
         $d.="</table>" if ($#i!=-1);
      }
   }



#print STDERR (Dumper($rmostat->{stats}));
#print STDERR (Dumper($rmostat));


   if ($showLegend){
      $d.=$self->Legend();
      $d.="<hr>";
   }

   $d.="Debug-Data:<br>";
   
   $d.="w5stat w5baseid=".
       $app->OpenByIdWindow("base::w5stat",$primrec->{id},$primrec->{id}).
       "<br>";
   $d.="w5stat RMO w5baseid=".
       $app->OpenByIdWindow("base::w5stat",$rmostat->{id},$rmostat->{id}).
       "<br>";
   $d.="w5stat RMO Stand=$rmostat->{mdate}<br>";
   $d.="<hr>";
   return($d);
}

sub OpenByIdWindow
{
   my $self=shift;
   my $dataobj=shift;
   my $id=shift;

}



sub processData
{
   my $self=shift;
   my $statstream=shift;
   my $dstrange=shift;
   my %param=@_;
   my ($year,$month)=$dstrange=~m/^(\d{4})(\d{2})$/;
   my $count=0;

   return() if ($statstream ne "RMO");

   my $appl=getModuleObject($self->getParent->Config,"TS::appl");
   $appl->SetCurrentView(qw(name cistatusid mandatorid systems swinstances
                            businessteam responseteam id dataissuestate
                            mgmtitemgroup));
   #$appl->SetFilter({cistatusid=>'<=4',name=>'W5* NGSS* Dina*'});
   #$appl->SetFilter({cistatusid=>'<=4',name=>'W5* Dina* TSG_VIRTUELLE_T-SERVER*'});
   $appl->SetFilter({cistatusid=>'4'});
   $appl->SetCurrentOrder("NONE");
   msg(INFO,"starting collect of RMO Applications");
   my ($rec,$msg)=$appl->getFirst();
   if (defined($rec)){
      do{
         $self->getParent->processRecord($statstream,'tsRMO::appl',
                                         $dstrange,$rec,%param);
         ($rec,$msg)=$appl->getNext();
         $count++;
      } until(!defined($rec));
   }
   msg(INFO,"FINE of tsRMO::appl  $count records");

}


sub processRecord
{
   my $self=shift;
   my $statstream=shift;
   my $module=shift;
   my $monthstamp=shift;
   my $rec=shift;
   my $app=$self->getParent();
   my %param=@_;
   my ($year,$month)=$monthstamp=~m/^(\d{4})(\d{2})$/;

   return() if ($statstream ne "RMO");

   if ($module eq "tsRMO::appl"){
      msg(INFO,"RMO Processs $rec->{name}");
      my $appkpi={};
      my $name=$rec->{name};
      my $grp=$app->getPersistentModuleObject("base::grp");


      my @repOrg;
      if ($rec->{businessteam} ne ""){
         push(@repOrg,$rec->{businessteam});
      }
      if ($rec->{mandatorid} ne ""){
         $grp->SetFilter({grpid=>\$rec->{mandatorid},cistatusid=>'4'});
         my ($grec)=$grp->getOnlyFirst(qw(fullname));
         if (defined($grec)){
            push(@repOrg,$grec->{fullname});
         }
      }


      #######################################################################
      # Analyse of systems
      my %systemid=();
      my %assetid=();
      my %systemsystemid=();
      my %swinst=();
      foreach my $sysrec (@{$rec->{systems}}){
         my $rec={
            name=>$sysrec->{system},
            systemid=>$sysrec->{systemid},
            systemsystemid=>$sysrec->{systemsystemid},
            assetid=>$sysrec->{assetid},
            assetassetid=>$sysrec->{assetassetname}
         };
         if ($sysrec->{systemsystemid} ne ""){
            $rec->{systemsystemid}=$sysrec->{systemsystemid};
            $systemsystemid{$sysrec->{systemsystemid}}=$rec;
         }
         $systemid{$sysrec->{systemid}}=$rec;
         if (!exists($assetid{$sysrec->{assetid}})){
            $assetid{$sysrec->{assetid}}={
               id=>$sysrec->{assetid},
               productline=>{}
            };
         }
      }
      if (keys(%systemsystemid)){
         my $tcc=$app->getPersistentModuleObject("tssmartcube::tcc");
         $tcc->SetFilter({systemid=>[keys(%systemsystemid)]});
         foreach my $tccrec ($tcc->getHashList(qw(systemid 
                                                  systemname
                                                  check_release_color))){
            my $tcc_color=$tccrec->{check_release_color};
            $tcc_color="green" if ($tcc_color eq "");
            $systemsystemid{$tccrec->{systemid}}->{roadmap_color}=$tcc_color;
         }
      }
      #######################################################################

      #######################################################################
      # Analyse of instances
      my %instanceid=();
      foreach my $irec (@{$rec->{swinstances}}){
         my $rec={
            name=>$irec->{fullname},
            id=>$irec->{id}
         };
         $instanceid{$rec->{id}}=$rec; 
      }
      #######################################################################


      if (keys(%instanceid)){
         my $o=$app->getPersistentModuleObject("itil::swinstance");
         $o->SetFilter({id=>[keys(%instanceid)]});
         my @l=$o->getHashList(qw(id dataissuestate));
         for(my $c=0;$c<=$#l;$c++){
            if (exists($l[$c]->{dataissuestate}->{id})){
               my $dicolor="red";
               my $eventstart=$l[$c]->{dataissuestate}->{eventstart};
               if ($eventstart ne ""){
                  my $d=CalcDateDuration($eventstart,NowStamp('en'));
                  if (defined($d) && $d->{days}<8*7){
                     $dicolor="yellow";
                  }
               }
               $instanceid{$l[$c]->{id}}->{dataissue}=
                  $l[$c]->{dataissuestate}->{id}.",$dicolor";
               $appkpi->{'RMO.DataIssue.'.$dicolor}++;
            }
            else{
               $appkpi->{'RMO.DataIssue.green'}++;
            }
         }
      }

      if (keys(%systemid)){
         my $o=$app->getPersistentModuleObject("itil::system");
         $o->SetFilter({id=>[keys(%systemid)]});
         my @l=$o->getHashList(qw(id assetid dataissuestate productline));
         for(my $c=0;$c<=$#l;$c++){
            if (exists($l[$c]->{dataissuestate}->{id})){
               my $dicolor="red";
               my $eventstart=$l[$c]->{dataissuestate}->{eventstart};
               if ($eventstart ne ""){
                  my $d=CalcDateDuration($eventstart,NowStamp('en'));
                  if (defined($d) && $d->{days}<8*7){
                     $dicolor="yellow";
                  }
               }
               $systemid{$l[$c]->{id}}->{dataissue}=
                  $l[$c]->{dataissuestate}->{id}.",$dicolor";
               $appkpi->{'RMO.DataIssue.'.$dicolor}++;
            }
            else{
               $appkpi->{'RMO.DataIssue.green'}++;
            }
            $systemid{$l[$c]->{id}}->{productline}=$l[$c]->{productline};
            $assetid{$l[$c]->{assetid}}->{productline}->{
                $l[$c]->{productline}}++;
            
         }
      }

      if (keys(%assetid)){
         my $o=$app->getPersistentModuleObject("itil::asset");
         $o->SetFilter({id=>[keys(%assetid)]});
         my @l=$o->getHashList(qw(id name srcsys srcid  refreshstate acqumode
                                  assetrefreshstate age dataissuestate));
         for(my $c=0;$c<=$#l;$c++){
            $assetid{$l[$c]->{id}}->{acqumode}=
               $l[$c]->{acqumode};

            my $refreshstate=$l[$c]->{refreshstate};
            my $age=$l[$c]->{age};
            {  # detect Serverfarm Assets with no relevant Hardare-Refresh
               my @productline=keys($assetid{$l[$c]->{id}}->{productline});
               @productline=grep(!/^(ITSF-.*|DBaaS)$/,@productline);
               if ($#productline==-1){
                  $refreshstate="blue";
                  $age="";
               }
            }

            $assetid{$l[$c]->{id}}->{refreshstate}=$refreshstate;
            $assetid{$l[$c]->{id}}->{age}=$age;

            if (exists($l[$c]->{dataissuestate}->{id})){
               my $dicolor="red";
               my $eventstart=$l[$c]->{dataissuestate}->{eventstart};
               if ($eventstart ne ""){
                  my $d=CalcDateDuration($eventstart,NowStamp('en'));
                  if (defined($d) && $d->{days}<8*7){
                     $dicolor="yellow";
                  }
               }
               $assetid{$l[$c]->{id}}->{dataissue}=
                  $l[$c]->{dataissuestate}->{id}.",$dicolor";
               $appkpi->{'RMO.DataIssue.'.$dicolor}++;
            }
            else{
               $appkpi->{'RMO.DataIssue.green'}++;
            }
            if ($l[$c]->{srcid} ne "" && 
                lc($l[$c]->{srcsys}) eq "assetmanager"){
               $assetid{$l[$c]->{id}}->{assetid}=$l[$c]->{srcid};
            }
         }
      }
      if (keys(%systemid)){
         my $o=$app->getPersistentModuleObject("itil::lnksoftware");
         $o->SetFilter({systemid=>[keys(%systemid)],
                        softwareset=>'TEL-IT Patchmanagement 2019-10'});
         foreach my $swirec ($o->getHashList(qw(id fullname 
                                                softwareinstrelstate))){
            #print Dumper($swirec);
            $swinst{$swirec->{id}}={
                fullname=>$swirec->{fullname}
            };
         }
      }
      #print Dumper(\%swinst);




      my %colors=@{$self->{Colors}};
      foreach my $color (keys(%colors)){
         foreach my $prefix (qw(RMO.System.TCC.os RMO.Asset.age)){
            $appkpi->{$prefix.".".$color}=0;
         }
      }




      foreach my $sid (sort(keys(%systemid))){
         $appkpi->{'RMO.System.Count'}++;
         my $l="";
         
         $l.=$systemid{$sid}->{systemid}.";";
         $l.=$systemid{$sid}->{name}.";";
         $l.=$systemid{$sid}->{dataissue}.";";
         $l.=$systemid{$sid}->{assetid}.";";
         $l.=$systemid{$sid}->{systemsystemid}.";";
         $l.=$systemid{$sid}->{productline}.";";
         my $roadmap_color=$systemid{$sid}->{roadmap_color};
         if ($roadmap_color eq ""){
            $roadmap_color="gray";
         }
         $l.=$roadmap_color.";";
         if (in_array([keys(%colors)],$roadmap_color)){
            $appkpi->{'RMO.System.TCC.os.'.$roadmap_color}++;
         }
         $self->getParent->storeStatVar("Application",
                                        [$rec->{name}],
                                        {nosplit=>1,
                                         nameid=>$rec->{id},
                                         method=>'add'},
                                        "RMO.System",$l);
      }
      foreach my $iid (sort(keys(%instanceid))){
         $appkpi->{'RMO.Instance.Count'}++;
         my $l="";
         $l.=$instanceid{$iid}->{id}.";";
         $l.=$instanceid{$iid}->{name}.";";
         $l.=$instanceid{$iid}->{dataissue}.";";
         $self->getParent->storeStatVar("Application",
                                        [$rec->{name}],
                                        {nosplit=>1,
                                         nameid=>$rec->{id},
                                         method=>'add'},
                                        "RMO.Instance",$l);
      }
      foreach my $aid (sort(keys(%assetid))){
         $appkpi->{'RMO.Asset.Count'}++;
         my $l="";
         $l.=$assetid{$aid}->{id}.";";
         $l.=$assetid{$aid}->{assetid}.";";
         $l.=$assetid{$aid}->{dataissue}.";";
         $l.=$assetid{$aid}->{acqumode}.";";
         $l.=$assetid{$aid}->{refreshstate}.";";
         my $refreshstate=$assetid{$aid}->{refreshstate};
         $refreshstate=~s/\s.*$//;
         if (in_array([keys(%colors)],$refreshstate)){
            $appkpi->{'RMO.Asset.age.'.$refreshstate}++;
         }
         $l.=$assetid{$aid}->{age}.";";
         $self->getParent->storeStatVar("Application",
                                        [$rec->{name}],
                                        {nosplit=>1,
                                         nameid=>$rec->{id},
                                         method=>'add'},
                                        "RMO.Asset",$l);
      }
      my $mgmtitemgroup=$rec->{mgmtitemgroup};
      $mgmtitemgroup=[$mgmtitemgroup] if (ref($mgmtitemgroup) ne "ARRAY");
      if (grep(/^TOP.*Telekom.*$/i,@$mgmtitemgroup)){
         $self->getParent->storeStatVar("Group",\@repOrg,{},"RMO.Appl.Count",1);
         $self->getParent->storeStatVar("Application",[$rec->{name}],{
                                           nosplit=>1,nameid=>$rec->{id}
                                        },
                                        "RMO.Appl.Count",1);
         foreach my $k (keys(%$appkpi)){
            $self->getParent->storeStatVar("Group",\@repOrg,{},
                                           $k,$appkpi->{$k});
         }
      }
   }
}


1;
