package itil::workflow::itquotation;
#  W5Base Framework
#  Copyright (C) 2011  Hartmut Vogler (it@guru.de)
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
use base::workflow::request;
use itil::workflow::base;
@ISA=qw(base::workflow::request itil::workflow::base);

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
   $self->AddGroup("customerdata",translation=>'itil::workflow::itquotation');
   $self->itil::workflow::base::Init();
   return($self->SUPER::Init(@_));
}

sub getDynamicFields
{
   my $self=shift;
   my %param=@_;
   my $class;

   return($self->InitFields(
      new kernel::Field::Select(  name       =>'reqnature',
                                  label      =>'Request nature',
                                  translateion=>'itil::workflow::itquotation',
                                  value      =>['RUser',
                                                'RGroup',
                                                'RApp.developer',
                                                'RApp.businessteam',
                                                'RApp.opm',
                                                'RApp.tsm'],
                                  container  =>'headref'),

#      new kernel::Field::Text(    name       =>'customerrefno',
#                                  htmleditwidth=>'150px',
#                                  group      =>'customerdata',
#                                  translation=>'itil::workflow::itquotation',
#                                  searchable =>0,
#                                  expandvar  =>\&expandVar,
#                                  container  =>'headref',
#                                  label      =>'Reference'),
#
#      new kernel::Field::Text(    name       =>'reqdesdate',
#                                  label      =>'desired date',
#                                  group      =>'default',
#                                  container  =>'headref'),

    ),$self->SUPER::getDynamicFields(%param));



}

sub expandVar
{
   my $self=shift;
   my $var=shift;
   my $current=shift;

   if ($var eq "W5BaseID"){
      return($current->{id});
   }

   return("?");
}


sub XgetRequestNatureOptions
{
   my $self=shift;
   return($self->getParent->getRequestNatureOptions());
}
sub getRequestNatureOptions
{
   my $self=shift;
   my $vv=['operation','project','modification','inquiry','other'];
   my @l;
   foreach my $v (@$vv){
      push(@l,$v,$v);
   }
   return(@l);
}


sub isWorkflowManager
{
   my $self=shift;
   my $WfRec=shift;

   if (defined($WfRec->{id}) &&   # only if a workflow exists, a workflow
       $WfRec->{stateid}<16){     # manager can be calculated
      my $userid=$self->getParent->getCurrentUserId();
     
      my @devcon=$self->getDefaultContractor($WfRec);
     
      my $msg=shift(@devcon);
     
      while(my $target=shift(@devcon)){
         my $targetid=shift(@devcon);
         if ($target eq "base::user" && $targetid eq $userid){
            return(1);
         }
         if ($target eq "base::grp" && $targetid ne ""){
            if ($self->getParent->IsMemberOf($targetid,"RMember","direct")){
               return(1);
            }
         }
      }
   }
   return(0);
}


sub getDefaultContractor
{
   my $self=shift;
   my $WfRec=shift;
   my $actions=shift;
   my $target;
   my $flt;

   if (defined($WfRec->{affectedapplication})){
      my $applname=$WfRec->{affectedapplication};
      if (ref($applname) eq "ARRAY"){
         $flt={name=>\$applname->[0]};
      } 
      else{
         $flt={name=>\$applname};
      }
   }
   if (defined($WfRec->{affectedapplicationid})){
      my $applid=$WfRec->{affectedapplicationid};
      if (ref($applid) eq "ARRAY"){
         $flt={id=>\$applid->[0]};
      } 
      else{
         $flt={id=>\$applid};
      }
   }
   my @devcon;
   if (defined($flt)){
      my $appl=getModuleObject($self->getParent->Config,"itil::appl");
      $appl->SetFilter($flt);
      my ($cur,$msg)=$appl->getOnlyFirst(qw(allowitquotation sem semid 
                                            contacts id name));
      if (defined($cur) && defined($cur->{contacts})){
         if (!defined($WfRec->{affectedapplicationid})){
            $WfRec->{affectedapplicationid}=$cur->{id};
         }
         if (!defined($WfRec->{affectedapplication})){
            $WfRec->{affectedapplication}=$cur->{name};
         }
         my $c=$cur->{contacts};
         if (ref($c) eq "ARRAY"){
            foreach my $con (@$c){
               my $roles=$con->{roles};
               $roles=[$roles] if (ref($roles) ne "ARRAY");
               if (grep(/^orderin1$/,@$roles)){
                  unshift(@devcon,{target=>$con->{target},
                                   targetid=>$con->{targetid}});
               } 
               if (grep(/^orderin2$/,@$roles)){
                  push(@devcon,{target=>$con->{target},
                                targetid=>$con->{targetid}});
               } 
            }
         }
         if ($#devcon==-1){
            if ($cur->{sem} ne "" && $cur->{semid} ne ""){
               push(@devcon,{target=>"base::user",targetid=>$cur->{semid}});
            }
         }
         if (!$cur->{allowitquotation}){
            $self->LastMsg(ERROR,"business requests are disabled ".
                                 "for the desired application");
            return(undef);
         }
      }
   }
   else{
      $self->LastMsg(ERROR,"no reference to related application specified");
      return(undef);
   }
   if ($#devcon==-1){
      $self->LastMsg(ERROR,"no orderin found");
      return(undef);
   }
   return(undef,map({$_->{target},$_->{targetid}} @devcon));
}


sub getStepByShortname
{
   my $self=shift;
   my $shortname=shift;
   my $WfRec=shift;

   if ($shortname eq "dataload"){
      return("itil::workflow::itquotation::".$shortname);
   }
   return($self->SUPER::getStepByShortname($shortname,$WfRec));
}

sub isViewValid
{
   my $self=shift;
   return($self->SUPER::isViewValid(@_),"affected","customerdata");
}

sub isWriteValid
{
   my $self=shift;
   my @l=$self->SUPER::isWriteValid(@_);
   if (grep(/^default$/,@l)){
      push(@l,"customerdata");
   }
   return(@l);
}

sub getDetailBlockPriority            # posibility to change the block order
{
   return("header","default","affected","customerdata","init","flow");
}

#sub getRecordImageUrl
#{
#   my $self=shift;
#   my $cgi=new CGI({HTTP_ACCEPT_LANGUAGE=>$ENV{HTTP_ACCEPT_LANGUAGE}});
#   return("../../../public/itil/load/workflow_appl.jpg?".$cgi->query_string());
#}

sub getPosibleRelations
{
   my $self=shift;
   my $WfRec=shift;
   return("itil::workflow::itquotation"=>'relbuisreq',
          "itil::workflow::itquotation"=>'reldevreq'); 
}









#######################################################################
package itil::workflow::itquotation::dataload;
use vars qw(@ISA);
use kernel;
@ISA=qw(base::workflow::request::dataload);

sub generateWorkspace
{
   my $self=shift;
   my $WfRec=shift;
   my $actions=shift;

   my $oldval=Query->Param("Formated_prio");
   $oldval="5" if (!defined($oldval));
   my $d="<select name=Formated_prio style=\"width:100px\">";
   my @l=("high"=>3,"normal"=>5,"low"=>8);
   while(my $n=shift(@l)){
      my $i=shift(@l);
      $d.="<option value=\"$i\"";
      $d.=" selected" if ($i==$oldval);
      $d.=">".$self->T($n,"base::workflow")."</option>";
   }
   $d.="</select>";

   my $templ=<<EOF;
<table border=0 cellspacing=0 cellpadding=0 width=100%>
<tr>
<td class=fname width=20%>%name(label)%:</td>
<td colspan=3 class=finput>%name(detail)%</td>
</tr>
<tr>
<td class=fname valign=top width=20%>%detaildescription(label)%:</td>
<td colspan=3 class=finput>%detaildescription(detail)%</td>
</tr>
<tr>
<td class=fname>%reqnature(label)%:</td>
<td colspan=3 class=finput>%reqnature(detail)%</td>
</tr>
<tr>
<td colspan=4>

<div id=app style="height:60px;padding:5px;margin:15px;border-style:solid;border-width:2px;border-color:black">
<table width=100% border=1>
<tr>
<td class=fname>%affectedapplication(label)%:</td>
<td class=finput>%affectedapplication(detail)%</td>
</tr>
</table>
</div>

<div id=fwd style="height:60px;padding:5px;margin:15px;border-style:solid;border-width:2px;border-color:black">
<table width=100% border=1>
<tr>
<td class=fname width=1% nowrap>%fwdtargetname(label)%:</td>
<td class=finput>%fwdtargetname(detail)%</td>
</tr>
</table>
</div>




</td>
</tr>
<tr>
<td class=fname>%forceinitiatorgroupid(label)%:</td>
<td colspan=3 class=finput>%forceinitiatorgroupid(detail)%</td>
</tr>
</table>
<script language="JavaScript">
setFocus("Formated_name");
setEnterSubmit(document.forms[0],"NextStep");
function setInitFormLayout(reqnature){
  var fdiv=document.getElementById("fwd");
  var adiv=document.getElementById("app");
  if (reqnature.match(/^RApp\\./)){
     adiv.style.visibility='visible';
     adiv.style.display='block';
     fdiv.style.visibility='hidden';
     fdiv.style.display='none';
  } 
  else{
     fdiv.style.visibility='visible';
     fdiv.style.display='block';
     adiv.style.visibility='hidden';
     adiv.style.display='none';
  }
}
window.onload = function() {
    document.forms[0].elements['Formated_reqnature'].onchange=function(){
      setInitFormLayout(document.forms[0].elements['Formated_reqnature'].value);
    };
    setInitFormLayout(document.forms[0].elements['Formated_reqnature'].value);
}
</script>
EOF
   return($templ);
}

sub nativProcess
{
   my $self=shift;
   my $action=shift;
   my $h=shift;
   my $WfRec=shift;
   my $actions=shift;

   if ($action eq "NextStep"){
      if ($h->{reqdesdate} eq ""){
         $h->{reqdesdate}="as soon as posible / baldmöglichst";
      }
      my $flt;
      if ($h->{affectedapplication} ne ""){
         $flt={name=>\$h->{affectedapplication}}; 
      }
      if ($h->{affectedapplicationid} ne ""){
         $flt={id=>\$h->{affectedapplicationid}}; 
      }
      if (defined($flt)){
         my $appl=getModuleObject($self->getParent->Config,"itil::appl");
         $appl->SetFilter($flt);
         my ($arec)=$appl->getOnlyFirst(qw(mandator mandatorid conumber
                                           custcontracts
                                           customer customerid));
         if (defined($arec)){
            $h->{mandatorid}=[$arec->{mandatorid}];
            $h->{mandator}=[$arec->{mandator}];
            $h->{involvedcustomer}=[$arec->{customer}];
            $h->{involvedcostcenter}=[$arec->{conumber}];
            if (ref($arec->{custcontracts}) eq "ARRAY"){
               my %custcontractid;
               my %custcontract;
               foreach my $rec (@{$arec->{custcontracts}}){
                  if (defined($rec->{custcontractid})){
                     $custcontractid{$rec->{custcontractid}}=1;
                  }
                  if (defined($rec->{custcontract})){
                     $custcontract{$rec->{custcontract}}=1;
                  }
               }
               if (keys(%custcontractid)){
                  $h->{affectedcontractid}=[keys(%custcontractid)];
               }
               if (keys(%custcontract)){
                  $h->{affectedcontract}=[keys(%custcontract)];
               }
            }

         }
         else{
            $self->LastMsg(ERROR,"can not find a related mandator");
            return(0);
         }
      }
      else{
         $self->LastMsg(ERROR,"no applicationid findable");
         return(0);
      }
   }

   return($self->SUPER::nativProcess($action,$h,$WfRec,$actions));
}




sub Process
{
   my $self=shift;
   my $action=shift;
   my $WfRec=shift;
   my $actions=shift;

   if ($action eq "NextStep"){
      my $fo=$self->getField("affectedapplication");
      my $foval=Query->Param("Formated_".$fo->Name());
      if ($foval=~m/^\s*$/){
         $self->LastMsg(ERROR,"no application specified");
         return(0);
      }
      if (!$fo->Validate($WfRec,{$fo->Name=>$foval})){
         $self->LastMsg(ERROR,"unknown error") if (!$self->LastMsg());
         return(0);
      }
      
   }
   return($self->SUPER::Process($action,$WfRec));
}

sub Validate
{
   my $self=shift;
   my $oldrec=$_[0];
   my $newrec=$_[1];
   my $found=0;

   my $aid=effVal($oldrec,$newrec,"affectedapplicationid");
   if ($aid ne ""){
      $aid=[$aid] if (ref($aid) ne "ARRAY");
      my $co=getModuleObject($self->getParent->Config,"itil::costcenter");
      my $app=getModuleObject($self->getParent->Config,"itil::appl");

      $app->SetFilter({id=>$aid});
      my @l=$app->getHashList(qw(custcontracts mandator 
                                 conumber mandatorid));


      my %custcontract;
      my %custcontractid;
      my %mandator;
      my %mandatorid;
      my %conumber;
      foreach my $apprec (@l){
         if (defined($apprec->{mandator})){
            $mandator{$apprec->{mandator}}=1;
         }
         if (defined($apprec->{mandatorid})){
            $mandatorid{$apprec->{mandatorid}}=1;
         }
         if (defined($apprec->{conumber}) && $apprec->{conumber} ne ""){
            $co->ResetFilter();
            $co->SetFilter({name=>\$apprec->{conumber},cistatusid=>"<=4"});
            my ($corec)=$co->getOnlyFirst("id");
            if (!defined($corec)){
               $self->LastMsg(ERROR,"invalid or inactive costcenter ".
                                    "used in application configuration");
               return(0);
            }
            $conumber{$apprec->{conumber}}=1;
         }
         next if (!defined($apprec->{custcontracts}));
         foreach my $rec (@{$apprec->{custcontracts}}){
            if (defined($rec->{custcontractid})){
               $custcontractid{$rec->{custcontractid}}=1;
            }
            if (defined($rec->{custcontract})){
               $custcontract{$rec->{custcontract}}=1;
            }
         }
      }
      if (keys(%custcontractid)){
         $newrec->{affectedcontractid}=[keys(%custcontractid)];
      }
      if (keys(%custcontract)){
         $newrec->{affectedcontract}=[keys(%custcontract)];
      }
      if (keys(%mandator)){
         $newrec->{mandator}=[keys(%mandator)];
      }
      if (keys(%mandatorid)){
         $newrec->{mandatorid}=[keys(%mandatorid)];
      }
      if (keys(%conumber)){
         $found++;
         $newrec->{involvedcostcenter}=[keys(%conumber)];
      }
   }
   if ($found!=1){
      $self->LastMsg(ERROR,"no valid application found in request");
      return(0);
   }
   
   return($self->SUPER::Validate(@_));

}







sub getWorkHeight
{
   my $self=shift;
   my $WfRec=shift;

   return("340");
}

1;
