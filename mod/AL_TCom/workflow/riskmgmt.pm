package AL_TCom::workflow::riskmgmt;
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
use kernel::WfClass;
use itil::workflow::riskmgmt;
use Text::Wrap qw($columns &wrap);

@ISA=qw(itil::workflow::riskmgmt);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);
   return($self);
}

sub getDynamicFields
{
   my $self=shift;
   my %param=@_;
   my $class;

   return($self->InitFields(
      $self->SUPER::getDynamicFields(@_),
      new kernel::Field::Select(  name          =>'extdescdtagmonetaryimpact',
                                  label         =>'Estimated financial impact within DTAG over the entire duration of the damage',
                                  value         =>['','0','1','2','3'],
                                  default       =>'',
                                  transprefix   =>'DTAGMONIMP.',
                                  group         =>'riskdesc',
                                  container     =>'headref'),

      new kernel::Field::Select(  name          =>'extdesctelitmonetaryimpact',
                                  label         =>'Loss of IT - Immediate monetary impact within the Telekom IT',
                                  value         =>['','0','1','2','3','4'],
                                  default       =>'',
                                  transprefix   =>'TELITMONIMP.',
                                  group         =>'riskdesc',
                                  container     =>'headref'),


      ));

}


sub isRiskParameterComplete
{
   my $self=shift;
   my $oldrec=shift;
   my $newrec=shift;

   return(0) if (!$self->SUPER::isRiskParameterComplete($oldrec,$newrec));

   if (effVal($oldrec,$newrec,"extdescdtagmonetaryimpact") eq ""){
      return(0);
   }
   return(1);


}



sub calculateRiskState
{
   my $self=shift;
   my $current=shift;
   my $mode=shift;
   my $st=shift;

   $self->SUPER::calculateRiskState($current,$mode,$st);

   my $v={};
   foreach my $vname (qw(extdescriskoccurrency 
                         extdescdtagmonetaryimpact
                         itrmcriticality 
                         extdescarisedate)){
      my $fld=$self->getParent->getField("wffields.".$vname,$current);
      $v->{$vname}=$fld->RawValue($current);
   }

   if ($v->{extdescarisedate} eq ""){
      push(@{$st->{raw}->{riskmgmtstate}},"ERROR: missing date of rise");
   }
   if ($v->{extdescriskoccurrency} eq ""){
      push(@{$st->{raw}->{riskmgmtstate}},"ERROR: missing pct occurrency");
   }
   if ($v->{extdescdtagmonetaryimpact} eq ""){
      push(@{$st->{raw}->{riskmgmtstate}},"ERROR: missing DTAG mony impact");
   }
   if ($#{$st->{raw}->{riskmgmtstate}}!=-1){
      $st->{raw}->{riskmgmtcolor}="hotpink";
      $st->{raw}->{riskmgmtpoints}="???";
   }
   else{
      my $d=CalcDateDuration(NowStamp("en"),$v->{extdescarisedate});
      $v->{extdescarisedatedays}=$d->{days};

      push(@{$st->{raw}->{riskmgmtstate}},
           "INFO: days to rise:  $v->{extdescarisedatedays}");

      if ($v->{extdescarisedatedays}<30){
         $v->{extdescarisedatedayspoint}=3;
      }
      elsif ($v->{extdescarisedatedays}<6*30){
         $v->{extdescarisedatedayspoint}=2;
      }
      elsif ($v->{extdescarisedatedays}<12*30){
         $v->{extdescarisedatedayspoint}=1;
      }
      else{
         $v->{extdescarisedatedayspoint}=0;
      }

      push(@{$st->{raw}->{riskmgmtstate}},
           "INFO: days points :  $v->{extdescarisedatedayspoint}");



      push(@{$st->{raw}->{riskmgmtstate}},
           "INFO: DTAG money $v->{extdescdtagmonetaryimpact}");
      push(@{$st->{raw}->{riskmgmtstate}},
           "INFO: risk $v->{extdescriskoccurrency}");
      $v->{extdescriskoccurrencylevel}=0 if ($v->{extdescriskoccurrency} eq "0" ||
                                             $v->{extdescriskoccurrency} eq "1" ||
                                             $v->{extdescriskoccurrency} eq "2");
      
      $v->{extdescriskoccurrencylevel}=1 if ($v->{extdescriskoccurrency} eq "3" ||
                                             $v->{extdescriskoccurrency} eq "4" ||
                                             $v->{extdescriskoccurrency} eq "5");

      $v->{extdescriskoccurrencylevel}=2 if ($v->{extdescriskoccurrency} eq "6" ||
                                             $v->{extdescriskoccurrency} eq "7" ||
                                             $v->{extdescriskoccurrency} eq "8");
      
      $v->{extdescriskoccurrencylevel}=3 if ($v->{extdescriskoccurrency} eq "8" ||
                                             $v->{extdescriskoccurrency} eq "9" ||
                                             $v->{extdescriskoccurrency} eq "10"||
                                             $v->{extdescriskoccurrency} eq "11");
      push(@{$st->{raw}->{riskmgmtstate}},
           "INFO: risk level block $v->{extdescriskoccurrencylevel}");


      my $mtrx=[
             [ qw  (    0    0    1    2    3 ) ],
             [ qw  (    1    2    3    4    5 ) ],
             [ qw  (    2    4    6    8    9 ) ],
             [ qw  (    3    5    7    9   10 ) ]
      ];
      $v->{magicriskkey}=
         $mtrx->[$v->{extdescdtagmonetaryimpact}]->[$v->{extdescriskoccurrencylevel}];
      push(@{$st->{raw}->{riskmgmtstate}},
           "INFO: magic risk key $v->{magicriskkey}");

      $st->{raw}->{riskmgmtpoints}=$v->{magicriskkey}+$v->{extdescarisedatedayspoint}+$v->{itrmcriticality};

      if ($st->{raw}->{riskmgmtpoints}<=7){
         $st->{raw}->{riskmgmtcolor}="green";
      }
      elsif ($st->{raw}->{riskmgmtpoints}<=12){
         $st->{raw}->{riskmgmtcolor}="yellow";
      }
      else{
         $st->{raw}->{riskmgmtcolor}="red";
      }

      


   }






   
}





1;
