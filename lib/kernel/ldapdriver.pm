package kernel::ldapdriver;
#  W5Base Framework
#  Copyright (C) 2002  Hartmut Vogler (hartmut.vogler@epost.de)
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
use Net::LDAP;
use Net::LDAP::Control::Sort;
use Net::LDAP::Constant qw(LDAP_CONTROL_SORTRESULT);
use Time::HiRes;

@ISA=qw(kernel::Universal);

sub new
{
   my $type=shift;
   my $parent=shift;
   my $name=shift;
   my $self=bless({},$type);

   $self->setParent($parent);
   $self->{ldapname}=$name;
   $self->{isConnected}=0;

   return($self);
}

sub DESTROY
{
   my $self=shift;
   if (!defined($self->{SessionCacheKey})){
      unbindHandle($self->{ldap});
      delete($self->{ldap});
   }
}


sub unbindHandle
{
   my $ldaphandle=shift;
   if (defined($ldaphandle) && $ldaphandle->can("unbind")){
      $ldaphandle->unbind();
   }
   else{
      return(0);
   }
   return(1);
}


sub Connect
{
   my $self=shift;
   my $ldapname=$self->{ldapname};
   my %p=();
  
  # if ($self->{isConnected}){
  #    return($self->{'ldap'});
  # }
   my $BackendSessionName=$self->getParent->BackendSessionName();
   $BackendSessionName="default" if (!defined($BackendSessionName));

   if ($BackendSessionName ne "ForceUncached"){
      $self->{SessionCacheKey}=$BackendSessionName.':'.$ldapname; 
      if (exists($LDAPConnectionPool::Session{$self->{SessionCacheKey}})){
         my $cacheEntry=$LDAPConnectionPool::Session{$self->{SessionCacheKey}};
         if (time()-$cacheEntry->{atime}<300){
            $self->{ldap}=$cacheEntry->{ldap};
            $self->{isConnected}=1;
            return($self->{'ldap'});
         }
         else{
            unbindHandle($cacheEntry->{ldap});
            delete($LDAPConnectionPool::Session{$self->{SessionCacheKey}});
         }
      }
   }


   $p{ldapuser}=$self->getParent->Config->Param('DATAOBJUSER');
   $p{ldappass}=$self->getParent->Config->Param('DATAOBJPASS');
   $p{ldapserv}=$self->getParent->Config->Param('DATAOBJSERV');

   foreach my $v (qw(ldapuser ldappass ldapserv)){
      if ((ref($p{$v}) ne "HASH" || !defined($p{$v}->{$ldapname}))){
         return(undef,
                msg(ERROR,"Connect(%s): essential information '%s' missing",
                    $ldapname,$v));
      }
      if (defined($p{$v}->{$ldapname}) && $p{$v}->{$ldapname} ne ""){
         $self->{$v}=$p{$v}->{$ldapname};
      }
   }
   if (!($self->{ldap}=Net::LDAP->new($self->{ldapserv},
                                      timeout=>100,
                                      version=>'3',async=>0))){
      return(undef,msg(ERROR,"ldapbind '%s' while connect '%s'",
             $@,$self->{ldapserv}));
   }
   $self->{ldap}->bind($self->{ldapuser},password =>$self->{ldappass});


   if (!$self->{'ldap'}){
      return(undef,msg(ERROR,"Connect(%s): LDAP '%s'",$ldapname,
                       "can't connect"));
   }
   else{
      $self->{isConnected}=1;
      if (defined($self->{SessionCacheKey})){
         $LDAPConnectionPool::Session{$self->{SessionCacheKey}}={
            ldap=>$self->{'ldap'},
            atime=>time()
         };
      }
   }

   return($self->{'ldap'});
}

sub getErrorMsg
{
   return("getErrorMsg:ldap errorstring");
}

sub checksoftlimit
{
   my $self=shift;
   my $cmd=shift;
   delete($self->{softlimit});
}


sub execute 
{
   my $self=shift;
   my @param=@_;
   my %p=@param;

   if ($self->{ldap}){
      my $c=$self->getParent->Context;

      my $ldaporderstring=$self->getParent->getLdapOrder();
      #my $sort = Net::LDAP::Control::Sort->new(order=>$ldaporderstring);
      #push(@param,"control"=>[$sort]);
      # - sort request did not work on whoishwo
      my $sseconds=Time::HiRes::time();
      $c->{$self->{ldapname}}->{sth}=$self->{'ldap'}->search(@param);
      my $eseconds=Time::HiRes::time();
      my $slowlimit=20;
      if ($self->getParent->Config->Param("W5BaseOperationMode") eq "dev"){
         $slowlimit=8;
      }
      if ($eseconds-$sseconds>$slowlimit){
        my $t=sprintf("%.3lf",$eseconds-$sseconds);
        my $s=$self->getParent->Self();
        my $q=$p{filter};
        msg(WARN,"slow LDAP Query on $s with query $q (duration=$t sec)");
      }
      $self->getParent->Log(INFO,"ldapread","query $p{filter} ".
                            sprintf("%.2sec",$eseconds-$sseconds));


      if (!($c->{$self->{ldapname}}->{sth})){
         return(undef,msg(ERROR,"problem while LDAP search"));
      }
      if ($c->{$self->{ldapname}}->{sth}->code()){
         $c->{$self->{ldapname}}->{sthdata}=[];
         $c->{$self->{ldapname}}->{sthcount}=0;
         return(undef,msg(ERROR,"ldap-search:%s (%s)",
                          $c->{$self->{ldapname}}->{sth}->error,
                          Dumper(\@param)));
      }
      my $resultsorted=0;
                     
      #{ # sort handling
      #   my ($resp)=$c->{$self->{ldapname}}->{sth}->control(
      #      LDAP_CONTROL_SORTRESULT
      #   );
      #   if (defined($resp)){
      #      die('unexpeded sorted result'); # sort handling mu� noch
      #                                      # programmiert werden (hv 02/2016)
      #   }
      #}
      if (!$resultsorted){    # do client sort
         my $tmpres=[$c->{$self->{ldapname}}->{sth}->all_entries()];
         my @sortkeys=split(/\s/,$ldaporderstring);
         $tmpres=[sort({
            my @cmpstr=([],[]);
            my @sk=@sortkeys;
            foreach my $sk (@sk){
               my $c=0;
               foreach my $entry ($a,$b){
                  foreach my $attr ($entry->attributes) {
                     if ($attr eq $sk){
                        my @val=$entry->get_value($attr);
                        for(my $c=0;$c<=$#val;$c++){
                           $val[$c]=utf8_to_latin1($val[$c]);
                        }
                        push(@{$cmpstr[$c]},join(",",@val));
                     }
                  }
                  $c++;
               }
            }
            my $bk=0;
            for(my $cc=0;$cc<=$#sk;$cc++){
               $bk=$cmpstr[0]->[$cc] cmp $cmpstr[1]->[$cc];
               last if ($bk!=0);
            }
            $bk;
         } @{$tmpres})];
         $c->{$self->{ldapname}}->{sthdata}=$tmpres;
      }
      else{
         $c->{$self->{ldapname}}->{sthdata}=
             [$c->{$self->{ldapname}}->{sth}->all_entries()];
      }
      $c->{$self->{ldapname}}->{sthcount}=
          $#{$c->{$self->{ldapname}}->{sthdata}}+1;
      #printf STDERR ("fifi kernel::ldapdriver found %d entries\n",
      #               $#{$c->{$self->{ldapname}}->{sthdata}}+1);
      return($c->{$self->{ldapname}}->{sth});
   }
   return(undef);
}

sub rows
{
   my $self=shift;
   my $c=$self->getParent->Context;
   if (defined($c->{$self->{ldapname}}->{sthcount})){
      return($c->{$self->{ldapname}}->{sthcount}-
             $#{$c->{$self->{ldapname}}->{sthdata}}-1);
   }
   return(undef);
}

sub finish
{
   my $self=shift;
   my $c=$self->getParent->Context;
   delete($c->{$self->{ldapname}}->{sth});
   delete($c->{$self->{ldapname}}->{sthdata});
   delete($c->{$self->{ldapname}}->{sthcount});
}

   
sub fetchrow
{
   my $self=shift;
   my $c=$self->getParent->Context;

   my $entry=shift(@{$c->{$self->{ldapname}}->{sthdata}});
   if ($entry){
      my %rec=();
      foreach my $attr ($entry->attributes) {
         my @val=$entry->get_value($attr);
         for(my $c=0;$c<=$#val;$c++){
            $val[$c]=utf8_to_latin1($val[$c]);
         }
         if ($#val>0){
            $rec{$attr}=\@val;
         }
         else{
            $rec{$attr}=$val[0];
         }
      }
      return(\%rec);
   }

   return(undef);
}

sub getCurrent
{
   my $self=shift;
   my $c=$self->getParent->Context;
   return($c->{$self->{dbname}}->{'current'});
}

sub do
{
   my $self=shift;
   my $cmd=shift;


   if (defined($self->{SessionCacheKey})){
      if (exists($LDAPConnectionPool::Session{$self->{SessionCacheKey}})){
         my $cacheEntry=$LDAPConnectionPool::Session{$self->{SessionCacheKey}};
         $cacheEntry->{atime}=time();
      }
   }

   $cmd.=" /* W5BaseUser: $ENV{REMOTE_USER} */" if ($ENV{REMOTE_USER} ne "");
   if ($self->{'db'}){
      if ($self->{'db'}->do($cmd,{},@_)){
         return($self->{'db'});
      }
      else{
         msg(ERROR,"do('%s')",$cmd);
      }
   }
   return(undef);
}

END{
   foreach my $SessionCacheKey (keys(%LDAPConnectionPool::Session)){
      my $cacheEntry=$LDAPConnectionPool::Session{$SessionCacheKey};
      unbindHandle($cacheEntry->{ldap});
      delete($LDAPConnectionPool::Session{$SessionCacheKey});
   }
}



1;

