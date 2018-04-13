#######################################################################
=pod

=encoding latin1

=head3 PURPOSE

Checks the ssl expiration on swinstances in cistate "installed/active"
or "available". If the expiration of the sslcheck url comes closer then
1 week, a dataissue will be generated.

=head3 IMPORTS

NONE

=head3 HINTS

[en:]

The Qrule checks on Software Instances in status "installed/active" or 
"available/ in project" if the certificate is available via the filled out URL.
It is important to ensure that the specified URL is accessible from the 
W5Base environment. Appropriate firewall permissions must be in place for 
this purpose.

[de:]

Die Qrule pr�ft an den Software-Instanzen im Status "installiert/aktiv" 
oder "verf�gbar/in Projektierung" ob das Zertifikat �ber die angegebene URL 
abrufbar ist.
Dabei ist darauf zu achten, dass die angegebene URL netzm��ig von der 
W5Base-Umgebung aus erreichbar ist. Evtl. sind daf�r entsprechende 
Firewall-Freischaltungen zu beauftragen.


=cut
#######################################################################
#  W5Base Framework
#  Copyright (C) 2009  Hartmut Vogler (it@guru.de)
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
package Net::ProxySSLconnect;
use IO::Socket::SSL;
use URI;
use kernel;
use base 'IO::Socket::SSL';
my $sockclass = 'IO::Socket::INET';
$sockclass .= '6' if eval "require IO::Socket::INET6";

sub configure {
   my ($self,$args) = @_;
   my $phost = URI->new($args->{Proxy});
   my $port = $args->{PeerPort};
   my $host = $args->{PeerHost} || $args->{PeerAddr};
   if ( ! $port ) {
      $host =~s{:(\w+)$}{};
      $port = $args->{PeerPort} = $1;
      $args->{PeerHost} = $host;
   }
   if ( $phost->scheme ne 'http' ) {
      $@ = "scheme ".$phost->scheme." not supported for https_proxy";
      Stacktrace(1);
      return;
   }
   my $auth = '';
   if ( my ($user,$pass) = split( ':', $phost->userinfo || '' ) ) {
      $auth = "Proxy-authorization: Basic ".
         encode_base64( uri_unescape($user).':'.uri_unescape($pass),'' ).
         "\r\n";
   }

   my $pport = $phost->port;
   $phost = $phost->host;

   # temporally downgrade $self so that the right connect chain
   # gets called w/o doing SSL stuff. If we don't do it it will
   # try to call IO::Socket::SSL::connect
   my $ssl_class = ref($self);
   bless $self,$sockclass;
   $self->configure({ %$args, PeerAddr => $phost, PeerPort => $pport }) or do {
      $@ = "connect to proxy $phost port $pport failed";
      return;
   };
   print $self "CONNECT $host:$port HTTP/1.0\r\n$auth\r\n";
   my $hdr = '';
   while (<$self>) {
      $hdr .= $_;
      last if $_ eq "\n" or $_ eq "\r\n";
   }
   if ( $hdr !~m{\AHTTP/1.\d 2\d\d} ) {
      # error
      $@ = "non 2xx response to CONNECT: $hdr";
      return;
   }

   # and upgrade self by calling start_SSL
   $ssl_class->start_SSL( $self,
      SSL_verifycn_name => $host,
      %$args
   ) or do {
      $@ = "start SSL failed: $SSL_ERROR";
      return;
   };
   return $self;
};

package itil::qrule::SWInstanceCertCheck;
use strict;
use vars qw(@ISA);
use kernel;
use kernel::QRule;
use itil::lib::Listedit;
@ISA=qw(kernel::QRule);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   return($self);
}

sub getPosibleTargets
{
   return(["itil::swinstance"]);
}

sub qcheckRecord
{
   my $self=shift;
   my $dataobj=shift;
   my $rec=shift;

   return(0,undef) if ($rec->{'cistatusid'}!=4 && 
                       $rec->{'cistatusid'}!=3);
   if ($rec->{'sslurl'} ne "" &&  # Eckige Klammern verhindern den autoscan
       !($rec->{'sslurl'}=~m/^\[.+\]$/)){
      my $newrec={};
      my $sslurl=$rec->{'sslurl'};
      my $sslstate=$rec->{'sslstate'};
      my $sslend=$rec->{'sslend'};
      my $sslbegin=$rec->{'sslbegin'};

      my $sslhost;
      my $sslport;
      if (my (undef,$host)=$sslurl=~m#^(https)://([^/]+)(/){0,1}$#){
         $sslhost=$host;
         $sslport=443;
      }
      if (my (undef,$host)=$sslurl=~m#^(ldaps)://([^/]+)(/){0,1}$#){
         $sslhost=$host;
         $sslport=636;
      }
      if (my (undef,$host,$port)=$sslurl
           =~m#^(http|https|ldaps)://([^/]+):(\d+)(/){0,1}$#){
         $sslhost=$host;
         $sslport=$port;
      }
      if (my ($host,$port)=$sslurl=~m#^([^/]+):(\d+)$#){
         $sslhost=$host;
         $sslport=$port;
      }
      my ($msg);
      if (defined($sslhost) && defined($sslport)){
         msg(DEBUG,"check %s",$rec->{fullname});
         eval('use Net::SSLeay;
               use IO::Socket::SSL;use Date::Parse;use Carp;
               ($msg,$sslbegin,$sslend)=
                        $self->checkSSL($sslhost,$sslport,$newrec);'); 
         if ($@ ne ""){
            msg(INFO,"message from eval in checkSSL $@");
            $sslstate=$@;
         }
         else{
            $sslstate=$msg;
         }
      }
      else{
         $sslstate="unknown URL format";
      }
      if ($sslstate ne ""){
         my $now=NowStamp("en");
         $newrec->{sslcheck}=$now;
         $newrec->{sslstate}=$sslstate;
         if (defined($sslend)){
            $newrec->{sslend}=sprintf("%s",$sslend);
         }
         else{
            $newrec->{sslend}=undef;
         }
         if (defined($sslbegin)){
            $newrec->{sslbegin}=sprintf("%s",$sslbegin);
         }
         else{
            $newrec->{sslbegin}=undef;
         }
         $newrec->{mdate}=$rec->{mdate};
         $newrec->{editor}=$rec->{editor};

         my $swop=$dataobj->Clone();
         #print STDERR Dumper($newrec);
         $swop->ValidatedUpdateRecord($rec,$newrec,{id=>\$rec->{id}});

         my $errorlevel=0;
         my @qmsg;
         my @dataissue;

         if ($sslstate=~m/OK/){
            if (!defined($sslend)){
               my $m="SSL check: invalid or undefined sslend returend";
               return(3,{qmsg=>[$m],dataissue=>[$m]});
            }

            my $ok=$self->itil::lib::Listedit::handleCertExpiration(
                                        $dataobj,$rec,undef,undef,
                                        \@qmsg,\@dataissue,\$errorlevel,
                                        {expnotifyfld=>'sslexpnotify1',
                                         expdatefld=>'sslend'});
            if (!$ok) {
               msg(ERROR,sprintf("QualityCheck of '%s' (%d) failed",
                                 $dataobj->Self(),$rec->{id}));
            }
         }
         else{
            push(@qmsg,"SSL check:".$sslstate);
            push(@dataissue,"SSL check:".$sslstate);
            $errorlevel=3 if ($errorlevel<3);
         }

         if ($#qmsg!=-1) {
            return($errorlevel,{qmsg=>\@qmsg,dataissue=>\@dataissue});
         }
      }
   }

   return(0,undef);
}

sub checkSSL
{
   my $self=shift;
   my $host=shift;
   my $port=shift;
   my $newrec=shift;

   msg(INFO,"Step2: try to connect to %s:%s SSLv3",$host,$port);
   $ENV{"HTTPS_VERSION"}="3";
   my $sock = IO::Socket::SSL->new(PeerAddr=>"$host:$port",
                                   SSL_version=>'SSLv23',
                                   SSL_verify_mode=>'SSL_VERIFY_NONE',
                                   Timeout=>10,
                                   SSL_session_cache_size=>0);
   #my $errstr=IO::Socket::SSL->errstr();
   #msg(ERROR,"connet error: $errstr");
   if (!defined($sock)){
      msg(INFO,"Step2.1: try to connect to %s:%s SSLv2",$host,$port);
      $sock = IO::Socket::SSL->new(PeerAddr=>"$host:$port",
                                   SSL_version=>'SSLv2',
                                   SSL_verify_mode=>'SSL_VERIFY_NONE',
                                   Timeout=>10,
                                   SSL_session_cache_size=>0);
     # my $errstr=IO::Socket::SSL->errstr();
     # msg(ERROR,"connet error: $errstr");
   }
   if (!defined($sock)){
      msg(INFO,"Step2.2: try to connect to %s:%s SSLv23",$host,$port);
      $sock = IO::Socket::SSL->new(PeerAddr=>"$host:$port",
                                   SSL_version=>'SSLv23',
                                   SSL_verify_mode=>'SSL_VERIFY_NONE',
                                   Timeout=>10,
                                   SSL_session_cache_size=>0);
     # my $errstr=IO::Socket::SSL->errstr();
     # msg(ERROR,"connet error: $errstr");
   }

   if (!defined($sock)){  # try to build connection over proxy
      my $proxy=$self->getParent->Config->Param("HTTPS_PROXY");
      if ($proxy eq ""){
         $proxy=$self->getParent->Config->Param("HTTP_PROXY");
      }
      msg(INFO,"Step2.2: try to connect over proxy %s",$proxy);
      $sock=new Net::ProxySSLconnect(PeerAddr=>"$host:$port",
                                     SSL_verify_mode=>'SSL_VERIFY_NONE',
                                     SSL_session_cache_size=>0,
                                     Proxy=>$proxy);
      if (defined($sock)){
         $newrec->{ssl_networkid}="11811326390001";
      }
   }
   else{
      $newrec->{ssl_networkid}="11811326110001";
   }

   
   return("SSL connect failed to $host:$port") if (!defined($sock));
   msg(INFO,"Step2: Connect done");
   msg(INFO,"Step3: try to load peer_certificate");
   my $cert = $sock->peer_certificate();

   if (1){

      my $certdump;
      eval('$certdump=$sock->dump_peer_certificate();');
      $newrec->{ssl_certdump}=$certdump if ($@ eq "");

      my $version;
      eval('$version = $sock->get_sslversion();');
      $newrec->{ssl_version}=$version if ($@ eq "");
  
      my $cipher;
      eval('$cipher=$sock->get_cipher();');
      $newrec->{ssl_cipher}=$cipher if ($@ eq "");

   }

   my ($begin_date,$expire_date)=();
   if ($cert){
      msg(INFO,"Step4: peer_certificate loaded");
      msg(INFO,"Step5: extracting data");
      my $expire_date_asn1=Net::SSLeay::X509_get_notAfter($cert);
      my $expireDate=Net::SSLeay::P_ASN1_UTCTIME_put2string($expire_date_asn1);
      ### $expire_date_str
      my $begin_date_asn1 =Net::SSLeay::X509_get_notBefore($cert);
      my $beginDate=Net::SSLeay::P_ASN1_UTCTIME_put2string($begin_date_asn1);
      msg(INFO,"Step6: date extraction done");
      $begin_date  = DateTime->from_epoch(epoch => str2time($beginDate));
      $expire_date = DateTime->from_epoch(epoch => str2time($expireDate));

      my $certserial;
      eval('$certserial=Net::SSLeay::X509_get_serialNumber($cert);');
      $newrec->{ssl_cert_serialno}=
         Net::SSLeay::P_ASN1_INTEGER_get_hex($certserial) if ($@ eq "");
      if (main->can("Net::SSLeay::P_X509_get_signature_alg")){
         my $cert_signature_algo;
         eval('$cert_signature_algo=
            Net::SSLeay::OBJ_obj2txt(
               Net::SSLeay::P_X509_get_signature_alg($cert)
            );
         ');
         $newrec->{ssl_cert_signature_algo}=$cert_signature_algo if ($@ eq "");
      }
      else{
         $newrec->{ssl_cert_signature_algo}='need Net::SSLeay update to detect';
      }
   }
   else{
      return("invalid peer cert response");
   }
   ### $begin_date_str


   $sock->close(SSL_fast_shutdown=>1);  # Ich weis nicht mehr, warum ich
                                        # das rein hatte (HV)
   #$sock->close();

   my $sslbegin=$self->getParent->ExpandTimeExpression($begin_date,'en','GMT');
   my $sslend=$self->getParent->ExpandTimeExpression($expire_date,'en','GMT');

   msg(INFO,"ssl result begin=%s expire=%s",$begin_date,$expire_date);
   return("check OK",$sslbegin,$sslend);
}



1;
