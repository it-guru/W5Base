#!/usr/bin/perl
use strict;
use CGI qw/:standard/;
use Data::Dumper;
use JSON;
use URI;
use IO::Socket::INET;
use Time::HiRes;



<<<<<<< HEAD
=======


%ssl3ciphers = (
	'ECDHE-RSA-AES256-SHA' => 'AES 256 bits, RSA Auth, SHA1 MAC, ECDH Kx',
	'ECDHE-ECDSA-AES256-SHA' => 'AES 256 bits, ECDSA Auth, SHA1 MAC, ECDH Kx',
	'SRP-DSS-AES-256-CBC-SHA' => 'AES 256 bits, DSS Auth, SHA1 MAC, SRP Kx',
	'SRP-RSA-AES-256-CBC-SHA' => 'AES 256 bits, RSA Auth, SHA1 MAC, SRP Kx',
	'SRP-AES-256-CBC-SHA' => 'AES 256 bits, SRP Auth, SHA1 MAC, SRP Kx',
	'DHE-RSA-AES256-SHA' => 'AES 256 bits, RSA Auth, SHA1 MAC, DH Kx',
	'DHE-DSS-AES256-SHA' => 'AES 256 bits, DSS Auth, SHA1 MAC, DH Kx',
	'DHE-RSA-CAMELLIA256-SHA' => 'Camellia 256 bits, RSA Auth, SHA1 MAC, DH Kx',
	'DHE-DSS-CAMELLIA256-SHA' => 'Camellia 256 bits, DSS Auth, SHA1 MAC, DH Kx',
	'AECDH-AES256-SHA' => 'AES 256 bits, Null Auth, SHA1 MAC, ECDH Kx',
	'ADH-AES256-SHA' => 'AES 256 bits, Null Auth, SHA1 MAC, DH Kx',
	'ADH-CAMELLIA256-SHA' => 'Camellia 256 bits, Null Auth, SHA1 MAC, DH Kx',
	'ECDH-RSA-AES256-SHA' => 'AES 256 bits, ECDH Auth, SHA1 MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-AES256-SHA' => 'AES 256 bits, ECDH Auth, SHA1 MAC, ECDH/ECDSA Kx',
	'AES256-SHA' => 'AES 256 bits, RSA Auth, SHA1 MAC, RSA Kx',
	'CAMELLIA256-SHA' => 'Camellia 256 bits, RSA Auth, SHA1 MAC, RSA Kx',
	'PSK-AES256-CBC-SHA' => 'AES 256 bits, PSK Auth, SHA1 MAC, PSK Kx',
	'ECDHE-RSA-DES-CBC3-SHA' => '3DES 168 bits, RSA Auth, SHA1 MAC, ECDH Kx',
	'ECDHE-ECDSA-DES-CBC3-SHA' => '3DES 168 bits, ECDSA Auth, SHA1 MAC, ECDH Kx',
	'SRP-DSS-3DES-EDE-CBC-SHA' => '3DES 168 bits, DSS Auth, SHA1 MAC, SRP Kx',
	'SRP-RSA-3DES-EDE-CBC-SHA' => '3DES 168 bits, RSA Auth, SHA1 MAC, SRP Kx',
	'SRP-3DES-EDE-CBC-SHA' => '3DES 168 bits, SRP Auth, SHA1 MAC, SRP Kx',
	'EDH-RSA-DES-CBC3-SHA' => '3DES 168 bits, RSA Auth, SHA1 MAC, DH Kx',
	'EDH-DSS-DES-CBC3-SHA' => '3DES 168 bits, DSS Auth, SHA1 MAC, DH Kx',
	'AECDH-DES-CBC3-SHA' => '3DES 168 bits, Null Auth, SHA1 MAC, ECDH Kx',
	'ADH-DES-CBC3-SHA' => '3DES 168 bits, Null Auth, SHA1 MAC, DH Kx',
	'ECDH-RSA-DES-CBC3-SHA' => '3DES 168 bits, ECDH Auth, SHA1 MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-DES-CBC3-SHA' => '3DES 168 bits, ECDH Auth, SHA1 MAC, ECDH/ECDSA Kx',
	'DES-CBC3-SHA' => '3DES 168 bits, RSA Auth, SHA1 MAC, RSA Kx',
	'PSK-3DES-EDE-CBC-SHA' => '3DES 168 bits, PSK Auth, SHA1 MAC, PSK Kx',
	'ECDHE-RSA-AES128-SHA' => 'AES 128 bits, RSA Auth, SHA1 MAC, ECDH Kx',
	'ECDHE-ECDSA-AES128-SHA' => 'AES 128 bits, ECDSA Auth, SHA1 MAC, ECDH Kx',
	'SRP-DSS-AES-128-CBC-SHA' => 'AES 128 bits, DSS Auth, SHA1 MAC, SRP Kx',
	'SRP-RSA-AES-128-CBC-SHA' => 'AES 128 bits, RSA Auth, SHA1 MAC, SRP Kx',
	'SRP-AES-128-CBC-SHA' => 'AES 128 bits, SRP Auth, SHA1 MAC, SRP Kx',
	'DHE-RSA-AES128-SHA' => 'AES 128 bits, RSA Auth, SHA1 MAC, DH Kx',
	'DHE-DSS-AES128-SHA' => 'AES 128 bits, DSS Auth, SHA1 MAC, DH Kx',
	'DHE-RSA-SEED-SHA' => 'SEED 128 bits, RSA Auth, SHA1 MAC, DH Kx',
	'DHE-DSS-SEED-SHA' => 'SEED 128 bits, DSS Auth, SHA1 MAC, DH Kx',
	'DHE-RSA-CAMELLIA128-SHA' => 'Camellia 128 bits, RSA Auth, SHA1 MAC, DH Kx',
	'DHE-DSS-CAMELLIA128-SHA' => 'Camellia 128 bits, DSS Auth, SHA1 MAC, DH Kx',
	'AECDH-AES128-SHA' => 'AES 128 bits, Null Auth, SHA1 MAC, ECDH Kx',
	'ADH-AES128-SHA' => 'AES 128 bits, Null Auth, SHA1 MAC, DH Kx',
	'ADH-SEED-SHA' => 'SEED 128 bits, Null Auth, SHA1 MAC, DH Kx',
	'ADH-CAMELLIA128-SHA' => 'Camellia 128 bits, Null Auth, SHA1 MAC, DH Kx',
	'ECDH-RSA-AES128-SHA' => 'AES 128 bits, ECDH Auth, SHA1 MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-AES128-SHA' => 'AES 128 bits, ECDH Auth, SHA1 MAC, ECDH/ECDSA Kx',
	'AES128-SHA' => 'AES 128 bits, RSA Auth, SHA1 MAC, RSA Kx',
	'SEED-SHA' => 'SEED 128 bits, RSA Auth, SHA1 MAC, RSA Kx',
	'CAMELLIA128-SHA' => 'Camellia 128 bits, RSA Auth, SHA1 MAC, RSA Kx',
	'PSK-AES128-CBC-SHA' => 'AES 128 bits, PSK Auth, SHA1 MAC, PSK Kx',
	'ECDHE-RSA-RC4-SHA' => 'RC4 128 bits, RSA Auth, SHA1 MAC, ECDH Kx',
	'ECDHE-ECDSA-RC4-SHA' => 'RC4 128 bits, ECDSA Auth, SHA1 MAC, ECDH Kx',
	'AECDH-RC4-SHA' => 'RC4 128 bits, Null Auth, SHA1 MAC, ECDH Kx',
	'ADH-RC4-MD5' => 'RC4 128 bits, Null Auth, MD5 MAC, DH Kx',
	'ECDH-RSA-RC4-SHA' => 'RC4 128 bits, ECDH Auth, SHA1 MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-RC4-SHA' => 'RC4 128 bits, ECDH Auth, SHA1 MAC, ECDH/ECDSA Kx',
	'RC4-SHA' => 'RC4 128 bits, RSA Auth, SHA1 MAC, RSA Kx',
	'RC4-MD5' => 'RC4 128 bits, RSA Auth, MD5 MAC, RSA Kx',
	'PSK-RC4-SHA' => 'RC4 128 bits, PSK Auth, SHA1 MAC, PSK Kx',
	'EDH-RSA-DES-CBC-SHA' => 'DES 56 bits, RSA Auth, SHA1 MAC, DH Kx',
	'EDH-DSS-DES-CBC-SHA' => 'DES 56 bits, DSS Auth, SHA1 MAC, DH Kx',
	'ADH-DES-CBC-SHA' => 'DES 56 bits, Null Auth, SHA1 MAC, DH Kx',
	'DES-CBC-SHA' => 'DES 56 bits, RSA Auth, SHA1 MAC, RSA Kx',
	'EXP-EDH-RSA-DES-CBC-SHA' => 'DES 40 bits, RSA Auth, SHA1 MAC, DH(512) Kx',
	'EXP-EDH-DSS-DES-CBC-SHA' => 'DES 40 bits, DSS Auth, SHA1 MAC, DH(512) Kx',
	'EXP-ADH-DES-CBC-SHA' => 'DES 40 bits, Null Auth, SHA1 MAC, DH(512) Kx',
	'EXP-DES-CBC-SHA' => 'DES 40 bits, RSA Auth, SHA1 MAC, RSA(512) Kx',
	'EXP-RC2-CBC-MD5' => 'RC2 40 bits, RSA Auth, MD5 MAC, RSA(512) Kx',
	'EXP-ADH-RC4-MD5' => 'RC4 40 bits, Null Auth, MD5 MAC, DH(512) Kx',
	'EXP-RC4-MD5' => 'RC4 40 bits, RSA Auth, MD5 MAC, RSA(512) Kx',
	'ECDHE-RSA-NULL-SHA' => 'Null, RSA Auth, SHA1 MAC, ECDH Kx',
	'ECDHE-ECDSA-NULL-SHA' => 'Null, ECDSA Auth, SHA1 MAC, ECDH Kx',
	'AECDH-NULL-SHA' => 'Null, Null Auth, SHA1 MAC, ECDH Kx',
	'ECDH-RSA-NULL-SHA' => 'Null, ECDH Auth, SHA1 MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-NULL-SHA' => 'Null, ECDH Auth, SHA1 MAC, ECDH/ECDSA Kx',
	'NULL-SHA' => 'Null, RSA Auth, SHA1 MAC, RSA Kx',
	'NULL-MD5' => 'Null, RSA Auth, MD5 MAC, RSA Kx'
);


%tlsv12ciphers = (
	'ECDHE-RSA-AES256-GCM-SHA384' => 'AESGCM 256 bits, RSA Auth, AEAD MAC, ECDH Kx',
	'ECDHE-ECDSA-AES256-GCM-SHA384' => 'AESGCM 256 bits, ECDSA Auth, AEAD MAC, ECDH Kx',
	'ECDHE-RSA-AES256-SHA384' => 'AES 256 bits, RSA Auth, SHA384 MAC, ECDH Kx',
	'ECDHE-ECDSA-AES256-SHA384' => 'AES 256 bits, ECDSA Auth, SHA384 MAC, ECDH Kx',
	'DHE-DSS-AES256-GCM-SHA384' => 'AESGCM 256 bits, DSS Auth, AEAD MAC, DH Kx',
	'DHE-RSA-AES256-GCM-SHA384' => 'AESGCM 256 bits, RSA Auth, AEAD MAC, DH Kx',
	'DHE-RSA-AES256-SHA256' => 'AES 256 bits, RSA Auth, SHA256 MAC, DH Kx',
	'DHE-DSS-AES256-SHA256' => 'AES 256 bits, DSS Auth, SHA256 MAC, DH Kx',
	'ADH-AES256-GCM-SHA384' => 'AESGCM 256 bits, Null Auth, AEAD MAC, DH Kx',
	'ADH-AES256-SHA256' => 'AES 256 bits, Null Auth, SHA256 MAC, DH Kx',
	'ECDH-RSA-AES256-GCM-SHA384' => 'AESGCM 256 bits, ECDH Auth, AEAD MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-AES256-GCM-SHA384' => 'AESGCM 256 bits, ECDH Auth, AEAD MAC, ECDH/ECDSA Kx',
	'ECDH-RSA-AES256-SHA384' => 'AES 256 bits, ECDH Auth, SHA384 MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-AES256-SHA384' => 'AES 256 bits, ECDH Auth, SHA384 MAC, ECDH/ECDSA Kx',
	'AES256-GCM-SHA384' => 'AESGCM 256 bits, RSA Auth, AEAD MAC, RSA Kx',
	'AES256-SHA256' => 'AES 256 bits, RSA Auth, SHA256 MAC, RSA Kx',
	'ECDHE-RSA-AES128-GCM-SHA256' => 'AESGCM 128 bits, RSA Auth, AEAD MAC, ECDH Kx',
	'ECDHE-ECDSA-AES128-GCM-SHA256' => 'AESGCM 128 bits, ECDSA Auth, AEAD MAC, ECDH Kx',
	'ECDHE-RSA-AES128-SHA256' => 'AES 128 bits, RSA Auth, SHA256 MAC, ECDH Kx',
	'ECDHE-ECDSA-AES128-SHA256' => 'AES 128 bits, ECDSA Auth, SHA256 MAC, ECDH Kx',
	'DHE-DSS-AES128-GCM-SHA256' => 'AESGCM 128 bits, DSS Auth, AEAD MAC, DH Kx',
	'DHE-RSA-AES128-GCM-SHA256' => 'AESGCM 128 bits, RSA Auth, AEAD MAC, DH Kx',
	'DHE-RSA-AES128-SHA256' => 'AES 128 bits, RSA Auth, SHA256 MAC, DH Kx',
	'DHE-DSS-AES128-SHA256' => 'AES 128 bits, DSS Auth, SHA256 MAC, DH Kx',
	'ADH-AES128-GCM-SHA256' => 'AESGCM 128 bits, Null Auth, AEAD MAC, DH Kx',
	'ADH-AES128-SHA256' => 'AES 128 bits, Null Auth, SHA256 MAC, DH Kx',
	'ECDH-RSA-AES128-GCM-SHA256' => 'AESGCM 128 bits, ECDH Auth, AEAD MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-AES128-GCM-SHA256' => 'AESGCM 128 bits, ECDH Auth, AEAD MAC, ECDH/ECDSA Kx',
	'ECDH-RSA-AES128-SHA256' => 'AES 128 bits, ECDH Auth, SHA256 MAC, ECDH/RSA Kx',
	'ECDH-ECDSA-AES128-SHA256' => 'AES 128 bits, ECDH Auth, SHA256 MAC, ECDH/ECDSA Kx',
	'AES128-GCM-SHA256' => 'AESGCM 128 bits, RSA Auth, AEAD MAC, RSA Kx',
	'AES128-SHA256' => 'AES 128 bits, RSA Auth, SHA256 MAC, RSA Kx',
	'NULL-SHA256' => 'Null, RSA Auth, SHA256 MAC, RSA Kx'
);


# add the list of ssl3 ciphers to the tlsv1.2 list
while ( ($k,$v) = each(%ssl3ciphers) ) {
    $tlsv12ciphers{$k} = $v;
}

package main;


my $r={};
my $t1;
>>>>>>> 12c819b... try to use sslv3 first
my $q=new CGI();
my @CERTBuffer;
<<<<<<< HEAD
=======
my $ScriptTimeout=60;
>>>>>>> 46c479e... try to find beetter W5ProbeIP process

if (request_method() eq "POST"){
   ProbeIP();
}
else{
   if ($q->param("url") eq ""){
      $q->param("url"=>$ENV{SCRIPT_URI});
   }
   ShowForm();
}
exit(0);


<<<<<<< HEAD
=======
sub outputResults
{
   foreach my $k (keys(%$r)){
      if (ref($r->{$k}) eq "HASH"){
         if (exists($r->{$k}->{exitcode}) && 
             $r->{$k}->{exitcode} ne "0"){
            if ($r->{exitcode}<$r->{$k}->{exitcode}){
               $r->{exitcode}=$r->{$k}->{exitcode};
               if (defined($r->{$k}->{exitmsg})){
                  $r->{exitmsg}=$r->{$k}->{exitmsg};
               }
            }
         }
      }
   }
   if (!exists($r->{exitcode})){
      $r->{exitcode}=0;
   }
   my $t2=Time::HiRes::time();
   $r->{startunixtime}=$t1;
   $r->{endunixtime}=$t2;
   $r->{duration}=$t2-$t1;

   print to_json($r,{ 
      utf8=>1, 
      pretty=>1 
   });
}



>>>>>>> 12c819b... try to use sslv3 first
sub ProbeIP()
{
   $|=1;
   print $q->header(
      -type=>'application/json',
      -expires=>'+10s',
      -charset=>'utf-8'
   );
   my $r={};

   my $uri=new URI($q->param("url"));
   $SIG{ALRM}=sub{
      die("W5ProbeIP timeout for $uri");
   };
   alarm(30);

   my $scheme=$uri->scheme();
   if (ref($uri) ne "URI::_foreign"){
      $uri->path("");
      $r->{url}=$uri->as_string();
      $r->{target}={
         schema=>$scheme,
         host=>$uri->host(),
         port=>$uri->port()
      }
   }
   else{
      my $name=$uri;
      my $befhost=qr{\@}; # character before the host
      $befhost=qr{://} if (index($name,'@')==-1);

      my ($host,$port)=$name=~m/$befhost([^:\/]+)(?:\:(\d+))?/;
      $r->{target}={
         schema=>$scheme,
         host=>$host
      };
      if ($port eq ""){
         $port="22" if ($scheme eq "sftp");
         $port="22" if ($scheme eq "ssh");
         $port="22" if ($scheme eq "scp");
      }

      if ($port ne ""){
         $r->{target}->{port}=$port;
      }

   }
   $t1=Time::HiRes::time();
   my @operation=$q->param("operation");
   do_DNSRESOLV($r) if (grep(/^DNSRESOLV$/,@operation));
   do_SSLCERT($r)   if (grep(/^SSLCERT$/,@operation));
   do_REVDNS($r)    if (grep(/^REVDNS$/,@operation));
   do_IPCONNECT($r) if (grep(/^IPCONNECT$/,@operation));
   foreach my $k (keys(%$r)){
      if (ref($r->{$k}) eq "HASH"){
         if (exists($r->{$k}->{exitcode}) && 
             $r->{$k}->{exitcode} ne "0"){
            if ($r->{exitcode}<$r->{$k}->{exitcode}){
               $r->{exitcode}=$r->{$k}->{exitcode};
            }
         }
      }
   }
   if (!exists($r->{exitcode})){
      $r->{exitcode}=0;
   }
   my $t2=Time::HiRes::time();
   $r->{duration}=$t2-$t1;

   print to_json($r,{ 
      utf8=>1, 
      pretty=>1 
   });
}

sub do_DNSRESOLV
{
   my $r=shift;

   $r->{operation}->{DNSRESOLV}=1;

   my $host=$r->{target}->{host};

   $r->{dnsresolver}=resolv2ip($host);
}


sub resolv2ip
{
   my $host=shift;

   my $r={};

   my $k=$host;

   if (exists($W5ProbeIP::resolvip::Cache{$k})){
      return($W5ProbeIP::resolvip::Cache{$k});
   }


   my @okt=unpack("C4",pack("C4",split(/\./,$host)));
   @okt=grep({ $_>=0 and $_< 256 } @okt);
   my $parsed=join('.',unpack("C4",pack("C4",split(/\./,$host))));
   if ($parsed eq $host){ # is already v4 address
      $r->{ipaddress}=[$host];
      $r->{exitcode}=0;
   }
   elsif ($host=~m/^[:a-f0-9]+$/){ # is already v6 address
      $r->{ipaddress}=[$host];
      $r->{exitcode}=0;
   }
   else{
      my $res;
      eval('
         use Net::DNS;
         $res=Net::DNS::Resolver->new();
      ');
      if ($@ ne ""){
         $r->{errorcode}=100;
         $r->{error}=$@;
      }
      else{
         my @ipaddress;
         my $query=$res->search($host);
         if ($query){
            foreach my $rr ($query->answer) {
               next unless($rr->type eq "A");
               push(@ipaddress,$rr->address);
            }
            $r->{exitcode}=0;
            $r->{ipaddress}=\@ipaddress;
         }
         elsif ($res->errorstring eq "NXDOMAIN" ||
                $res->errorstring eq "NOERROR"){
            $r->{error}="invalid dns name";
            $r->{exitcode}=101;
         }
         else{
            $r->{error}="dns query failed";
            $r->{exitcode}=102;
            return(undef);
         }
      }
   }
   $W5ProbeIP::resolvip::Cache{$k}=$r;


   return($r);
}




sub do_SSLCERT
{
   my $r=shift;

   $r->{operation}->{SSLCERT}=1;

   my $host=$r->{target}->{host};
   my $port=$r->{target}->{port};

   eval('use IO::Socket::SSL;');
   eval('use Net::SSLeay;');
   eval('use IO::Socket::INET;');
   eval('use IO::Socket::INET6;');
   eval('use DateTime;');
   eval('use Date::Parse;');

   sub unpackCert
   {
      my $cert=shift;
      my $sslcert={};

      my $expire_date_asn1=Net::SSLeay::X509_get_notAfter($cert);
      my $expireDate=Net::SSLeay::P_ASN1_UTCTIME_put2string(
                     $expire_date_asn1);
      ### $expire_date_str
      my $begin_date_asn1 =Net::SSLeay::X509_get_notBefore($cert);
      my $beginDate=Net::SSLeay::P_ASN1_UTCTIME_put2string($begin_date_asn1);
      $sslcert->{ssl_cert_begin}="".
          DateTime->from_epoch(epoch=>str2time($beginDate));
      $sslcert->{ssl_cert_end}="".
          DateTime->from_epoch(epoch=>str2time($expireDate));
    
      my $certserial;
      eval('$certserial=Net::SSLeay::X509_get_serialNumber($cert);');
      $sslcert->{ssl_cert_serialno}=
         Net::SSLeay::P_ASN1_INTEGER_get_hex($certserial) if ($@ eq "");
      if (main->can("Net::SSLeay::P_X509_get_signature_alg")){
         my $cert_signature_algo;
         eval('$cert_signature_algo=
            Net::SSLeay::OBJ_obj2txt(
               Net::SSLeay::P_X509_get_signature_alg($cert)
            );
         ');
         if ($@ eq ""){
            $sslcert->{ssl_cert_signature_algo}=$cert_signature_algo;
         }
      }
      return($sslcert);
   }

   sub preConnectReadServerCerts
   {
      my ($ok,$ctx_store,$certname,$error,$cert,$depth) = @_;
      my $sslcert=unpackCert($cert);
      $sslcert->{name}=$certname;
      push(@CERTBuffer,$sslcert);
      return(1);
   }

   if (!canTcpConnect($host,$port)){
      push(@{$r->{sslcert}->{log}},
          sprintf("Step0: generic tcp connect check %s:%s",$host,$port));
      $r->{sslcert}->{error}="can not tcp connect to $host:$port";
      $r->{sslcert}->{exitcode}=1;
      return;
   }

   push(@{$r->{sslcert}->{log}},
       sprintf("Step1: try to connect to %s:%s SSLv23",$host,$port));
   $ENV{"HTTPS_VERSION"}="3";


   @CERTBuffer=();

   my $step=0;

   if (!defined($sock) && $#CERTBuffer==-1){
      $step++;
      push(@{$r->{sslcert}->{log}},
          sprintf("Step${step}: try to connect to %s:%s SSLv3",$host,$port));
      $sock = IO::Socket::SSL->new(
         PeerAddr=>"$host:$port",
         SSL_version=>'SSLv3',
         SSL_verify_mode=>'SSL_VERIFY_PEER',
         Timeout=>5,
         SSL_verify_callback=>\&preConnectReadServerCerts,
         SSL_session_cache_size=>0
      );
      if (!defined($sock)){
         push(@{$r->{sslcert}->{log}},
             sprintf("->result=%s",IO::Socket::SSL->errstr()));
      }
   }


   if (!defined($sock) && $#CERTBuffer==-1){
      $step++;
      push(@{$r->{sslcert}->{log}},
          sprintf("Step${step}: try to connect to %s:%s TLSv12",$host,$port));
      $sock = IO::Socket::SSL->new(
         PeerAddr=>"$host:$port",
         SSL_version=>'TLSv12',
         SSL_verify_mode=>'SSL_VERIFY_PEER',
         Timeout=>5,
         SSL_verify_callback=>\&preConnectReadServerCerts,
         SSL_session_cache_size=>0
      );
      if (!defined($sock)){
         push(@{$r->{sslcert}->{log}},
             sprintf("->result=%s",IO::Socket::SSL->errstr()));
      }
   }


   if (!defined($sock) && $#CERTBuffer==-1){
      $step++;
      push(@{$r->{sslcert}->{log}},
          sprintf("Step${step}: try to connect to %s:%s TLSv11",$host,$port));
      $sock = IO::Socket::SSL->new(
         PeerAddr=>"$host:$port",
         SSL_version=>'TLSv11',
         SSL_verify_mode=>'SSL_VERIFY_PEER',
         Timeout=>5,
         SSL_verify_callback=>\&preConnectReadServerCerts,
         SSL_session_cache_size=>0
      );
      if (!defined($sock)){
         push(@{$r->{sslcert}->{log}},
             sprintf("->result=%s",IO::Socket::SSL->errstr()));
      }
   }


   if (!defined($sock) && $#CERTBuffer==-1){
      $step++;
      push(@{$r->{sslcert}->{log}},
          sprintf("Step${step}: try to connect to %s:%s SSLv2",$host,$port));
      $sock = IO::Socket::SSL->new(
         PeerAddr=>"$host:$port",
         SSL_version=>'SSLv2',
         SSL_verify_mode=>'SSL_VERIFY_PEER',
         SSL_verify_callback=>\&preConnectReadServerCerts,
         Timeout=>5,
         SSL_session_cache_size=>0
      );
      if (!defined($sock) && $#CERTBuffer==-1){
         push(@{$r->{sslcert}->{log}},
             sprintf("->result=%s",IO::Socket::SSL->errstr()));
      }
   }

   if (!defined($sock) && $#CERTBuffer==-1){
      $step++;
      push(@{$r->{sslcert}->{log}},
          sprintf("Step${step}: try to connect to %s:%s SSLv23",$host,$port));
      my $sock = IO::Socket::SSL->new(
         PeerAddr=>"$host:$port",
         SSL_version=>'SSLv23',
         SSL_verify_mode=>'SSL_VERIFY_PEER',
         Timeout=>5,
         SSL_verify_callback=>\&preConnectReadServerCerts,
         SSL_session_cache_size=>0
      );
      if (!defined($sock) && $#CERTBuffer==-1){
         push(@{$r->{sslcert}->{log}},
             sprintf("->result=%s",IO::Socket::SSL->errstr()));
      }
   }
<<<<<<< HEAD
=======




   delete($r->{sslcert}->{exitcode}); # remove timeout flag
   delete($r->{sslcert}->{exitmsg});
>>>>>>> 12c819b... try to use sslv3 first
   if (defined($sock)){
      my $cert = $sock->peer_certificate();
      if (1){
         my $certdump;
         eval('$certdump=$sock->dump_peer_certificate();');
         $r->{sslcert}->{ssl_certdump}=$certdump if ($@ eq "");
     
         my $version;
         eval('$version = $sock->get_sslversion();');
         $r->{sslcert}->{ssl_version}=$version if ($@ eq "");
     
         my $cipher;
         eval('$cipher=$sock->get_cipher();');
         $r->{sslcert}->{ssl_cipher}=$cipher if ($@ eq "");
      }

      if ($cert){
         $r->{sslcert}=unpackCert($cert);
      }
      if ($#CERTBuffer!=-1){
         $r->{sslcert}->{certtree}=\@CERTBuffer;
      }
      $r->{sslcert}->{method}="socket_peer_certifcate";
      $r->{sslcert}->{exitcode}=0;
   }
   elsif ($#CERTBuffer!=-1){
      $r->{sslcert}={%{$CERTBuffer[$#CERTBuffer]}};
      $r->{sslcert}->{certtree}=\@CERTBuffer;
      $r->{sslcert}->{method}="pre_verify_callback";
      $r->{sslcert}->{exitcode}=0;
   }
   else{
      $r->{sslcert}->{exitcode}=201;
   }
}

sub do_REVDNS
{
   my $r=shift;

   $r->{operation}->{REVDNS}=1;

   my $host=$r->{target}->{host};

   my $dns=resolv2ip($host);

   if ($dns->{exitcode}==0 &&
       ref($dns->{ipaddress}) eq "ARRAY"){
      my $res;
      eval('
         use Net::DNS;
         $res=Net::DNS::Resolver->new();
      ');
      if ($@ ne ""){
         $r->{errorcode}=100;
         $r->{error}=$@;
      }
      else{
         $r->{revdns}->{names}=[];
         my @ipl=@{$dns->{ipaddress}};
         my @names=();
         foreach my $ip (@ipl){
            my $query=$res->query($ip,"PTR");
            if ($query){
               foreach my $rr ($query->answer) {
                  next unless($rr->type eq "PTR");
                  push(@names,$rr->rdatastr);
               }
            }
         }
         push(@{$r->{revdns}->{names}},@names)
      }
   }
}

sub do_IPCONNECT
{
   my $r=shift;

   $r->{operation}->{IPCONNECT}=1;
   my $t1=Time::HiRes::time();
   my $res=canTcpConnect($r->{target}->{host},$r->{target}->{port});
   my $t2=Time::HiRes::time();
   if ($res){
      $r->{ipconnect}->{open}=1;
      $r->{ipconnect}->{time}=$t2-$t1;
      $r->{ipconnect}->{exitcode}=0;
   }
   else{
      $r->{ipconnect}->{open}=0;
      $r->{ipconnect}->{exitcode}=501;
   }
   if ($ENV{W5ProbeIP_SourceIP} ne ""){
      $r->{ipconnect}->{sourceip}=$ENV{W5ProbeIP_SourceIP};
   }
}

sub canTcpConnect
{
   my ($host,$port)=@_;

   my $k=$host.":".$port;

   if (exists($W5ProbeIP::canTcpConnect::Cache{$k})){
      return($W5ProbeIP::canTcpConnect::Cache{$k});
   }

   my $sock = IO::Socket::INET->new(
      PeerAddr => $host,PeerPort => $port,
      Proto => "tcp",
      Timeout => 5 
   );
   if (defined($sock)){
      if ($ENV{W5ProbeIP_SourceIP} eq ""){
         $ENV{W5ProbeIP_SourceIP}=$sock->sockhost();
      }
      $sock->close();
      $W5ProbeIP::canTcpConnect::Cache{$k}=1;
      return(1);
   }
   $W5ProbeIP::canTcpConnect::Cache{$k}=0;
   return(0);
}



sub ShowForm()
{
   my $e=Dumper(\%ENV);
   $e=~s/^\$VAR1/ENV/;

   print $q->header().
   $q->start_html('W5ProbeIP').

   "<div style='width:100%'>".
   h1({
      -style=>'Color: blue;'
   },'W5ProbeIP').

   $q->start_form(
      -method=>'POST',
      -target=>'OUT'
   ).

   $q->textfield(-name=>'url',
      -value=>'',
      -size=>50,
      -maxlength=>80
   ).

   $q->checkbox_group(
      -name=>'operation',
      -values=>['SSLCERT','DNSRESOLV','REVDNS','IPCONNECT'],
      -columns=>4
   ).

   $q->submit(
      -name=>'do',
      -value=>'analyse URL'
   ).
   $q->end_form().
   "<iframe name=OUT style='width:100%;height:300px'></iframe>".
   '</div>'.
   "<div style='height:200px;overflow:scroll'>"."<xmp>".$e."</xmp>"."</div>".
   

   $q->end_html();
}
