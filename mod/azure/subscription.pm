package azure::subscription;
#  W5Base Framework
#  Copyright (C) 2021  Hartmut Vogler (it@guru.de)
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
use kernel::Field;
use azure::lib::Listedit;
use JSON;
@ISA=qw(azure::lib::Listedit);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   $self->AddFields(
      new kernel::Field::Id(     
            name              =>'id',
            group             =>'source',
            htmldetail        =>'NotEmpty',
            label             =>'ResourceID'),

      new kernel::Field::Text(     
            name              =>'subscriptionId',
            group             =>'source',
            htmldetail        =>'NotEmpty',
            dataobjattr       =>'subscriptionId',
            label             =>'SubscriptionID'),

      new kernel::Field::Linenumber(
            name              =>'linenumber',
            label             =>'No.'),

      new kernel::Field::RecordUrl(),

      new kernel::Field::Text(     
            name              =>'name',
            ignorecase        =>1,
            dataobjattr       =>'displayName',
            label             =>'Name'),

      new kernel::Field::TextDrop(
            name              =>'appl',
            searchable        =>0,
            vjointo           =>'itil::appl',
            vjoinon           =>['w5baseid'=>'id'],
            searchable        =>0,
            vjoindisp         =>'name',
            label             =>'W5Base Application'),

      new kernel::Field::Interface(     
            name              =>'w5baseid',
            container         =>'tags',
            label             =>'Application W5BaseID'),

      new kernel::Field::SubList(
                name          =>'virtualmachines',
                label         =>'virtual Machines',
                group         =>'virtualmachines',
                searchable    =>0,
                vjointo       =>'azure::virtualMachine',
                vjoinon       =>['subscriptionId'=>'subscriptionId'],
                vjoindisp     =>['name']),

      new kernel::Field::Container(
            name              =>'tags',
            group             =>'tags',
            searchable        =>0,
            uivisible         =>1,
            onRawValue        =>sub{
               my $self=shift;
               my $current=shift;
               my $subscriptionid=$current->{id};
               return({}) if ($subscriptionid eq "");
               my $subrequest=$self->getParent->DataCollector({
                  filter=>[{id=>\$subscriptionid}]
               });
               if (defined($subrequest) && ref($subrequest) eq "ARRAY" &&
                   $#{$subrequest}==0){
                  return($subrequest->[0]->{tags});
               }
               return({});
            },
            label             =>'Tags'),

      new kernel::Field::Text(     
            name              =>'tenantid',
            ignorecase        =>1,
            group             =>'source',
            dataobjattr       =>'tenantId',
            label             =>'TenantId'),

   );
   $self->{'data'}=\&DataCollector;
   $self->setDefaultView(qw(id name appl));
   return($self);
}


sub DataCollector
{
   my $self=shift;
   my $filterset=shift;

   my @view=$self->GetCurrentView();
   #printf STDERR ("view=%s\n",Dumper(\@view));

   my $Authorization=$self->getAzureAuthorizationToken();

   my ($dbclass,$requesttoken)=$self->decodeFilter2Query4azure(
      "subscriptions","id",
      $filterset,{
        '$expand'=>'properties'
      }
   );
   my $d=$self->CollectREST(
      dbname=>'AZURE',
      requesttoken=>$requesttoken,
      useproxy=>1,
      url=>sub{
         my $self=shift;
         my $baseurl=shift;
         my $apikey=shift;
         my $base=shift;
      
         my $dataobjurl="https://management.azure.com/";
         $dataobjurl.=$dbclass;
         return($dataobjurl);
      },

      headers=>sub{
         my $self=shift;
         my $baseurl=shift;
         my $apikey=shift;
         my $headers=['Authorization'=>$Authorization,
                      'Content-Type'=>'application/json'];
 
         return($headers);
      },
      success=>sub{  # DataReformaterOnSucces
         my $self=shift;
         my $data=shift;
         if (ref($data) eq "HASH" && exists($data->{value})){
            $data=$data->{value};
         }
         if (ref($data) ne "ARRAY"){
            $data=[$data];
         }
         my @data;
         foreach my $rawrec (@$data){
            my $rec;
            foreach my $v (qw(id displayName subscriptionId tenantId tags)){
               if (exists($rawrec->{$v})){
                  $rec->{$v}=$rawrec->{$v};
                  if ($v eq "id"){
                     $rec->{$v}=azure::lib::Listedit::AzID2W5BaseID($rec->{$v});
                  }
               }
            }
            push(@data,$rec);
         }
         return(\@data);
      },
      onfail=>sub{
         my $self=shift;
         my $code=shift;
         my $statusline=shift;
         my $content=shift;
         my $reqtrace=shift;

         if ($code eq "404"){  # 404 bedeutet nicht gefunden
            return([],"200");
         }
         msg(ERROR,$reqtrace);
         $self->LastMsg(ERROR,"unexpected data Azure subscription response");
         return(undef);
      }
   );

   return($d);
}

sub isViewValid
{
   my $self=shift;
   my $rec=shift;
   return("default") if (!defined($rec));
   return("ALL");
}

sub isWriteValid
{
   my $self=shift;
   my $rec=shift;
   return(undef);
}

sub isQualityCheckValid
{
   my $self=shift;
   my $rec=shift;
   return(0);
}

sub isUploadValid
{
   my $self=shift;
   my $rec=shift;
   return(0);
}

sub getDetailBlockPriority
{
   my $self=shift;
   my $grp=shift;
   my %param=@_;
   return(qw(header default virtualmachines tags source));
}

sub getRecordImageUrl
{
   my $self=shift;
   my $cgi=new CGI({HTTP_ACCEPT_LANGUAGE=>$ENV{HTTP_ACCEPT_LANGUAGE}});
   return("../../../public/itil/load/itcloudarea.jpg?".$cgi->query_string());
}


sub getValidWebFunctions
{
   my ($self)=@_;
   return(qw(TriggerEndpoint),$self->SUPER::getValidWebFunctions());
}

#
# Endpoint URL to handle Trigger Events from Azure Cloud
#

sub TriggerEndpoint
{
   my $self=shift;
   my %param;

   $param{charset}="UTF8";

   my $q=Query->MultiVars();

   delete($q->{MOD});
   delete($q->{FUNC});
   print $self->HttpHeader("application/javascript",%param);

   my $json=new JSON;
   $json->utf8(1);

   my $d=$json->pretty->encode({
      request=>$q,
      handler=>$self->Self,
      exitcode=>0,
      ptimestamp=>NowStamp(),
      exitmsg=>'OK'
   });
   print $d;
   return(0);
}



1;


