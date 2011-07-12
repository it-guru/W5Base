package tssc::W5Server::ReadCtrl;
use strict;
use kernel;
use kernel::date;
use kernel::W5Server;
use vars (qw(@ISA));
@ISA=qw(kernel::W5Server);

sub new
{
   my $type=shift;
   my %param=@_;
   my $self=bless($type->SUPER::new(%param),$type);

   return($self);
}

sub process
{
   my $self=shift;

   my $opmode=$self->getParent->Config->Param("W5BaseOperationMode");
   if ($opmode eq "readonly"){
      while(1){
         sleep(3600);
      }
   }

   my %ctrl=(
              'scchange'=>{
                           laststart=>undef,
                           lastend=>undef,
                           AsyncID=>undef,
                          },
              'scincident'=>{
                           laststart=>undef,
                           lastend=>undef,
                           AsyncID=>undef,
                          },
              'scproblem'=>{
                           laststart=>undef,
                           lastend=>undef,
                           AsyncID=>undef,
                          }
             );
   my $evrt=getModuleObject($self->Config,"base::eventrouter");
   my $bk=$evrt->W5ServerCall("rpcCallEvent","LongRunner");


   while(!$self->ServerGoesDown()){
      my $evrt=getModuleObject($self->Config,"base::eventrouter");
      #
      # Job Starter
      #
      if (1){
         printf STDERR ("fifi from %s now i check to start new events\n",
                        $self->Self());
         EVST: foreach my $eventname (keys(%ctrl)){
            if (currentRunnings(\%ctrl)<3){
               if (!defined($ctrl{$eventname}->{'AsyncID'}) &&
                   ((defined($ctrl{$eventname}->{'lastend'}) &&
                     $ctrl{$eventname}->{'lastend'}<(time()-180)) ||
                    (!defined($ctrl{$eventname}->{'laststart'})) ||
                    ($ctrl{$eventname}->{'laststart'}<(time()-1200)))){
                  my $bk=$evrt->W5ServerCall("rpcCallEvent",$eventname);
                  if (ref($bk) eq "HASH" && 
                      $bk->{'exitcode'}==0 &&
                      $bk->{'AsyncID'}!=0){
                     $ctrl{$eventname}->{'laststart'}=time();
                     $ctrl{$eventname}->{'lastend'}=undef;
                     $ctrl{$eventname}->{'AsyncID'}= $bk->{'AsyncID'};
                     last EVST;       
                  }
                  else{
                     die('ERROR: ganz schlecht - can not call event');
                  }
                  printf STDERR ("fifi bk=%s\n",Dumper($bk));
               }
            }
         }
      }
      #
      # Job Status checker
      #
      foreach my $eventname (keys(%ctrl)){
         if (defined($ctrl{$eventname}->{'AsyncID'})){
            my $bk=$evrt->W5ServerCall("rpcAsyncState",
                                   $ctrl{$eventname}->{'AsyncID'});
            if (ref($bk) eq "HASH" && $bk->{'exitcode'}==0){
               printf STDERR ("fifi loop=%s\n",Dumper($bk));
               if (exists($bk->{'process'}->{'exitcode'})){
                  $ctrl{$eventname}->{'lastend'}=time();
                  $ctrl{$eventname}->{'AsyncID'}=undef; # erst mal egal ob gut
               }
            }
            else{
               die('ERROR: ganz schlecht - can not get async state');
            }
            
         }
      }
      printf STDERR ("fifi from %s at %d\n",$self->Self(),time());
      printf STDERR ("fifi data=%s\n",Dumper(\%ctrl));
      $self->FullContextReset();
      sleep(30);
   }
}

sub currentRunnings
{
   my $ctrl=shift;
   my %ctrl=%{$ctrl};
   my $n=0;

   foreach my $eventname (keys(%ctrl)){
      if (defined($ctrl{$eventname}->{'AsyncID'})){
         $n++;
      }
   }
   return($n);
}













1;


