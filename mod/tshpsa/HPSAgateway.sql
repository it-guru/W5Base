/* Diese SQL Gateway definition mu� manuell auf dem W5Warehouse System
   in die W5Repo Kennung eingespielt werden. �ber diese Definitionen 
   werden dann zyklisch die Daten aus HPSA in eine saubere und 
   indizierte Tabellenform gebracht.
*/ 

/** Overflow Tabel **/

-- drop table "W5I_HPSA_lnkswp_of";
create table "W5I_HPSA_lnkswp_of" (
 id                   VARCHAR2(3000),
 denyupd              NUMBER(*,0) default '0',
 denyupdcomments      VARCHAR2(4000),
 ddenyupdvalidto      DATE,
 modifyuser           NUMBER(*,0),
 dmodifydate          DATE,
 constraint "W5I_HPSA_lnkswp_of_pk" primary key (id)
);
grant select,insert,update,delete on "W5I_HPSA_lnkswp_of" to W5I;
create or replace synonym W5I.HPSA_lnkswp_of
   for "W5I_HPSA_lnkswp_of";


/*  ==== tshpsa::lnkswp ====== */
-- drop materialized view "mview_HPSA_lnkswp";
create materialized view "mview_HPSA_lnkswp"
   refresh complete start with TRUNC(SYSDATE+1)+((1/24)*6)
   next SYSDATE+1
   as
select item_id sysid,
       item_id server_id,
       substr(replace(utl_i18n.string_to_raw(data =>
              swclass||'-HostID'||item_id||'-'||
              swpath||'-'||iname),' ',''),0,3000) id,
       swclass||'-HostID'||item_id||'-'||
          swpath||'-'||iname fullname,
       mdate   curdate,
       swclass swclass,
       swvers  swvers,
       swpath  swpath,
       iname   iname,
       scandate,
       current_date srcload
from  T03TC_UC128.UC128_1_MW_REPORT@XAUTOM where isdeleted=0;

CREATE INDEX "HPSA_lnkswp_id" 
   ON "mview_HPSA_lnkswp"(id) online;
CREATE INDEX "HPSA_lnkswp_swclass" 
   ON "mview_HPSA_lnkswp"(lower(swclass)) online;

create or replace view "W5I_HPSA_lnkswp" as
select "mview_HPSA_lnkswp".*,
       overflow.id      of_id,
       overflow.denyupd,
       overflow.denyupdcomments,
       overflow.ddenyupdvalidto,
       overflow.modifyuser,
       overflow.dmodifydate
from "mview_HPSA_lnkswp"
     left outer join "W5I_HPSA_lnkswp_of" overflow
        on "mview_HPSA_lnkswp".id=overflow.id;

grant select on "W5I_HPSA_lnkswp" to "W5I";
create or replace synonym W5I.HPSA_lnkswp 
   for "W5I_HPSA_lnkswp";


/*  ==== tshpsa::system ====== */
-- drop materialized view "mview_HPSA_system";
create materialized view "mview_HPSA_system"
   refresh complete start with TRUNC(SYSDATE+1)+((1/24)*6)
   next SYSDATE+1
   as
with j as (select item_id,mdate,lower(hostname) lhostname,hostname,pip,
               regexp_replace(systemid,'([[:space:][:cntrl:]]+)$','') systemid,
           RANK() OVER (PARTITION BY item_id ORDER BY mdate DESC) dest_rank
           from  T03TC_UC128.UC128_1_MW_REPORT@XAUTOM
           where regexp_like(systemid,'^S.{4,10}') and isdeleted=0
           order by mdate),
     s as (select distinct  
            regexp_replace(systemid,'([[:space:][:cntrl:]]+)$','') systemid
           from  T03TC_UC128.UC128_1_MW_REPORT@XAUTOM
           where regexp_like(systemid,'^S.{4,10}') and isdeleted=0)
SELECT j.item_id    server_id,
       j.systemid   systemid,
       j.mdate      curdate,
       j.lhostname  hostname,
       j.hostname   name,
       j.pip        pip,
       current_date srcload
FROM s join j on s.systemid=j.systemid and dest_rank=1;


CREATE INDEX "HPSA_system_id" 
   ON "mview_HPSA_system"(server_id) online;
CREATE INDEX "HPSA_system_hostname" 
   ON "mview_HPSA_system"(hostname) online;

create or replace view "W5I_HPSA_system" as
select distinct "mview_HPSA_system".*,
                itil__system.name w5systemname,
                itil__system.cistatusid w5cistatusid
from "mview_HPSA_system" 
left outer join (select "itil::system".*,DENSE_RANK() OVER (PARTITION BY systemid ORDER BY cistatusid) rank from "itil::system") itil__system
on "mview_HPSA_system".systemid=itil__system.systemid and itil__system.rank=1;
grant select on "W5I_HPSA_system" to "W5I";
create or replace synonym W5I.HPSA_system 
   for "W5I_HPSA_system";

















