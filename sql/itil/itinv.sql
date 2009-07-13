use w5base;
create table appl (
  id         bigint(20) NOT NULL,
  name       varchar(40) NOT NULL,
  cistatus   int(2)      NOT NULL,
    applid         varchar(20) default NULL,
    conumber       varchar(20) default NULL,
    applgroup      varchar(20) default NULL,
    databoss       bigint(20)  default NULL,
    tsm            bigint(20)  default NULL,
    tsm2           bigint(20)  default NULL,
    sem            bigint(20)  default NULL,
    sem2           bigint(20)  default NULL,
    customer       bigint(20)  default NULL,
    businessteam   bigint(20)  default NULL,
    responseteam   bigint(20)  default NULL,
    mandator       bigint(20)  default NULL,
    desiredsla     float(5,2)  default NULL,
    is_licenseapp  bool        default '0',
    customerprio   int(2)      default '2',
    avgusercount   int(11),namedusercount int(11),
    currentvers    text        default NULL,
    maintwindow    text        default NULL,
    description    longtext    default NULL,
    additional     longtext    default NULL,
  comments    longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY applid (applid),
  UNIQUE KEY name (name),KEY(mandator),key(conumber),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnkapplcustcontract (
  id           bigint(20) NOT NULL,
  appl         bigint(20) NOT NULL,
  custcontract bigint(20) NOT NULL,
  fraction     double(8,2) default '100.00',
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY appl (appl),
  KEY custcontract (custcontract),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table system (
  id         bigint(20) NOT NULL,
  name       varchar(40) NOT NULL,
    adm            bigint(20)  default NULL,
    adm2           bigint(20)  default NULL,
    admteam        bigint(20)  default NULL,
    systemid       varchar(20)  default NULL,
    inventoryno    varchar(20)  default NULL,
    conumber       varchar(20) default NULL,
    mandator       bigint(20)  default NULL,
    is_prod        bool default '0',
    is_test        bool default '0',
    is_devel       bool default '0',
    is_education   bool default '0',
    is_approvtest  bool default '0',
    is_reference   bool default '0',
    asset          bigint(20)  default NULL,
    partofasset    float(5,2)  default NULL,
    is_virtual     bool default '0',
    is_custdriven  bool default '0',
    osrelease      bigint(20)  default NULL,
    cpucount       int(20)     default NULL,
    memory         int(20)     default NULL,
    is_router      bool default '0',
    is_workstation bool default '0',
    is_netswitch   bool default '0',
    is_printer     bool default '0',
    is_backupsrv   bool default '0',
    is_mailserver  bool default '0',
    is_applserver  bool default '0',
    is_adminsystem bool default '0',
    is_databasesrv bool default '0',
    is_webserver   bool default '0',
    is_terminalsrv bool default '0',
    shortdesc      varchar(80)  default NULL,
    description    longtext     default NULL,
    additional     longtext     default NULL,
  comments    longtext     default NULL,
  cistatus   int(2)      NOT NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY systemid (systemid),
  KEY adm (adm),KEY adm2 (adm2), KEY admteam (admteam),
  UNIQUE KEY name (name),KEY(mandator),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table asset (
  id         bigint(20) NOT NULL,
  name       varchar(40) default NULL,
  cistatus   int(2)      NOT NULL,
    mandator       bigint(20)  default NULL,
    guardian       bigint(20)  default NULL,
    guardian2      bigint(20)  default NULL,
    guardianteam   bigint(20)  default NULL,
    assetid        varchar(20)  default NULL,
    serialnumber   varchar(20)  default NULL,
    hwmodel        bigint(20)  default NULL,
    location       bigint(20)  default NULL,
    cpucount       int(20)     default NULL,
    corecount      int(20)     default NULL,
    cpuspeed       int(20)     default NULL,
    memory         int(20)     default NULL,
    description    longtext     default NULL,
    additional     longtext     default NULL,
    deprstart      datetime default NULL,
    deprend        datetime default NULL,
  comments    longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY assetid (assetid),
  UNIQUE KEY name (name),KEY(mandator),
  KEY guardian (guardian),KEY guardian2 (guardian2), 
  KEY guardianteam (guardianteam),
  UNIQUE KEY `srcsys` (srcsys,srcid),key(location),key(hwmodel)
);
create table platform (
  id         bigint(20) NOT NULL,
  name       varchar(20) NOT NULL,
  cistatus   int(2)      NOT NULL,
    hwbits         varchar(20) default NULL,
    mandator       bigint(20)  default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY name (name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table osrelease (
  id         bigint(20) NOT NULL,
  name       varchar(40) NOT NULL,
  cistatus   int(2)      NOT NULL,
    mandator       bigint(20)  default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY name (name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table producer (
  id          bigint(20)  NOT NULL,
  name        varchar(40) NOT NULL,
  cistatus    int(2)      NOT NULL,
    mandator       bigint(20)  default NULL,
  comments    longtext     default NULL,
  additional  longtext     default NULL,
  createdate  datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate  datetime NOT NULL default '0000-00-00 00:00:00',
  createuser  bigint(20) NOT NULL default '0',
  modifyuser  bigint(20) NOT NULL default '0',
  editor      varchar(100) NOT NULL default '',
  realeditor  varchar(100) NOT NULL default '',
  srcsys      varchar(10) default 'w5base',
  srcid       varchar(20) default NULL,
  srcload     datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY name (name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table software (
  id          bigint(20)  NOT NULL,
  name        varchar(80) NOT NULL,
  cistatus    int(2)      NOT NULL,
    producer       bigint(20)  default NULL,
    releaseexp     varchar(128) default NULL,
    mandator       bigint(20)  default NULL,
  comments    longtext     default NULL,
  additional  longtext     default NULL,
  createdate  datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate  datetime NOT NULL default '0000-00-00 00:00:00',
  createuser  bigint(20) NOT NULL default '0',
  modifyuser  bigint(20) NOT NULL default '0',
  editor      varchar(100) NOT NULL default '',
  realeditor  varchar(100) NOT NULL default '',
  srcsys      varchar(10) default 'w5base',
  srcid       varchar(20) default NULL,
  srcload     datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY name (name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table network (
  id         bigint(20) NOT NULL,
  name       varchar(40) NOT NULL,
  cistatus   int(2)      NOT NULL,
    uniquearea     int(20)     default NULL,
    mandator       bigint(20)  default NULL,
  comments    longtext     default NULL,
  additional  longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY name (name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table ipaddress (
  id         bigint(20) NOT NULL,
  name       varchar(40) NOT NULL,  
  cistatus   int(2)      NOT NULL,
    dnsname        varchar(40) default NULL,
    addresstyp     int(10)     default NULL,
    is_foundindns  bool default '0',is_controllpartner  bool default '0',
    system         bigint(20)  default NULL,
    uniqueflag     bigint(20)  default NULL,
    network        bigint(20)  default NULL,
    description    longtext     default NULL,
    additional     longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  key name(network,name),key dnsname(dnsname),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table liccontract (
  id          bigint(20)  NOT NULL,
  name        varchar(40) NOT NULL,
  cistatus    int(2)      NOT NULL,
    software       bigint(20)  default NULL,
    sem            bigint(20)  default NULL,
    sem2           bigint(20)  default NULL,
    mandator       bigint(20)  default NULL,
    responseteam   bigint(20)  default NULL,
    producer       bigint(20)  default NULL,
    lictype        varchar(20) default NULL,
    durationstart  datetime NOT NULL default '0000-00-00 00:00:00',
    durationend    datetime    default NULL,
    intprice       double(36,2) default NULL,
    extprice       double(36,2) default NULL,
    intmaintprice  double(36,2) default NULL,
    extmaintprice  double(36,2) default NULL,
    intafadurationstart  datetime NOT NULL default '0000-00-00 00:00:00',
    intafadurationend    datetime    default NULL,
    extafadurationstart  datetime NOT NULL default '0000-00-00 00:00:00',
    extafadurationend    datetime    default NULL,
    ordertyp       varchar(20) default NULL,
    orderdate      datetime    default NULL,
    orderref       varchar(40) default NULL,
    producerpartno varchar(40) default NULL,
    exppriceliftup double(36,2) default NULL,
  comments    longtext     default NULL,
  additional  longtext     default NULL,
  createdate  datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate  datetime NOT NULL default '0000-00-00 00:00:00',
  createuser  bigint(20) NOT NULL default '0',
  modifyuser  bigint(20) NOT NULL default '0',
  editor      varchar(100) NOT NULL default '',
  realeditor  varchar(100) NOT NULL default '',
  srcsys      varchar(10) default 'w5base',
  srcid       varchar(20) default NULL,
  srcload     datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY name (name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnkapplappl (
  id           bigint(20) NOT NULL,
  fromappl     bigint(20) NOT NULL,
  toappl       bigint(20) NOT NULL,
  conmode      varchar(10) default NULL,
  contype      int(1)      default NULL,
  conprotocol  varchar(15) default NULL,
  comments     longtext    default NULL,
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY fromappl (fromappl),
  KEY toappl (toappl),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table hwmodel (
  id          bigint(20)  NOT NULL,
  fullname    varchar(80) NOT NULL,
  cistatus    int(2)      NOT NULL,
    name        varchar(40) NOT NULL,
    mandator    bigint(20)  default NULL,
    producer    bigint(20)  default NULL,
    platform    bigint(20)  default NULL,
  comments    longtext     default NULL,
  additional  longtext     default NULL,
  createdate  datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate  datetime NOT NULL default '0000-00-00 00:00:00',
  createuser  bigint(20) NOT NULL default '0',
  modifyuser  bigint(20) NOT NULL default '0',
  editor      varchar(100) NOT NULL default '',
  realeditor  varchar(100) NOT NULL default '',
  srcsys      varchar(10) default 'w5base',
  srcid       varchar(20) default NULL,
  srcload     datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY name (name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnkapplsystem (
  id           bigint(20) NOT NULL,
  appl         bigint(20) NOT NULL,
  system       bigint(20) NOT NULL,
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  fraction     double(8,2) default '100.00',
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY appl (appl),UNIQUE applsys(appl,system),
  KEY system (system),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnksoftwaresystem (
  id           bigint(20) NOT NULL,
  software     bigint(20) NOT NULL,
  system       bigint(20) NOT NULL,
  liccontract  bigint(20),
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  quantity     double(8,2) NOT NULL default '1.00',
  version      varchar(30),
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY software (software),KEY liccontract (liccontract),
  KEY system (system),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnkinstance (
  id                bigint(20) NOT NULL,
  lnksoftwaresystem bigint(20) NOT NULL,
  name              varchar(80) NOT NULL,
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE name (name,lnksoftwaresystem),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
alter table appl add is_soxcontroll   bool default '0';
alter table appl add is_applwithnosys bool default '0';
alter table system add systemtype varchar(20) not null,add key(systemtype);
alter table asset add room varchar(20) default '';
alter table ipaddress add unique ipchk(name,uniqueflag,network);
alter table ipaddress add comments     longtext    default NULL;
alter table system add is_clusternode bool default '0';
alter table system add clusterid bigint(20) default NULL;
alter table system add key(clusterid);
alter table appl add key(customer);
alter table system add ccproxy varchar(128) default '';
create table servicesupport (
  id         bigint(20) NOT NULL,
  name       varchar(60) NOT NULL,
  cistatus   int(2)      NOT NULL,
    mandator       bigint(20)  default NULL,
  comments    longtext     default NULL,
  additional  longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY name (name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
alter table appl add servicesupport bigint(20) default NULL;
alter table appl add key(servicesupport);
alter table asset  add place varchar(40) default NULL;
alter table asset  add rack  varchar(40) default NULL;
alter table system add servicesupport bigint(20) default NULL;
alter table servicesupport add timezone varchar(40) NOT NULL default 'CET';
create table systemnfsnas (
  id         bigint(20) NOT NULL,
  name       varchar(128) NOT NULL,  
  cistatus   int(2)      NOT NULL,
    system         bigint(20)   default NULL,
    mbquota        bigint(20)   default NULL,
    exportoptions  varchar(128) default NULL,
    exporttype     varchar(20)  default NULL,
    exportname     varchar(40)  default NULL,
    publicexport   int(1)       default '0',
    description    longtext     default NULL,comments longtext default NULL,
    additional     longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),key(exportname),key(cistatus),
  UNIQUE KEY name (name,system),key(system),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnksystemnfsnas (
  id         bigint(20) NOT NULL,
  systemnfsnas    bigint(20) NOT NULL,
  system          bigint(20) NOT NULL,
  exportoptions   varchar(128) default NULL,
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE name (system,systemnfsnas),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
alter table system add is_nas bool default '0';
create table swinstance (
  id         bigint(20)   NOT NULL,
  fullname   varchar(128) NOT NULL,
  cistatus   int(2)       NOT NULL,
    mandator       bigint(20)  default NULL,
    name           varchar(40) NOT NULL,
    addname        varchar(40) NOT NULL,
    swnature       varchar(40) NOT NULL,
    swtype         varchar(10) NOT NULL,
    swport         int(10)     default NULL,
    appl           bigint(20)  default NULL,
    system         bigint(20)  default NULL,
    autompartner   varchar(40) default NULL,
    databoss       bigint(20)  default NULL,
    adm            bigint(20)  default NULL,
    adm2           bigint(20)  default NULL,
    swteam         bigint(20)  default NULL,
    servicesupport bigint(20)  default NULL,
    additional     longtext    default NULL,
  comments   longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(10) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY fullname (fullname),key(system),key(databoss),
  UNIQUE KEY name (fullname),KEY(mandator),key(name),key(servicesupport),
  UNIQUE KEY `srcsys` (srcsys,srcid),key(swteam),key(adm),key(adm2)
);
alter table asset add systemhandle varchar(30)   default NULL;
alter table asset add prodmaintlevel bigint(20)  default NULL;
alter table appl  add slacontroltool varchar(20) default NULL;
alter table appl  add slacontravail  double(8,2) default NULL;
alter table appl  add slacontrbase   varchar(20) default NULL;
alter table appl   add kwords  varchar(255) default NULL;
alter table system add kwords  varchar(255) default NULL;
alter table asset  add kwords  varchar(255) default NULL;
create table lnkswinstancesystem (
  id           bigint(20) NOT NULL,
  swinstance   bigint(20) NOT NULL,
  system       bigint(20) NOT NULL,
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY swinstance (swinstance),
  KEY system (system),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnkaccountingno (
  id           bigint(20)  NOT NULL,
  accountno    varchar(20) NOT NULL,
  refid        bigint(20)  NOT NULL,
  parentobj    varchar(30) NOT NULL,
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(30) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE acc (parentobj,accountno,refid),
  KEY accountno (accountno), KEY refid (refid),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnknfsnasipnet (
  id         bigint(20) NOT NULL,
  systemnfsnas    bigint(20) NOT NULL,
  network         bigint(20) NOT NULL,
  ip              varchar(80) NOT NULL,
  exportoptions   varchar(128) default NULL,
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  UNIQUE name (ip,network,systemnfsnas),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
create table lnkapplapplcomp (
  id           bigint(20) NOT NULL,
  lnkapplappl  bigint(20) NOT NULL,
  sortkey      bigint(20)  default NULL,
  objtype      varchar(20) default NULL,
  obj1id       bigint(20)  default NULL,
  obj2id       bigint(20)  default NULL,
  obj3id       bigint(20)  default NULL,
  obj4id       bigint(20)  default NULL,
  importance   int(2)      default 1,
  #
  #
  comments     longtext    default NULL,
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL, 
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY obj1 (objtype,obj1id),
  KEY obj2 (objtype,obj2id),
  KEY obj3 (objtype,obj3id),
  KEY obj4 (objtype,obj4id),
  KEY lnkapplappl (lnkapplappl),               
  UNIQUE KEY `sortkey` (sortkey),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
alter table system       add allowifupdate int(2) default 0;
alter table appl         add allowifupdate int(2) default 0;
alter table custcontract add allowifupdate int(2) default 0;
alter table swinstance   add allowifupdate int(2) default 0;
alter table liccontract  add allowifupdate int(2) default 0;
alter table appl add criticality char(20) default NULL;
alter table appl   add lastqcheck datetime default NULL,add key(lastqcheck);
alter table system add lastqcheck datetime default NULL,add key(lastqcheck);
alter table asset  add lastqcheck datetime default NULL,add key(lastqcheck);
alter table system add consoleip  varchar(40) default NULL;
alter table ipaddress add accountno varchar(20), add key(accountno);
alter table ipaddress add ifname varchar(20);
alter table swinstance add swinstanceid varchar(20) default NULL;
alter table swinstance add UNIQUE key swinstanceid (swinstanceid);
alter table swinstance add custcostalloc int(2) default 0;
alter table servicesupport add flathourscost float(5,2) default NULL;
alter table appl add is_applwithnoiface bool default '0';
alter table asset  add databoss bigint(20) default NULL,add key(databoss);
alter table system add databoss bigint(20) default NULL,add key(databoss);
alter table lnkapplcustcontract add unique applcontr(appl,custcontract);
alter table asset  add allowifupdate int(2) default 0;
alter table servicesupport add sapservicename varchar(20) default NULL;
alter table servicesupport add sapcompanycode varchar(20) default NULL;
alter table appl       add databoss2 bigint(20)  default NULL;
alter table asset      add databoss2 bigint(20)  default NULL;
alter table system     add databoss2 bigint(20)  default NULL;
alter table swinstance add databoss2 bigint(20)  default NULL;
alter table system     add hostid    varchar(20) default NULL;
alter table system     add vhostsystem bigint(20) default NULL;
alter table appl       add opmode     varchar(20) default NULL;
alter table asset      add conumber   varchar(20) default NULL;
alter table system     add key(conumber);
alter table asset      add key(conumber);
alter table liccontract  add unitcount int(2) default 1;
alter table liccontract  add unittype  varchar(20) default NULL;
alter table liccontract  add databoss bigint(20)  default NULL;
alter table liccontract  add databoss2 bigint(20)  default NULL;
create table lickey (
  id           bigint(20)  NOT NULL,
  liccontract  bigint(20)  NOT NULL,
  name         varchar(128) NOT NULL,
  comments     longtext    default NULL,
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(30) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY liccontract (liccontract),UNIQUE name (name,liccontract),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
alter table lnksoftwaresystem add key(liccontract);
create table lnklicappl (
  id           bigint(20) NOT NULL,
  appl         bigint(20) NOT NULL,
  liccontract  bigint(20),
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  quantity     double(8,2) NOT NULL default '1.00',
  is_avforfuse bool        default '0',
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY liccontract (liccontract),key(is_avforfuse),
  KEY appl (appl),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
alter table system add is_avforfuse bool default '0', add key(is_avforfuse);
alter table asset  add is_avforfuse bool default '0', add key(is_avforfuse);
alter table appl   add eventlang  varchar(5) default NULL;
update appl set eventlang='de';
alter table appl   add chmgrteam    bigint(20) default NULL;
alter table system add is_infrastruct bool default '0', add key(is_infrastruct);
alter table appl   add secstate  varchar(20) default NULL;
alter table servicesupport add fullname varchar(128) default NULL;
alter table osrelease add osclass varchar(20) default NULL,add key(osclass);
create table lnkapplclust   (
  id           bigint(20) NOT NULL,
  appl         bigint(20) NOT NULL,
  clust        bigint(20) NOT NULL,
  comments     longtext    default NULL,
  additional   longtext    default NULL,
  fraction     double(8,2) default '100.00',
  createdate   datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate   datetime NOT NULL default '0000-00-00 00:00:00',
  createuser   bigint(20) default NULL,
  modifyuser   bigint(20) default NULL,
  editor       varchar(100) NOT NULL default '',
  realeditor   varchar(100) NOT NULL default '',
  srcsys       varchar(10) default 'w5base',
  srcid        varchar(20) default NULL,
  srcload      datetime    default NULL,
  PRIMARY KEY  (id),
  KEY appl (appl),UNIQUE applcl(appl,clust),
  KEY clust(clust),
  UNIQUE KEY `srcsys` (srcsys,srcid)
);
alter table swinstance add ssl_url varchar(128) default NULL;
alter table swinstance add ssl_cert_check datetime default NULL;
alter table swinstance add ssl_cert_end datetime default NULL;
alter table swinstance add ssl_cert_begin datetime default NULL;
alter table swinstance add ssl_state varchar(128) default NULL;
alter table swinstance add lastqcheck datetime default NULL,add key(lastqcheck);
