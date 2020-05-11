use w5base;
set FOREIGN_KEY_CHECKS=0;
create table tRnAI_system(
  id              bigint(20)   NOT NULL,
  serviceid       varchar(30)  NOT NULL,
  systemname      varchar(68)  NOT NULL,
  opmode          varchar(20)  default 'nonprod',
  ipaddress       varchar(45),
  costcenter      varchar(80),
  costcentermgr   varchar(128),
  customer        varchar(40),
  department      varchar(40),
  contactemail    varchar(128),
  tools           varchar(256),
  bpver           varchar(40),
  addsoft         varchar(256),
    additional     longtext    default NULL,
  comments    longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (id),
  unique(serviceid),
  unique(systemname)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
create table tRnAI_useraccount(
  id              bigint(20)   NOT NULL,
#  system          bigint(20)   NOT NULL,
  name            varchar(80)  NOT NULL,
  email           varchar(128),domain varchar(40),
  expdate         datetime,
    additional     longtext    default NULL,
  comments    longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (id),
  unique(name),
#  FOREIGN KEY (system) REFERENCES tRnAI_system (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
create table tRnAI_usbsrv(
  id              bigint(20)   NOT NULL,
  name            varchar(128) NOT NULL,
  contact         bigint(20),
  contact2        bigint(20),
  utnport         int(20),
  portcount       int(20) default '20',
  admuser         varchar(40),
  admpass         varchar(40),
    additional     longtext    default NULL,
  comments    longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (id),
  unique(name)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
create table tRnAI_usbsrvport(
  id              varchar(30) NOT NULL,
  usbsrv          bigint(20)  NOT NULL,
  port            varchar(10) NOT NULL,
  system          bigint(20),
    additional     longtext    default NULL,
  comments    longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (id),unique(usbsrv,port),unique(system),
  FOREIGN KEY (usbsrv) REFERENCES tRnAI_usbsrv (id) ON DELETE CASCADE,
  FOREIGN KEY (system) REFERENCES tRnAI_system (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
set FOREIGN_KEY_CHECKS=1;
alter table tRnAI_useraccount add sappersno varchar(20),add bdate datetime;
create table tRnAI_lnkuseraccountsystem(
  id              bigint(20)   NOT NULL,
  system          bigint(20)   NOT NULL,
  useraccount     bigint(20)   NOT NULL,
  reltyp          varchar(20), uflag varchar(20) default NULL,
    additional     longtext    default NULL,
  comments    longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (id),
  UNIQUE(system,useraccount),
  UNIQUE KEY `PrimCheck`(system,uflag),
  FOREIGN KEY (system) REFERENCES tRnAI_system (id) ON DELETE CASCADE,
  FOREIGN KEY (useraccount) REFERENCES tRnAI_useraccount (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
create table tRnAI_instance(
  id              bigint(20)   NOT NULL,
  name            varchar(128) NOT NULL,
  system          bigint(20),
  software        bigint(20), version varchar(30),
  customer        varchar(40), department      varchar(40),
  iusage          varchar(20), subcustomer varchar(40),
  contact         bigint(20),
  contact2        bigint(20),
  tcpport         int(20) not NULL,
  additional longtext    default NULL,
  comments   longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (id),
  FOREIGN KEY (system)  REFERENCES system (id) ON DELETE RESTRICT,
  unique(name)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
create table tRnAI_license(
  id         bigint(20)   NOT NULL,
  fullname   varchar(128) NOT NULL,
  name       varchar(40) NOT NULL,
  ponum      varchar(40),
  plmnum     varchar(40),
  units      int(20),
  expdate    datetime,
  additional longtext    default NULL,
  comments   longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (id),
  unique(fullname)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
create table tRnAI_lnkinstlic(
  id         bigint(20)   NOT NULL,
  instance   bigint(20)   NOT NULL,
  license    bigint(20)   NOT NULL,
  additional longtext     default NULL,
  comments   longtext     default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) default NULL,
  modifyuser bigint(20) default NULL,
  editor     varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (id),
  unique(instance,license),
  FOREIGN KEY (instance) REFERENCES tRnAI_instance (id) ON DELETE CASCADE,
  FOREIGN KEY (license)  REFERENCES tRnAI_license (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
