use w5base;
create table vou (
  id         bigint(20) not null,
  idseq      bigint(6) unsigned zerofill NOT NULL AUTO_INCREMENT,
  code       varchar(40) GENERATED ALWAYS
                         AS (CONCAT('VOU',idseq)),
  shortname   varchar(10) not null, grouptype varchar(10) default 'HUB',
  name        varchar(40) not null,
  cistatus    int(2)      NOT NULL,
  databoss    bigint(20)  default NULL,
  leader      bigint(20), leaderit  bigint(20),
  rorg bigint(20) not null,
  description longtext    default NULL,
  comments    blob, rampupid varchar(20),
  canvasid    varchar(10),
  canvasfield varchar(40),
  canvasownerbuid bigint(20),
  canvasowneritid bigint(20),
  segment     varchar(40),
  rte         bigint(20),
  spc         bigint(20),
  additional  longtext    default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  lastqcheck datetime default NULL,
  srcsys     varchar(100) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  primary key(idseq), unique(id),unique(shortname),
  UNIQUE KEY `srcsys` (srcsys,srcid),
  key(lastqcheck)
) AUTO_INCREMENT=1000;
create table canvas (
  id         bigint(20) not null,
  canvasid    varchar(10),
  name        varchar(40) not null,
  cistatus    int(2)      NOT NULL,
  databoss    bigint(20)  default NULL,
  leader      bigint(20), 
  leaderit  bigint(20),
  rorg bigint(20) not null,
  description longtext    default NULL,
  comments    blob,
  canvasfield varchar(40),
  additional  longtext    default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  lastqcheck datetime default NULL,
  srcsys     varchar(100) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  primary key(id),unique(canvasid,name),
  UNIQUE KEY `srcsys` (srcsys,srcid),
  key(lastqcheck)
) ENGINE=INNODB;
create table lnkcanvas (
  id         bigint(20) not null,
  canvasid   bigint(20) not null,
  ictoid     varchar(20) not null,
  vouid      bigint(20),
  ictono     varchar(20) not null,
  fraction   double(8,2) default '100.00',
  comments    blob,
  additional  longtext    default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  lastqcheck datetime default NULL,
  srcsys     varchar(100) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
  primary key(id),unique(canvasid,ictoid,vouid),
  # unique(vouid),
  UNIQUE KEY `srcsys` (srcsys,srcid),
  # FOREIGN KEY fk_vou (vouid) REFERENCES vou (id) ON DELETE CASCADE,
  FOREIGN KEY fk_canvas (canvasid) REFERENCES canvas (id) ON DELETE CASCADE,
  key(lastqcheck)
) ENGINE=INNODB;
create table subvou (
  id         bigint(20) not null,
  vou        bigint(20) not null,
  name        varchar(40) not null,
  additional  longtext    default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  createuser bigint(20) NOT NULL default '0',
  modifyuser bigint(20) NOT NULL default '0',
  editor varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  srcsys     varchar(100) default 'w5base',
  srcid      varchar(20) default NULL,
  srcload    datetime    default NULL,
 # FOREIGN KEY fk_vou (vou) REFERENCES vou (id) ON DELETE CASCADE,
  primary key(id), unique(vou,name),
  UNIQUE KEY `srcsys` (srcsys,srcid)
) ENGINE=INNODB;
alter table subvou add description varchar(128);
