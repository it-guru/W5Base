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
  leader      bigint(20),
  description longtext    default NULL,
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
  primary key(idseq), unique(id),unique(shortname),
  UNIQUE KEY `srcsys` (srcsys,srcid),
  key(lastqcheck)
) AUTO_INCREMENT=1000;
