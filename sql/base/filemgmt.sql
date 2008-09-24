use w5base;
CREATE TABLE filemgmt (
  fid bigint(20) NOT NULL default '0',
  parentid bigint(20) default NULL,
  fullname varchar(255) NOT NULL default '',
  realfile varchar(128),
  contentsize bigint(20),
  contenttype varchar(80),
  parentobj   varchar(40),
  parentrefid varchar(20),
  name varchar(80) NOT NULL default '',
  comments blob,
  srcsys varchar(20) default NULL,
  srcid varchar(20) default NULL,
  srcload datetime default NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  owner bigint(20) NOT NULL default '0',
  editor varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (fid),
  UNIQUE KEY fullname (fullname,parentobj,parentrefid),
  KEY parentrefid (parentobj,parentrefid),
  KEY parentid (parentid),
  KEY realfile (realfile),
  KEY name (name)
);
alter table filemgmt add entrytyp char(20)   default 'file';
alter table filemgmt add additional longtext default NULL;
CREATE TABLE fileacl (
  aclid bigint(20) NOT NULL,
  refid bigint(20) NOT NULL,
  aclparentobj varchar(20) NOT NULL,
  aclmode varchar(10) NOT NULL default 'read',
  acltarget varchar(20) NOT NULL default 'user',
  acltargetid  bigint(20) NOT NULL,
  createdate datetime NOT NULL default '0000-00-00 00:00:00',
  modifydate datetime NOT NULL default '0000-00-00 00:00:00',
  editor varchar(100) NOT NULL default '',
  realeditor varchar(100) NOT NULL default '',
  PRIMARY KEY  (aclid),
  KEY faqid (refid),
  unique key aclmode (aclparentobj,refid,acltarget,aclmode,acltargetid)
);
alter table filemgmt add inheritrights int(1) default '1';
alter table fileacl add comments   longtext;
alter table fileacl add expiration datetime;
alter table fileacl add alertstate varchar(10);
alter table filemgmt add viewcount int(20) not null;
alter table filemgmt add viewlast  datetime default NULL, add key(viewlast);
alter table filemgmt add viewfreq  int(20)  default NULL;
