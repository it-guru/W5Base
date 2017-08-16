-- drop view  dbo.customDarwinExportDevice;
create view dbo.customDarwinExportDevice as
select ComplianceComputer_MT.ComplianceComputerID  FLEXERASYSTEMID,            
       ComplianceComputer_MT.UUID                  UUID,
       ComplianceComputer_MT.TenantID              TENANTID,
       ComputerName                                SYSTEMNAME,
       OperatingSystem                             SYSTEMOS,
       ServicePack                                 SYSTEMOSPATCHLEVEL,
       NumberOfProcessors                          SYSTEMCPUCOUNT,
       NumberOfLogicalProcessors                   SYSTEMLOGICALCPUCOUNT,
       NumberOfCores                               SYSTEMCORECOUNT,
       ProcessorType                               SYSTEMCPUTTYPE,
       MaxClockSpeed                               SYSTEMCPUSPEED,
       ComplianceComputerType.DefaultValue         SYSTEMINVHOSTTYPE,
       ComplianceComputer_MT.TotalMemory           SYSTENMEMORY,
       ComplianceComputer_MT.ModelNo               ASSETMODLEL,
       ComplianceComputer_MT.SerialNo              ASSETSERIALNO,
       ComplianceComputer_MT.HostID                HOSTID,
       ComplianceComputer_MT.IPAddress             IPADDRLIST,
       ComplianceComputer_MT.InventoryDate         INVENTORYDATE,
       ComplianceComputer_MT.HardwareInventoryDate HARDWAREINVENTORYDATE,
       ComplianceComputer_MT.ServicesInventoryDate SERVICESINVENTORYDATE,
       ComplianceComputer_MT.CreationDate          CDATE,
       CASE WHEN
          VirtualMachine_MT.ComplianceComputerID is null
          THEN '0'
          ELSE '1'
       END                                         ISVM,
       CASE WHEN
          VirtualMachine_MT.HostComplianceComputerID is null and
          VirtualMachine_MT.ComplianceComputerID is not null
          THEN '1'
          ELSE '0'
       END                                         ISVMHOSTMISSING

from dbo.ComplianceComputer_MT 
     left outer join dbo.VirtualMachine_MT
        on dbo.ComplianceComputer_MT.ComplianceComputerID=
           dbo.VirtualMachine_MT.ComplianceComputerID
     join dbo.ComplianceComputerType
        on dbo.ComplianceComputer_MT.ComplianceComputerTypeID=
           dbo.ComplianceComputerType.ComplianceComputerTypeID
where ComplianceComputer_MT.ComplianceComputerStatusID<>4   -- ignore dummy records



-- drop view dbo.customDarwinExportDeviceInst;
create view dbo.customDarwinExportDeviceInst as
select InstalledSoftware_MT.InstalledSoftwareID          ID,
       ComplianceComputerID                              FLEXERASYSTEMID,
       InstalledSoftware_MT.InstallDate                  INSTDATE,
       SoftwareTitle_S.Fullname                          FULLNAME,
       SoftwareTitle_S.Comments                          CMTS,
       SoftwareTitleProduct_S.ProductName                PRODUCTNAME,
       IIF(SoftwareTitleVersion_S.VersionName is null OR
           SoftwareTitleVersion_S.VersionName='',' ',
           SoftwareTitleVersion_S.VersionName)           VERSION,
       IIF(SoftwareTitleVersion_S.VersionWeight is null OR
           SoftwareTitleVersion_S.VersionWeight='',' ',
           SoftwareTitleVersion_S.VersionWeight)         VERSIONWEIGHT,
       SoftwareTitlePublisher_S.PublisherName            PUBLISHERNAME,
       InstalledSoftware_MT.DiscoveryDate                DISCDATE
                     
from dbo.InstalledSoftware_MT
   join SoftwareTitle_S 
      on InstalledSoftware_MT.SoftwareTitleID=
         SoftwareTitle_S.SoftwareTitleID
   join SoftwareTitleProduct_S
      on SoftwareTitle_S.SoftwareTitleProductID=
         SoftwareTitleProduct_S.SoftwareTitleProductID
   join SoftwareTitlePublisher_S
      on SoftwareTitleProduct_S.SoftwareTitlePublisherID=
         SoftwareTitlePublisher_S.SoftwareTitlePublisherID
   join SoftwareTitleVersion_S
      on SoftwareTitle_S.SoftwareTitleVersionID=
         SoftwareTitleVersion_S.SoftwareTitleVersionID;

