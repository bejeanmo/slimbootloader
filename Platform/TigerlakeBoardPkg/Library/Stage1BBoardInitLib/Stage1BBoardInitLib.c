/** @file

  Copyright (c) 2008 - 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Library/PcdLib.h>
#include <Library/IoLib.h>
#include <Library/PciLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/GpioLib.h>
#include <Library/BoardInitLib.h>
#include <Library/SerialPortLib.h>
#include <Library/PlatformHookLib.h>
#include <Library/ConfigDataLib.h>
#include <Library/SpiFlashLib.h>
#include <FspmUpd.h>
#include <Library/DebugLib.h>
#include <IndustryStandard/Pci30.h>
#include <Library/BootloaderCoreLib.h>
#include <Library/BoardSupportLib.h>
#include <PchAccess.h>
#include <CpuRegsAccess.h>
#include <CpuRegs.h>
#include <Library/CryptoLib.h>
#include <ConfigDataDefs.h>
#include <Library/TpmLib.h>
#include <Library/BootGuardLib.h>
#include <PlatformData.h>
#include "GpioTableTglHPreMem.h"
#include "GpioTableTglUPreMem.h"
#include <Library/TimerLib.h>
#include "BoardSaConfigPreMem.h"
#include <PlatformBoardId.h>
#include <TccConfigSubRegions.h>

CONST PLT_DEVICE  mPlatformDevices[]= {
  {{0x00001700}, OsBootDeviceSata  , 0 },
  {{0x00001F05}, OsBootDeviceSpi   , 0 },
  {{0x00001400}, OsBootDeviceUsb   , 0 },
  {{0x01000000}, OsBootDeviceMemory, 0 },
  {{0x00010000}, OsBootDeviceNvme  , 0 },
  {{0x00020000}, OsBootDeviceNvme  , 1 },
  {{0x00050000}, OsBootDeviceNvme  , 2 }
};

VOID
GetBoardId (
  OUT UINT8 *BoardId
);

/**
  Update FSP-M UPD config data for TCC mode and tuning

  @param  FspmUpd            The pointer to the FSP-M UPD to be updated.

  @retval EFI_NOT_FOUND   Features Data not found
                                                Platform features not found
                 EFI_LOAD_ERROR  Tcc Buffer sub-region not found
                 EFI_SUCCESS        Successfully loaded buffer sub-region
**/
EFI_STATUS
TccModePreMemConfig (
  FSPM_UPD  *FspmUpd
)
{
  UINT32        *TccBufferBase;
  UINT32        TccBufferSize;
  UINT32        *TccTuningBase;
  UINT32        TccTuningSize;
 EFI_STATUS    Status;
  PLAT_FEATURES           *PlatformFeatures;
  FEATURES_CFG_DATA       *FeaturesCfgData;
  BIOS_SETTINGS                         *PolicyConfig;
  TCC_STREAM_CONFIGURATION              *StreamConfig;

  Status = EFI_SUCCESS;
  FeaturesCfgData = (FEATURES_CFG_DATA *) FindConfigDataByTag(CDATA_FEATURES_TAG);
  if ((FeaturesCfgData != NULL)  && (!FeaturesCfgData->Features.Tcc)) {
    return EFI_NOT_FOUND;
  }
  DEBUG ((DEBUG_INFO, "TccModePreMemConfig () - Start\n"));

  // TCC related memory settings
  DEBUG ((DEBUG_INFO, "Tcc is enabled\n"));
  FspmUpd->FspmConfig.SaGv                       = 0;    // System Agent Geyserville - SAGV dynamically adjusts the system agent
                                               // voltage and clock frequencies depending on power and performance requirements
  FspmUpd->FspmConfig.DisPgCloseIdleTimeout      = 1;    // controls Page Close Idle Timeout
  FspmUpd->FspmConfig.PowerDownMode              = 0;    // controls command bus tristating during idle periods
  FspmUpd->FspmConfig.WrcFeatureEnable           = 1;
  FspmUpd->FspmConfig.HyperThreading             = 0;
  FspmUpd->FspmConfig.GtClosEnable               = 1;
  FspmUpd->FspmConfig.BiosGuard                  = 0x0;

  FspmUpd->FspmConfig.TccTuningEnable = 1;

  // Load TCC tuning data from container
  TccTuningBase = NULL;
  TccTuningSize = 0;
  Status = LoadComponent (SIGNATURE_32 ('I', 'P', 'F', 'W'), SIGNATURE_32 ('T', 'C', 'C', 'T'),
                          (VOID **)&TccTuningBase, &TccTuningSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "TCC Tuning not found! %r\n", Status));
  } else {
    PlatformFeatures = &((PLATFORM_DATA *)GetPlatformDataPtr ())->PlatformFeatures;
    if (PlatformFeatures != NULL) {
      PlatformFeatures->TcctBase = TccTuningBase;
      PlatformFeatures->TcctSize = TccTuningSize;
    }
    StreamConfig   = (TCC_STREAM_CONFIGURATION *) TccTuningBase;
    PolicyConfig = (BIOS_SETTINGS *) &StreamConfig->Info.Format1.BiosSettings;

    FspmUpd->FspmConfig.SaGv                = PolicyConfig->SaGv;
    FspmUpd->FspmConfig.HyperThreading      = PolicyConfig->HyperThreading;
    if (PolicyConfig->MemPm == 0) {
      FspmUpd->FspmConfig.PowerDownMode         = 0;
     FspmUpd->FspmConfig.DisPgCloseIdleTimeout  = 1;
    } else {
      FspmUpd->FspmConfig.PowerDownMode         = 1;
      FspmUpd->FspmConfig.DisPgCloseIdleTimeout = 0;
    }

    FspmUpd->FspmConfig.TccStreamCfgBase = (UINT32) (UINTN)TccTuningBase;
    FspmUpd->FspmConfig.TccStreamCfgSize = TccTuningSize;
  }

  // Load Tcc buffers data from container
  TccBufferBase = NULL;
  TccBufferSize = 0;
  Status = LoadComponent (SIGNATURE_32 ('I', 'P', 'F', 'W'), SIGNATURE_32 ('T', 'C', 'C', 'B'),
                                (VOID **)&TccBufferBase, &TccBufferSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "TCC  Buffer not found! %r\n", Status));
  } else {
    PlatformFeatures = &((PLATFORM_DATA *)GetPlatformDataPtr ())->PlatformFeatures;
    if (PlatformFeatures != NULL) {
      PlatformFeatures->TccBufferBase = TccBufferBase;
      PlatformFeatures->TccBufferSize = TccBufferSize;
    }
    // Assign the Tcc buffer to FSP M UPDs
    FspmUpd->FspmConfig.TccBufferCfgBase = (UINT32)(UINTN)TccBufferBase;
    FspmUpd->FspmConfig.TccBufferCfgSize = TccBufferSize;
  }
  DEBUG ((DEBUG_INFO, "TccModePreMemConfig () - End\n"));

  return Status;
}

/**
  Update FSP-M UPD config data

  @param  FspmUpdPtr            The pointer to the FSP-M UPD to be updated.

  @retval None
**/
VOID
EFIAPI
UpdateFspConfig (
  VOID                     *FspmUpdPtr
)
{
  FSPM_UPD                 *FspmUpd;
  FSPM_ARCH_UPD            *FspmArchUpd;
  FSP_M_CONFIG             *Fspmcfg;
  SECURITY_CFG_DATA        *SecCfgData;
  MEMORY_CFG_DATA          *MemCfgData;
  GRAPHICS_CFG_DATA        *GfxCfgData;
  UINT8                    Index;
  UINT32                   SpdData[3];
  UINT16                   BoardId;
  UINT8                    SaDisplayConfigTable[16] = { 0 };
  FEATURES_CFG_DATA       *FeaturesCfgData;
  SILICON_CFG_DATA        *SiCfgData;
  PLATFORM_DATA           *PlatformData;
  UINT8                   DebugPort;

  FspmUpd     = (FSPM_UPD *)FspmUpdPtr;
  FspmArchUpd = &FspmUpd->FspmArchUpd;
  Fspmcfg     = &FspmUpd->FspmConfig;
  FeaturesCfgData = (FEATURES_CFG_DATA *) FindConfigDataByTag(CDATA_FEATURES_TAG);

  BoardId = GetPlatformId();

  SecCfgData = (SECURITY_CFG_DATA *)FindConfigDataByTag (CDATA_SECURITY_TAG);
  if (SecCfgData != NULL) {
    DEBUG ((DEBUG_INFO, "Load Security Cfg Data\n"));
    // Configure Sgx SPD Data
    Fspmcfg->EnableSgx = SecCfgData->EnableSgx;
    Fspmcfg->PrmrrSize = SecCfgData->PrmrrSize;
  } else {
    DEBUG ((DEBUG_INFO, "Failed to find security CFG!\n"));
  }

  DebugPort = GetDebugPort ();
  if (DebugPort < PCH_MAX_SERIALIO_UART_CONTROLLERS) {
    Fspmcfg->PcdDebugInterfaceFlags = BIT4;
    Fspmcfg->SerialIoUartDebugControllerNumber = DebugPort;
  } else {
    Fspmcfg->PcdDebugInterfaceFlags = BIT1;
    if (DebugPort == 0xFF) {
      Fspmcfg->PcdIsaSerialUartBase = 0;
    } else {
      Fspmcfg->PcdIsaSerialUartBase = 1;
    }
  }

  //FSPM has a default value initially, during boot time, Slimboot can modify
  //it using data from CfgData blob.
  //then call FSPMemoryInit() who consumes all the overridden values.

  DEBUG ((DEBUG_INFO, "FSPM CfgData assignment\n"));
  MemCfgData = (MEMORY_CFG_DATA *)FindConfigDataByTag (CDATA_MEMORY_TAG);
  if (MemCfgData == NULL) {
    CpuHalt ("Failed to find memory CFGDATA!");
    return;
  }
  DEBUG ((DEBUG_INFO, "Load Memory Cfg Data\n"));
  CopyMem (&Fspmcfg->SpdAddressTable, MemCfgData->SpdAddressTable, sizeof(MemCfgData->SpdAddressTable));

  PlatformData = (PLATFORM_DATA *)GetPlatformDataPtr ();
  if (PlatformData == NULL) {
    return;
  }
  PlatformData->PlatformFeatures.VtdEnable = (!MemCfgData->VtdDisable) & FeaturePcdGet (PcdVtdEnabled);

  // Need enable VTD if TCC is enalbed.
  if (FeaturesCfgData != NULL) {
    if (FeaturesCfgData->Features.Tcc) {
      PlatformData->PlatformFeatures.VtdEnable = 1;
    }
  }

  // Need enable VTd if TSN is enabled
  SiCfgData = (SILICON_CFG_DATA *)FindConfigDataByTag (CDATA_SILICON_TAG);
  if (SiCfgData != NULL) {
    if (SiCfgData->PchTsnEnable == 1) {
      DEBUG ((DEBUG_INFO, "TSN is enabled\n"));
      PlatformData->PlatformFeatures.VtdEnable = 1;
    }
  }

  // Memory SPD Data
  SpdData[0] = 0;
  SpdData[1] = (UINT32)(UINTN) (((MEM_SPD0_CFG_DATA *)FindConfigDataByTag (CDATA_MEM_SPD0_TAG))->MemorySpdPtr0);
  SpdData[2] = (UINT32)(UINTN) (((MEM_SPD1_CFG_DATA *)FindConfigDataByTag (CDATA_MEM_SPD1_TAG))->MemorySpdPtr1);
  Fspmcfg->MemorySpdPtr000  = SpdData[MemCfgData->SpdDataSel000];
  Fspmcfg->MemorySpdPtr001  = SpdData[MemCfgData->SpdDataSel001];
  Fspmcfg->MemorySpdPtr010  = SpdData[MemCfgData->SpdDataSel010];
  Fspmcfg->MemorySpdPtr011  = SpdData[MemCfgData->SpdDataSel011];
  Fspmcfg->MemorySpdPtr020  = SpdData[MemCfgData->SpdDataSel020];
  Fspmcfg->MemorySpdPtr021  = SpdData[MemCfgData->SpdDataSel021];
  Fspmcfg->MemorySpdPtr030  = SpdData[MemCfgData->SpdDataSel030];
  Fspmcfg->MemorySpdPtr031  = SpdData[MemCfgData->SpdDataSel031];
  Fspmcfg->MemorySpdPtr100  = SpdData[MemCfgData->SpdDataSel100];
  Fspmcfg->MemorySpdPtr101  = SpdData[MemCfgData->SpdDataSel101];
  Fspmcfg->MemorySpdPtr110  = SpdData[MemCfgData->SpdDataSel110];
  Fspmcfg->MemorySpdPtr111  = SpdData[MemCfgData->SpdDataSel111];
  Fspmcfg->MemorySpdPtr120  = SpdData[MemCfgData->SpdDataSel120];
  Fspmcfg->MemorySpdPtr121  = SpdData[MemCfgData->SpdDataSel121];
  Fspmcfg->MemorySpdPtr130  = SpdData[MemCfgData->SpdDataSel130];
  Fspmcfg->MemorySpdPtr131  = SpdData[MemCfgData->SpdDataSel131];

  //Dq/Dqs Mapping arrays
  CopyMem (&Fspmcfg->DqsMapCpu2DramMc0Ch0, MemCfgData->DqsMapCpu2DramMc0Ch0, sizeof(MemCfgData->DqsMapCpu2DramMc0Ch0));
  CopyMem (&Fspmcfg->DqsMapCpu2DramMc0Ch1, MemCfgData->DqsMapCpu2DramMc0Ch1, sizeof(MemCfgData->DqsMapCpu2DramMc0Ch1));
  CopyMem (&Fspmcfg->DqsMapCpu2DramMc0Ch2, MemCfgData->DqsMapCpu2DramMc0Ch2, sizeof(MemCfgData->DqsMapCpu2DramMc0Ch2));
  CopyMem (&Fspmcfg->DqsMapCpu2DramMc0Ch3, MemCfgData->DqsMapCpu2DramMc0Ch3, sizeof(MemCfgData->DqsMapCpu2DramMc0Ch3));
  CopyMem (&Fspmcfg->DqsMapCpu2DramMc1Ch0, MemCfgData->DqsMapCpu2DramMc1Ch0, sizeof(MemCfgData->DqsMapCpu2DramMc1Ch0));
  CopyMem (&Fspmcfg->DqsMapCpu2DramMc1Ch1, MemCfgData->DqsMapCpu2DramMc1Ch1, sizeof(MemCfgData->DqsMapCpu2DramMc1Ch1));
  CopyMem (&Fspmcfg->DqsMapCpu2DramMc1Ch2, MemCfgData->DqsMapCpu2DramMc1Ch2, sizeof(MemCfgData->DqsMapCpu2DramMc1Ch2));
  CopyMem (&Fspmcfg->DqsMapCpu2DramMc1Ch3, MemCfgData->DqsMapCpu2DramMc1Ch3, sizeof(MemCfgData->DqsMapCpu2DramMc1Ch3));

  CopyMem (&Fspmcfg->DqMapCpu2DramMc0Ch0, MemCfgData->DqMapCpu2DramMc0Ch0, sizeof(MemCfgData->DqMapCpu2DramMc0Ch0));
  CopyMem (&Fspmcfg->DqMapCpu2DramMc0Ch1, MemCfgData->DqMapCpu2DramMc0Ch1, sizeof(MemCfgData->DqMapCpu2DramMc0Ch1));
  CopyMem (&Fspmcfg->DqMapCpu2DramMc0Ch2, MemCfgData->DqMapCpu2DramMc0Ch2, sizeof(MemCfgData->DqMapCpu2DramMc0Ch2));
  CopyMem (&Fspmcfg->DqMapCpu2DramMc0Ch3, MemCfgData->DqMapCpu2DramMc0Ch3, sizeof(MemCfgData->DqMapCpu2DramMc0Ch3));
  CopyMem (&Fspmcfg->DqMapCpu2DramMc1Ch0, MemCfgData->DqMapCpu2DramMc1Ch0, sizeof(MemCfgData->DqMapCpu2DramMc1Ch0));
  CopyMem (&Fspmcfg->DqMapCpu2DramMc1Ch1, MemCfgData->DqMapCpu2DramMc1Ch1, sizeof(MemCfgData->DqMapCpu2DramMc1Ch1));
  CopyMem (&Fspmcfg->DqMapCpu2DramMc1Ch2, MemCfgData->DqMapCpu2DramMc1Ch2, sizeof(MemCfgData->DqMapCpu2DramMc1Ch2));
  CopyMem (&Fspmcfg->DqMapCpu2DramMc1Ch3, MemCfgData->DqMapCpu2DramMc1Ch3, sizeof(MemCfgData->DqMapCpu2DramMc1Ch3));

  Fspmcfg->DqPinsInterleaved      = MemCfgData->DqPinsInterleaved;

  //RComp
  Fspmcfg->RcompResistor = MemCfgData->RcompResistor;
  CopyMem (&Fspmcfg->RcompTarget, MemCfgData->RcompTarget, sizeof(MemCfgData->RcompTarget));

  Fspmcfg->MrcFastBoot          = MemCfgData->MrcFastBoot;
  Fspmcfg->RmtPerTask           = MemCfgData->RmtPerTask;
  Fspmcfg->IedSize              = MemCfgData->IedSize;
  Fspmcfg->TsegSize             = MemCfgData->TsegSize;
  Fspmcfg->MmioSize             = MemCfgData->MmioSize;
  Fspmcfg->SmbusEnable          = MemCfgData->SmbusEnable;

  Fspmcfg->PlatformMemorySize   = MemCfgData->PlatformMemorySize;
  Fspmcfg->X2ApicOptOut         = MemCfgData->X2ApicOptOut;
  Fspmcfg->DmaControlGuarantee  = MemCfgData->DmaControlGuarantee;
  Fspmcfg->TxtDprMemorySize     = MemCfgData->TxtDprMemorySize;
  Fspmcfg->BiosAcmBase          = MemCfgData->BiosAcmBase;

  Fspmcfg->UserBd               = MemCfgData->UserBd;
  Fspmcfg->RealtimeMemoryTiming = MemCfgData->RealtimeMemoryTiming;
  Fspmcfg->EnableC6Dram         = MemCfgData->EnableC6Dram;
  Fspmcfg->CpuRatio             = MemCfgData->CpuRatio;
  Fspmcfg->BootFrequency        = MemCfgData->BootFrequency;
  Fspmcfg->ActiveCoreCount      = MemCfgData->ActiveCoreCount;
  Fspmcfg->FClkFrequency        = MemCfgData->FClkFrequency;
  Fspmcfg->MrcSafeConfig        = MemCfgData->MrcSafeConfig;
  Fspmcfg->EnhancedInterleave   = MemCfgData->EnhancedInterleave;
  Fspmcfg->RankInterleave       = MemCfgData->RankInterleave;
  Fspmcfg->RhPrevention         = MemCfgData->RhPrevention;
  if(MemCfgData->RhPrevention == 1) {
    Fspmcfg->RhSolution         = MemCfgData->RhSolution;
  }
  if((MemCfgData->RhPrevention == 1) || (MemCfgData->RhSolution == 0)) {
    Fspmcfg->RhActProbability   = MemCfgData->RhActProbability;
  }
  Fspmcfg->ExitOnFailure        = MemCfgData->ExitOnFailure;
  Fspmcfg->ChHashEnable         = MemCfgData->ChHashEnable;
  Fspmcfg->ChHashInterleaveBit  = MemCfgData->ChHashInterleaveBit;
  Fspmcfg->ChHashMask           = MemCfgData->ChHashMask;
//    Fspmcfg->CkeRankMapping       = MemCfgData->CkeRankMapping;
  Fspmcfg->RemapEnable          = MemCfgData->RemapEnable;
  Fspmcfg->ScramblerSupport     = MemCfgData->ScramblerSupport;

  //MRC Training algorithms
  Fspmcfg->RMT                  = MemCfgData->RMT;
  Fspmcfg->BdatEnable           = MemCfgData->BdatEnable;
  Fspmcfg->BdatTestType         = MemCfgData->BdatTestType;
  Fspmcfg->RMC                  = MemCfgData->RMC;
  Fspmcfg->MEMTST               = MemCfgData->MEMTST;
  Fspmcfg->ECT                  = MemCfgData->ECT;
//    Fspmcfg->RaplLim1WindX        = MemCfgData->RaplLim1WindX;
//    Fspmcfg->RaplLim1WindY        = MemCfgData->RaplLim1WindY;
//    Fspmcfg->RaplLim1Pwr          = MemCfgData->RaplLim1Pwr;

  CopyMem (Fspmcfg->DmiGen3RootPortPreset, MemCfgData->DmiGen3RootPortPreset, sizeof(MemCfgData->DmiGen3RootPortPreset));
  CopyMem (Fspmcfg->DmiGen3EndPointPreset, MemCfgData->DmiGen3EndPointPreset, sizeof(MemCfgData->DmiGen3EndPointPreset));
  CopyMem (Fspmcfg->DmiGen3EndPointHint,   MemCfgData->DmiGen3EndPointHint,   sizeof(MemCfgData->DmiGen3EndPointHint));
  CopyMem (Fspmcfg->PcieClkSrcUsage,       MemCfgData->PcieClkSrcUsage,       sizeof(MemCfgData->PcieClkSrcUsage));
  CopyMem (Fspmcfg->PcieClkSrcClkReq,      MemCfgData->PcieClkSrcClkReq,      sizeof(MemCfgData->PcieClkSrcClkReq));

  Fspmcfg->PchNumRsvdSmbusAddresses  = sizeof (MemCfgData->SmbusAddressTable) / sizeof (MemCfgData->SmbusAddressTable[0]);
  Fspmcfg->RsvdSmbusAddressTablePtr  = (UINT32) (UINTN)MemCfgData->SmbusAddressTable;
  Fspmcfg->UsbTcPortEnPreMem         = MemCfgData->UsbTcPortEnPreMem;

  Fspmcfg->TmeEnable = MemCfgData->TmeEnable;

  // Disable TME, if
  // 1. If this is a FuSa Enabled SKU
  // 2. In-Band ECC is enabled
  if (Fspmcfg->TmeEnable != 0) {
    if ((AsmReadMsr64(MSR_CORE_CAPABILITIES) & B_MSR_CORE_CAPABILITIES_FUSA_SUPPORTED) != 0 ||
          MemCfgData->Ibecc != 0) {
      DEBUG ((DEBUG_INFO, "FuSa-Supported SKU Detected or Ibecc enabled. Disabling TME.\n"));
      Fspmcfg->TmeEnable = 0;
    }
  }

  DEBUG ((DEBUG_INFO, "SkipMbpHob = 0x%x\n", Fspmcfg->SkipMbpHob));
  Fspmcfg->SkipMbpHob = 0;

  GfxCfgData = (GRAPHICS_CFG_DATA *)FindConfigDataByTag (CDATA_GRAPHICS_TAG);
  if (GfxCfgData != NULL) {
    DEBUG ((DEBUG_INFO, "Load Graphics Cfg Data\n"));
    Fspmcfg->IgdDvmt50PreAlloc         = GfxCfgData->IgdDvmt50PreAlloc;
    Fspmcfg->ApertureSize              = GfxCfgData->ApertureSize;
    Fspmcfg->GttSize                   = GfxCfgData->GttSize;
    Fspmcfg->InternalGfx               = GfxCfgData->InternalGfx;
    Fspmcfg->PrimaryDisplay            = GfxCfgData->PrimaryDisplay;
  } else {
    DEBUG ((DEBUG_INFO, "Failed to find GFX CFG!\n"));
  }

  // Value from EDKII bios, refine these settings later.
  FspmArchUpd->StackBase = 0xFEF3FF00;
  FspmArchUpd->StackSize = 0x40000;
  Fspmcfg->TcssXdciEn = 0x1;

  // Following UPDs are related to TCC . But all of these are also generic features that can be changed regardless of TCC feature.
  Fspmcfg->SaGv                       = MemCfgData->SaGv;                   // System Agent Geyserville - SAGV dynamically adjusts the system agent
                                                                                                                        // voltage and clock frequencies depending on power and performance requirements
  Fspmcfg->DisPgCloseIdleTimeout      = MemCfgData->DisPgCloseIdleTimeout;  // controls Page Close Idle Timeout
  Fspmcfg->PowerDownMode              = MemCfgData->PowerDownMode;          // controls command bus tristating during idle periods
  Fspmcfg->VtdDisable                 = (UINT8)(!PlatformData->PlatformFeatures.VtdEnable);
  Fspmcfg->WrcFeatureEnable           = MemCfgData->WrcFeatureEnable;
  Fspmcfg->HyperThreading             = MemCfgData->HyperThreading;
  Fspmcfg->GtClosEnable               = MemCfgData->GtClosEnable;
  Fspmcfg->VmxEnable                  = MemCfgData->VmxEnable;

  Fspmcfg->BiosGuard = 0x0;               // Need disable, else it will failed in fSPS
  Fspmcfg->SafeMode = 0x1;                // Need enable, else failed in MRC

  // IBECC configuration
  Fspmcfg->Ibecc                    = MemCfgData->Ibecc;
  Fspmcfg->IbeccParity              = MemCfgData->IbeccParity;
  Fspmcfg->IbeccOperationMode       = MemCfgData->IbeccOperationMode;
  Fspmcfg->IbeccErrorInj            = MemCfgData->IbeccErrorInj;
  for (Index = 0; Index < 8; Index++) {
    Fspmcfg->IbeccProtectedRegionEnable[Index] = MemCfgData->IbeccProtectedRegionEnable[Index];
    Fspmcfg->IbeccProtectedRegionBase[Index]   = MemCfgData->IbeccProtectedRegionBase[Index];
    if (MemCfgData->IbeccProtectedRegionMask[Index] > 0x3FFF) {
      MemCfgData->IbeccProtectedRegionMask[Index] = 0x3FFF;
    }
    Fspmcfg->IbeccProtectedRegionMask[Index]   = MemCfgData->IbeccProtectedRegionMask[Index];
  }


  DEBUG((DEBUG_INFO, "board Id = %x .....\n", BoardId));
  //
  // Display DDI Initialization ( default Native GPIO as per board during AUTO case)
  //
  switch (BoardId) {
  case BoardIdTglHDdr4SODimm:
  case 0xF:
    CopyMem(SaDisplayConfigTable, (VOID *)(UINTN)mTglHDdr4RowDisplayDdiConfig, sizeof(mTglHDdr4RowDisplayDdiConfig));
    break;
  case BoardIdTglUDdr4:
    CopyMem(SaDisplayConfigTable, (VOID *)(UINTN)mTglUDdr4RowDisplayDdiConfig, sizeof(mTglUDdr4RowDisplayDdiConfig));
    break;
  case BoardIdTglULp4Type4:
    CopyMem(SaDisplayConfigTable, (VOID *)(UINTN)mTglULpDdr4RowDisplayDdiConfig, sizeof(mTglULpDdr4RowDisplayDdiConfig));
    break;
  default:
    DEBUG((DEBUG_INFO, "Unsupported board Id %x .....\n", BoardId));
    break;
  }
  Fspmcfg->DdiPortAConfig = SaDisplayConfigTable[0];
  Fspmcfg->DdiPortBConfig = SaDisplayConfigTable[1];
  Fspmcfg->DdiPortAHpd = SaDisplayConfigTable[2];
  Fspmcfg->DdiPortBHpd = SaDisplayConfigTable[3];
  Fspmcfg->DdiPortCHpd = SaDisplayConfigTable[4];
  Fspmcfg->DdiPort1Hpd = SaDisplayConfigTable[5];
  Fspmcfg->DdiPort2Hpd = SaDisplayConfigTable[6];
  Fspmcfg->DdiPort3Hpd = SaDisplayConfigTable[7];
  Fspmcfg->DdiPort4Hpd = SaDisplayConfigTable[8];
  Fspmcfg->DdiPortADdc = SaDisplayConfigTable[9];
  Fspmcfg->DdiPortBDdc = SaDisplayConfigTable[10];
  Fspmcfg->DdiPortCDdc = SaDisplayConfigTable[11];
  Fspmcfg->DdiPort1Ddc = SaDisplayConfigTable[12];
  Fspmcfg->DdiPort2Ddc = SaDisplayConfigTable[13];
  Fspmcfg->DdiPort3Ddc = SaDisplayConfigTable[14];
  Fspmcfg->DdiPort4Ddc = SaDisplayConfigTable[15];

  if (PlatformData->PlatformFeatures.VtdEnable == 1) {
    Fspmcfg->VtdIgdEnable = 1;
    Fspmcfg->VtdIpuEnable = 1;
    Fspmcfg->VtdIopEnable = 1;
    Fspmcfg->VtdItbtEnable = 1;
    Fspmcfg->VtdBaseAddress[0] = 0xfed90000;
    Fspmcfg->VtdBaseAddress[1] = 0xfed92000;
    Fspmcfg->VtdBaseAddress[2] = 0xfed91000;
    Fspmcfg->VtdBaseAddress[3] = 0xfed84000;
    Fspmcfg->VtdBaseAddress[4] = 0xfed85000;
    Fspmcfg->VtdBaseAddress[5] = 0xfed86000;
    Fspmcfg->VtdBaseAddress[6] = 0xfed87000;
  }

  // Tcc enabling
  TccModePreMemConfig (FspmUpd);

  Fspmcfg->BootFrequency = 0x2;

  // will hang using default upds
  Fspmcfg->PchHdaEnable = 0x0;
  Fspmcfg->PchHdaAudioLinkDmicClkAPinMux[0] = 0x29460c06;
  Fspmcfg->PchHdaAudioLinkDmicClkAPinMux[1] = 0x29460e04;
  Fspmcfg->PchHdaAudioLinkDmicClkBPinMux[0] = 0x29461402;
  Fspmcfg->PchHdaAudioLinkDmicClkBPinMux[1] = 0x29461603;
  Fspmcfg->PchHdaAudioLinkDmicDataPinMux[0] = 0x29460407;
  Fspmcfg->PchHdaAudioLinkDmicDataPinMux[1] = 0x29460605;
  Fspmcfg->PchHdaAudioLinkSndwEnable[1] = 0x1;

  Fspmcfg->PchTraceHubMode      = MemCfgData->PchTraceHubMode;
  Fspmcfg->PlatformDebugConsent = MemCfgData->PlatformDebugConsent;
  Fspmcfg->DciEn                = MemCfgData->DciEn;

  // ES2 A1 silicon need set this to 1
  Fspmcfg->McParity = MemCfgData->McParity;

  if (GetBootMode() == BOOT_ON_FLASH_UPDATE) {
    Fspmcfg->SiSkipOverrideBootModeWhenFwUpdate = TRUE;
  }

  Fspmcfg->DebugInterfaceLockEnable = TRUE;
  if (PcdGetBool(PcdFastBootEnabled)) {
    Fspmcfg->CpuPcieRpEnableMask           = 0;
  }
}

/**
  Determine if this is firmware update mode.

  This function will determine if we have to put system in firmware update mode.

  @retval  EFI_SUCCESS           The operation completed successfully.
  @retval  others                There is error happening.
**/
BOOLEAN
IsFirmwareUpdate ()
{
  //
  // Check if state machine is set to capsule processing mode.
  //
  if (CheckStateMachine (NULL) == EFI_SUCCESS) {
    return TRUE;
  }

  //
  // Check if platform firmware update trigger is set.
  //
  if (IoRead32 (ACPI_BASE_ADDRESS + R_ACPI_IO_OC_WDT_CTL) & BIT16) {
    return TRUE;
  }

  return FALSE;
}

/**
  Initialize the SPI controller.

  @retval    None
**/
VOID
SpiControllerInitialize (
  VOID
)
{
  UINT32                  SpiAddress;
  UINT32                  SpiBar;

  SpiAddress = GetDeviceAddr (OsBootDeviceSpi, 0);
  SpiAddress = TO_PCI_LIB_ADDRESS (SpiAddress);

  // Enable PCI config space for SPI device
  SpiBar = PciRead32(SpiAddress + PCI_BASE_ADDRESSREG_OFFSET) & 0xFFFFF000;
  if (SpiBar == 0) {
    PciWrite32(SpiAddress + R_SPI_CFG_BAR0, SPI_TEMP_MEM_BASE_ADDRESS);
    PciWrite8(SpiAddress + 4, 6);
  }

  SpiConstructor ();
}


/**
    Read the Platform Features from the config data
**/
VOID
PlatformFeaturesInit (
  VOID
  )
{
  FEATURES_CFG_DATA           *FeaturesCfgData;
  LOADER_GLOBAL_DATA          *LdrGlobal;
  PLATFORM_DATA               *PlatformData;
  PLAT_FEATURES               *PlatformFeatures;
  UINTN                        HeciBaseAddress;

  // Set common features
  LdrGlobal = (LOADER_GLOBAL_DATA *)GetLoaderGlobalDataPointer ();
  LdrGlobal->LdrFeatures |= FeaturePcdGet (PcdAcpiEnabled)?FEATURE_ACPI:0;
  LdrGlobal->LdrFeatures |= FeaturePcdGet (PcdVerifiedBootEnabled)?FEATURE_VERIFIED_BOOT:0;
  LdrGlobal->LdrFeatures |= FeaturePcdGet (PcdMeasuredBootEnabled)?FEATURE_MEASURED_BOOT:0;

  // Disable feature by configuration data.
  FeaturesCfgData = (FEATURES_CFG_DATA *) FindConfigDataByTag(CDATA_FEATURES_TAG);
  if (FeaturesCfgData != NULL) {
    if (FeaturesCfgData->Features.Acpi == 0) {
      LdrGlobal->LdrFeatures &= ~FEATURE_ACPI;
    }

    if (FeaturesCfgData->Features.MeasuredBoot == 0) {
      LdrGlobal->LdrFeatures &= ~FEATURE_MEASURED_BOOT;
    }
     // Update platform specific feature from configuration data.
    PlatformFeatures           = &((PLATFORM_DATA *)GetPlatformDataPtr ())->PlatformFeatures;
    if (PlatformFeatures != NULL) {
       PlatformFeatures->TccMode   = FeaturesCfgData->Features.Tcc;
       PlatformFeatures->TccBufferBase  = NULL;
       PlatformFeatures->TccBufferSize  = 0;
    }
  } else {
    DEBUG ((DEBUG_INFO, "FEATURES CFG DATA NOT FOUND!\n"));
  }

  // Disable features by boot guard profile
  PlatformData = (PLATFORM_DATA *)GetPlatformDataPtr ();
  if (PlatformData != NULL) {
    HeciBaseAddress = MM_PCI_ADDRESS (
                        0x0,
                        22,
                        0x0,
                        0x0
                        );
    GetBootGuardInfo (HeciBaseAddress, &PlatformData->BtGuardInfo);
    DEBUG ((DEBUG_INFO, "GetPlatformDataPtr is copied 0x%08X \n", PlatformData));
    if (!PlatformData->BtGuardInfo.MeasuredBoot) {
      LdrGlobal->LdrFeatures &= ~FEATURE_MEASURED_BOOT;
    }
    if (!PlatformData->BtGuardInfo.VerifiedBoot) {
      LdrGlobal->LdrFeatures &= ~FEATURE_VERIFIED_BOOT;
    }
  }
}

/**
  Initialize TPM.
**/
VOID
TpmInitialize (
  VOID
  )
{
  EFI_STATUS                   Status;
  UINT8                        BootMode;
  PLATFORM_DATA               *PlatformData;
  LOADER_GLOBAL_DATA          *LdrGlobal;

  BootMode     = GetBootMode();
  PlatformData = (PLATFORM_DATA *)GetPlatformDataPtr ();

  if((PlatformData != NULL) && PlatformData->BtGuardInfo.MeasuredBoot &&
    (!PlatformData->BtGuardInfo.DisconnectAllTpms) &&
    ((PlatformData->BtGuardInfo.TpmType == dTpm20) || (PlatformData->BtGuardInfo.TpmType == Ptt))){

    // Initialize TPM if it has not already been initialized by BootGuard component (i.e. ACM)
    Status = TpmInit(PlatformData->BtGuardInfo.BypassTpmInit, BootMode);
    if (EFI_ERROR (Status)) {
      CpuHalt ("Tpm Initialization failed !!\n");
    } else {
      if (BootMode != BOOT_ON_S3_RESUME) {
        // Create and add BootGuard Event logs in TCG Event log
        CreateTpmEventLog (PlatformData->BtGuardInfo.TpmType);
      }
    }
  } else {
    DisableTpm();

    LdrGlobal = (LOADER_GLOBAL_DATA *)GetLoaderGlobalDataPointer ();
    LdrGlobal->LdrFeatures &= ~FEATURE_MEASURED_BOOT;
  }
}

/**
  Read the current platform state from PM status reg.

  @retval  Bootmode current power state.
**/
UINT8
GetPlatformPowerState (
  VOID
  )
{
  UINT8         BootMode;
  UINT32        PmconA;

  PmconA = MmioRead32 (PCH_PWRM_BASE_ADDRESS + R_PMC_PWRM_GEN_PMCON_A);

  //
  // Clear PWRBTNOR_STS
  //
  if (IoRead16 (ACPI_BASE_ADDRESS + R_ACPI_IO_PM1_STS) & B_ACPI_IO_PM1_STS_PRBTNOR) {
    IoWrite16 (ACPI_BASE_ADDRESS + R_ACPI_IO_PM1_STS, B_ACPI_IO_PM1_STS_PRBTNOR);
  }

  //
  // If Global Reset Status, Power Failure. Host Reset Status bits are set, return S5 State
  //
  if ((PmconA & (B_PMC_PWRM_GEN_PMCON_A_GBL_RST_STS | B_PMC_PWRM_GEN_PMCON_A_PWR_FLR | B_PMC_PWRM_GEN_PMCON_A_HOST_RST_STS)) != 0) {
    return BOOT_WITH_FULL_CONFIGURATION;
  }

  BootMode = BOOT_WITH_FULL_CONFIGURATION;
  if (IoRead16 (ACPI_BASE_ADDRESS + R_ACPI_IO_PM1_STS) & B_ACPI_IO_PM1_STS_WAK) {
    switch (IoRead16 (ACPI_BASE_ADDRESS + R_ACPI_IO_PM1_CNT) & B_ACPI_IO_PM1_CNT_SLP_TYP) {
      case V_ACPI_IO_PM1_CNT_S3:
        BootMode = BOOT_ON_S3_RESUME;
        break;
      case V_ACPI_IO_PM1_CNT_S4:
        BootMode = BOOT_ON_S4_RESUME;
        break;
      case V_ACPI_IO_PM1_CNT_S5:
        BootMode = BOOT_ON_S5_RESUME;
        break;
      default:
        BootMode = BOOT_WITH_FULL_CONFIGURATION;
        break;
    }
  }

  ///
  /// Clear Wake Status
  /// Also clear the PWRBTN_EN, it causes SMI# otherwise (SCI_EN is 0)
  ///
  IoAndThenOr32 (ACPI_BASE_ADDRESS + R_ACPI_IO_PM1_STS, (UINT32)~B_ACPI_IO_PM1_EN_PWRBTN_EN, B_ACPI_IO_PM1_STS_WAK);

  if ((MmioRead8 (PCH_PWRM_BASE_ADDRESS + R_PMC_PWRM_GEN_PMCON_B) & B_PMC_PWRM_GEN_PMCON_B_RTC_PWR_STS) != 0) {
    BootMode = BOOT_WITH_FULL_CONFIGURATION;

    ///
    /// Clear Sleep Type
    ///
    IoAndThenOr16 (ACPI_BASE_ADDRESS + R_ACPI_IO_PM1_CNT, (UINT16) ~B_ACPI_IO_PM1_CNT_SLP_TYP, V_ACPI_IO_PM1_CNT_S0);
  }

  ///
  /// Disable Power Management Event EN
  ///
  IoAnd32 (ACPI_BASE_ADDRESS + R_ACPI_IO_GPE0_EN_127_96, (UINT32)~B_ACPI_IO_GPE0_EN_127_96_PME_B0);

  return BootMode;
}

/**
  Initialize Board specific things in Stage1 Phase

  @param[in]  InitPhase            Indicates a board init phase to be initialized

  @retval None
**/
VOID
EFIAPI
BoardInit (
  IN  BOARD_INIT_PHASE  InitPhase
)
{
  UINTN                 PmcBase;
  PLT_DEVICE_TABLE      *PltDeviceTable;
  UINT8                 BoardId;
  PLAT_FEATURES         *PlatformFeatures;
   UINT32 *Buffer;

  PmcBase = MM_PCI_ADDRESS (0, PCI_DEVICE_NUMBER_PCH_PMC, PCI_FUNCTION_NUMBER_PCH_PMC, 0);

  switch (InitPhase) {
  case PreConfigInit:
DEBUG_CODE_BEGIN();
    UINT32  Data;

    Data = *(UINT32 *) (UINTN) (0xFED30328);
    DEBUG ((DEBUG_ERROR, "[Boot Guard] AcmStatus : 0x%08X\n", Data));

    Data = *(UINT32 *) (UINTN) (0xFED300A4);
    DEBUG ((DEBUG_ERROR, "[Boot Guard] BootStatus: 0x%08X\n", Data));

    if ((Data & (BIT31 | BIT30)) != BIT31) {
      DEBUG ((DEBUG_ERROR, "[Boot Guard] Boot Guard Failed or is Disabled!\n", Data));
    } else {
      DEBUG ((DEBUG_INFO, "[Boot Guard] Boot Guard is Enabled Successfully.\n", Data));
    }
DEBUG_CODE_END();

    PltDeviceTable = (PLT_DEVICE_TABLE *)AllocatePool (sizeof (PLT_DEVICE_TABLE) + sizeof (mPlatformDevices));
    if (PltDeviceTable != NULL) {
      PltDeviceTable->DeviceNumber = sizeof (mPlatformDevices) /sizeof (PLT_DEVICE);
      CopyMem (PltDeviceTable->Device, mPlatformDevices, sizeof (mPlatformDevices));
      SetDeviceTable (PltDeviceTable);
    } else {
      DEBUG ((DEBUG_ERROR, "Out of resource for PltDeviceTable\n"));
    }
    GetBoardId (&BoardId);
    if (BoardId == BoardIdTglHDdr4SODimm) {
      // SBL CFG Data PlatformId is limited to max of 0x1F, TGL-H DDR4 board is 0x21
      // need to W/A by setting the value lower
      BoardId = 0xF;
    }
    SetPlatformId (BoardId);
    SpiControllerInitialize ();
    break;
  case PostConfigInit:
    PlatformNameInit ();
    SetBootMode (IsFirmwareUpdate() ? BOOT_ON_FLASH_UPDATE : GetPlatformPowerState());
    PlatformFeaturesInit ();
    break;
  case PreMemoryInit:
    //
    // Set the DISB bit in PCH (DRAM Initialization Scratchpad Bit)
    // prior to starting DRAM Initialization Sequence.
    //
    MmioOr32 (PmcBase + R_PCH_PMC_GEN_PMCON_A, B_PCH_PMC_GEN_PMCON_A_DISB);

    switch (GetPlatformId ()) {
      case BoardIdTglHDdr4SODimm:
      case 0xF:
        GpioPadConfigTable (sizeof (mGpioTablePreMemTglHDdr4) / sizeof (mGpioTablePreMemTglHDdr4[0]), mGpioTablePreMemTglHDdr4);
        break;
      case BoardIdTglUDdr4:
      case BoardIdTglULp4Type4:
      default:
        GpioPadConfigTable (sizeof (mGpioTablePreMemTglUDdr4) / sizeof (mGpioTablePreMemTglUDdr4[0]), mGpioTablePreMemTglUDdr4);
        break;
    }

    //
    // Set WDT timeout value and start the timer.
    //
    IoWrite16 (TCO_BASE_ADDRESS+TCO_TMR_REGISTER,0x258);
    MicroSecondDelay (0x64);
    IoAnd16 (TCO_BASE_ADDRESS + TCO1_CNT_REGISTER,(UINT16)~BIT11);
    break;
  case PostMemoryInit:
    //
    // Copy TCC buffers data into memory from CAR
    //
    PlatformFeatures = &((PLATFORM_DATA *)GetPlatformDataPtr ())->PlatformFeatures;
    if ((PlatformFeatures->TccMode) && (PlatformFeatures->TccBufferBase != NULL)) {
      Buffer = (UINT32*) AllocatePool (PlatformFeatures->TccBufferSize);
      if (Buffer != NULL) {
        CopyMem (Buffer, PlatformFeatures->TccBufferBase, PlatformFeatures->TccBufferSize);
        PlatformFeatures->TccBufferBase = Buffer;
      } else {
        DEBUG ((DEBUG_ERROR, "Cannot allocate memory for TCC Buffers!\n"));
      }
    }

    //
    // Clear the DISB bit after completing DRAM Initialization Sequence
    //
    MmioAnd32 (PmcBase + R_PCH_PMC_GEN_PMCON_A, 0);

    //
    // Disable WDT
    //
    IoAnd16 (TCO_BASE_ADDRESS + TCO1_CNT_REGISTER,BIT11);
    break;
  case PreTempRamExit:
    break;
  case PostTempRamExit:
    if (MEASURED_BOOT_ENABLED()) {
      TpmInitialize();
    }
    break;
  default:
    break;
  }
}

/**
  Search for the saved MrcParam to initialize Memory for fastboot

  @retval Found MrcParam or NULL
**/
VOID *
EFIAPI
FindNvsData (
  VOID
)
{
  UINT32            MrcData;
  DYNAMIC_CFG_DATA *DynCfgData;
  EFI_STATUS        Status;

  DynCfgData = (DYNAMIC_CFG_DATA *)FindConfigDataByTag (CDATA_DYNAMIC_TAG);
  if (DynCfgData != NULL) {
    //
    // When enabled, memory training is enforced even if consistent memory parameters are available
    //
    if (DynCfgData->MrcTrainingEnforcement) {
      DEBUG ((DEBUG_INFO, "Training Enforcement enabled, hence providing NULL pointer for NVS Data!\n"));
      return NULL;
    }
  } else {
    DEBUG ((DEBUG_INFO, "Failed to find dynamic CFG!\n"));
  }

  Status = GetComponentInfo (FLASH_MAP_SIG_MRCDATA, &MrcData, NULL);
  if (EFI_ERROR(Status)) {
    return NULL;
  }

  if (*(UINT32 *)(UINTN)MrcData == 0xFFFFFFFF) {
    return NULL;
  } else {
    return (VOID *)(UINTN)MrcData;
  }
}

/**
  Load the configuration data blob from media into destination buffer.
  Currently for ICL, we support the sources: PDR, BIOS for external Cfgdata.

  @param[in]    Dst        Destination address to load configuration data blob.
  @param[in]    Src        Source address to load configuration data blob.
  @param[in]    Len        The destination address buffer size.

  @retval  EFI_SUCCESS             Configuration data blob was loaded successfully.
  @retval  EFI_NOT_FOUND           Configuration data blob cannot be found.
  @retval  EFI_OUT_OF_RESOURCES    Destination buffer is too small to hold the
                                   configuration data blob.
  @retval  Others                  Failed to load configuration data blob.

**/
EFI_STATUS
EFIAPI
LoadExternalConfigData (
  IN UINT32  Dst,
  IN UINT32  Src,
  IN UINT32  Len
  )
{

  return SpiLoadExternalConfigData (Dst, Src, Len);
}