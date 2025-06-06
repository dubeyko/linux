// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
//
// This file is provided under a dual BSD/GPLv2 license.  When using or
// redistributing this file, you may do so under either license.
//
// Copyright(c) 2018 Intel Corporation
//
// Authors: Liam Girdwood <liam.r.girdwood@linux.intel.com>
//	    Ranjani Sridharan <ranjani.sridharan@linux.intel.com>
//	    Rander Wang <rander.wang@intel.com>
//          Keyon Jie <yang.jie@linux.intel.com>
//

/*
 * Hardware interface for generic Intel audio DSP HDA IP
 */

#include <linux/module.h>
#include <sound/hdaudio_ext.h>
#include <sound/hda_register.h>
#include <sound/hda_component.h>
#include <sound/hda-mlink.h>
#include "../ops.h"
#include "hda.h"

/*
 * HDA Operations.
 */

int hda_dsp_ctrl_link_reset(struct snd_sof_dev *sdev, bool reset)
{
	unsigned long timeout;
	u32 gctl = 0;
	u32 val;

	/* 0 to enter reset and 1 to exit reset */
	val = reset ? 0 : SOF_HDA_GCTL_RESET;

	/* enter/exit HDA controller reset */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, SOF_HDA_GCTL,
				SOF_HDA_GCTL_RESET, val);

	/* wait to enter/exit reset */
	timeout = jiffies + msecs_to_jiffies(HDA_DSP_CTRL_RESET_TIMEOUT);
	while (time_before(jiffies, timeout)) {
		gctl = snd_sof_dsp_read(sdev, HDA_DSP_HDA_BAR, SOF_HDA_GCTL);
		if ((gctl & SOF_HDA_GCTL_RESET) == val)
			return 0;
		usleep_range(500, 1000);
	}

	/* enter/exit reset failed */
	dev_err(sdev->dev, "error: failed to %s HDA controller gctl 0x%x\n",
		reset ? "reset" : "ready", gctl);
	return -EIO;
}

int hda_dsp_ctrl_get_caps(struct snd_sof_dev *sdev)
{
	struct hdac_bus *bus = sof_to_bus(sdev);
	u32 cap, offset, feature;
	int count = 0;
	int ret;

	/*
	 * On some devices, one reset cycle is necessary before reading
	 * capabilities
	 */
	ret = hda_dsp_ctrl_link_reset(sdev, true);
	if (ret < 0)
		return ret;
	ret = hda_dsp_ctrl_link_reset(sdev, false);
	if (ret < 0)
		return ret;

	offset = snd_sof_dsp_read(sdev, HDA_DSP_HDA_BAR, SOF_HDA_LLCH);

	do {
		dev_dbg(sdev->dev, "checking for capabilities at offset 0x%x\n",
			offset & SOF_HDA_CAP_NEXT_MASK);

		cap = snd_sof_dsp_read(sdev, HDA_DSP_HDA_BAR, offset);

		if (cap == -1) {
			dev_dbg(bus->dev, "Invalid capability reg read\n");
			break;
		}

		feature = (cap & SOF_HDA_CAP_ID_MASK) >> SOF_HDA_CAP_ID_OFF;

		switch (feature) {
		case SOF_HDA_PP_CAP_ID:
			dev_dbg(sdev->dev, "found DSP capability at 0x%x\n",
				offset);
			bus->ppcap = bus->remap_addr + offset;
			sdev->bar[HDA_DSP_PP_BAR] = bus->ppcap;
			break;
		case SOF_HDA_SPIB_CAP_ID:
			dev_dbg(sdev->dev, "found SPIB capability at 0x%x\n",
				offset);
			bus->spbcap = bus->remap_addr + offset;
			sdev->bar[HDA_DSP_SPIB_BAR] = bus->spbcap;
			break;
		case SOF_HDA_DRSM_CAP_ID:
			dev_dbg(sdev->dev, "found DRSM capability at 0x%x\n",
				offset);
			bus->drsmcap = bus->remap_addr + offset;
			sdev->bar[HDA_DSP_DRSM_BAR] = bus->drsmcap;
			break;
		case SOF_HDA_GTS_CAP_ID:
			dev_dbg(sdev->dev, "found GTS capability at 0x%x\n",
				offset);
			bus->gtscap = bus->remap_addr + offset;
			break;
		case SOF_HDA_ML_CAP_ID:
			dev_dbg(sdev->dev, "found ML capability at 0x%x\n",
				offset);
			bus->mlcap = bus->remap_addr + offset;
			break;
		default:
			dev_dbg(sdev->dev, "found capability %d at 0x%x\n",
				feature, offset);
			break;
		}

		offset = cap & SOF_HDA_CAP_NEXT_MASK;
	} while (count++ <= SOF_HDA_MAX_CAPS && offset);

	return 0;
}
EXPORT_SYMBOL_NS(hda_dsp_ctrl_get_caps, "SND_SOC_SOF_INTEL_HDA_COMMON");

void hda_dsp_ctrl_ppcap_enable(struct snd_sof_dev *sdev, bool enable)
{
	u32 val = enable ? SOF_HDA_PPCTL_GPROCEN : 0;

	snd_sof_dsp_update_bits(sdev, HDA_DSP_PP_BAR, SOF_HDA_REG_PP_PPCTL,
				SOF_HDA_PPCTL_GPROCEN, val);
}
EXPORT_SYMBOL_NS(hda_dsp_ctrl_ppcap_enable, "SND_SOC_SOF_INTEL_HDA_COMMON");

void hda_dsp_ctrl_ppcap_int_enable(struct snd_sof_dev *sdev, bool enable)
{
	u32 val	= enable ? SOF_HDA_PPCTL_PIE : 0;

	snd_sof_dsp_update_bits(sdev, HDA_DSP_PP_BAR, SOF_HDA_REG_PP_PPCTL,
				SOF_HDA_PPCTL_PIE, val);
}
EXPORT_SYMBOL_NS(hda_dsp_ctrl_ppcap_int_enable, "SND_SOC_SOF_INTEL_HDA_COMMON");

void hda_dsp_ctrl_misc_clock_gating(struct snd_sof_dev *sdev, bool enable)
{
	u32 val = enable ? PCI_CGCTL_MISCBDCGE_MASK : 0;

	snd_sof_pci_update_bits(sdev, PCI_CGCTL, PCI_CGCTL_MISCBDCGE_MASK, val);
}

/*
 * enable/disable audio dsp clock gating and power gating bits.
 * This allows the HW to opportunistically power and clock gate
 * the audio dsp when it is idle
 */
int hda_dsp_ctrl_clock_power_gating(struct snd_sof_dev *sdev, bool enable)
{
	struct sof_intel_hda_dev *hda = sdev->pdata->hw_pdata;
	u32 val;

	/* enable/disable audio dsp clock gating */
	val = enable ? PCI_CGCTL_ADSPDCGE : 0;
	snd_sof_pci_update_bits(sdev, PCI_CGCTL, PCI_CGCTL_ADSPDCGE, val);

	/* disable the DMI link when requested. But enable only if it wasn't disabled previously */
	val = enable ? HDA_VS_INTEL_EM2_L1SEN : 0;
	if (!enable || !hda->l1_disabled)
		snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, HDA_VS_INTEL_EM2,
					HDA_VS_INTEL_EM2_L1SEN, val);

	/* enable/disable audio dsp power gating */
	val = enable ? 0 : PCI_PGCTL_ADSPPGD;
	snd_sof_pci_update_bits(sdev, PCI_PGCTL, PCI_PGCTL_ADSPPGD, val);

	return 0;
}
EXPORT_SYMBOL_NS(hda_dsp_ctrl_clock_power_gating, "SND_SOC_SOF_INTEL_HDA_COMMON");

int hda_dsp_ctrl_init_chip(struct snd_sof_dev *sdev)
{
	struct hdac_bus *bus = sof_to_bus(sdev);
	struct hdac_stream *stream;
	int sd_offset, ret = 0;
	u32 gctl;

	if (bus->chip_init)
		return 0;

	hda_codec_set_codec_wakeup(sdev, true);

	hda_dsp_ctrl_misc_clock_gating(sdev, false);

	/* clear WAKE_STS if not in reset */
	gctl = snd_sof_dsp_read(sdev, HDA_DSP_HDA_BAR, SOF_HDA_GCTL);
	if (gctl & SOF_HDA_GCTL_RESET)
		snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR,
				  SOF_HDA_WAKESTS, SOF_HDA_WAKESTS_INT_MASK);

	/* reset HDA controller */
	ret = hda_dsp_ctrl_link_reset(sdev, true);
	if (ret < 0) {
		dev_err(sdev->dev, "error: failed to reset HDA controller\n");
		goto err;
	}

	usleep_range(500, 1000);

	/* exit HDA controller reset */
	ret = hda_dsp_ctrl_link_reset(sdev, false);
	if (ret < 0) {
		dev_err(sdev->dev, "error: failed to exit HDA controller reset\n");
		goto err;
	}
	usleep_range(1000, 1200);

	hda_codec_detect_mask(sdev);

	/* clear stream status */
	list_for_each_entry(stream, &bus->stream_list, list) {
		sd_offset = SOF_STREAM_SD_OFFSET(stream);
		snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR,
				  sd_offset + SOF_HDA_ADSP_REG_SD_STS,
				  SOF_HDA_CL_DMA_SD_INT_MASK);
	}

	/* clear WAKESTS */
	snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR, SOF_HDA_WAKESTS,
			  bus->codec_mask);

	hda_codec_rirb_status_clear(sdev);

	/* clear interrupt status register */
	snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR, SOF_HDA_INTSTS,
			  SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_ALL_STREAM);

	hda_codec_init_cmd_io(sdev);

	/* enable CIE and GIE interrupts */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, SOF_HDA_INTCTL,
				SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_GLOBAL_EN,
				SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_GLOBAL_EN);

	/* program the position buffer */
	if (bus->use_posbuf && bus->posbuf.addr) {
		snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR, SOF_HDA_ADSP_DPLBASE,
				  (u32)bus->posbuf.addr);
		snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR, SOF_HDA_ADSP_DPUBASE,
				  upper_32_bits(bus->posbuf.addr));
	}

	hda_bus_ml_reset_losidv(bus);

	bus->chip_init = true;

err:
	hda_dsp_ctrl_misc_clock_gating(sdev, true);

	hda_codec_set_codec_wakeup(sdev, false);

	return ret;
}
EXPORT_SYMBOL_NS(hda_dsp_ctrl_init_chip, "SND_SOC_SOF_INTEL_HDA_COMMON");

void hda_dsp_ctrl_stop_chip(struct snd_sof_dev *sdev)
{
	struct hdac_bus *bus = sof_to_bus(sdev);
	struct hdac_stream *stream;
	int sd_offset;

	if (!bus->chip_init)
		return;

	/* disable interrupts in stream descriptor */
	list_for_each_entry(stream, &bus->stream_list, list) {
		sd_offset = SOF_STREAM_SD_OFFSET(stream);
		snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR,
					sd_offset +
					SOF_HDA_ADSP_REG_SD_CTL,
					SOF_HDA_CL_DMA_SD_INT_MASK,
					0);
	}

	/* disable SIE for all streams */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, SOF_HDA_INTCTL,
				SOF_HDA_INT_ALL_STREAM,	0);

	/* disable controller CIE and GIE */
	snd_sof_dsp_update_bits(sdev, HDA_DSP_HDA_BAR, SOF_HDA_INTCTL,
				SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_GLOBAL_EN,
				0);

	/* clear stream status */
	list_for_each_entry(stream, &bus->stream_list, list) {
		sd_offset = SOF_STREAM_SD_OFFSET(stream);
		snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR,
				  sd_offset + SOF_HDA_ADSP_REG_SD_STS,
				  SOF_HDA_CL_DMA_SD_INT_MASK);
	}

	/* clear WAKESTS */
	snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR, SOF_HDA_WAKESTS,
			  SOF_HDA_WAKESTS_INT_MASK);

	hda_codec_rirb_status_clear(sdev);

	/* clear interrupt status register */
	snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR, SOF_HDA_INTSTS,
			  SOF_HDA_INT_CTRL_EN | SOF_HDA_INT_ALL_STREAM);

	hda_codec_stop_cmd_io(sdev);

	/* disable position buffer */
	if (bus->use_posbuf && bus->posbuf.addr) {
		snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR,
				  SOF_HDA_ADSP_DPLBASE, 0);
		snd_sof_dsp_write(sdev, HDA_DSP_HDA_BAR,
				  SOF_HDA_ADSP_DPUBASE, 0);
	}

	bus->chip_init = false;
}

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("SOF helpers for HDaudio platforms");
MODULE_IMPORT_NS("SND_SOC_SOF_HDA_MLINK");
MODULE_IMPORT_NS("SND_SOC_SOF_HDA_AUDIO_CODEC");
MODULE_IMPORT_NS("SND_SOC_SOF_HDA_AUDIO_CODEC_I915");
