// SPDX-License-Identifier: GPL-2.0-only
/*
 * Framework for parsing the firmware image configuration.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include <gcip/gcip-image-config.h>

static int setup_iommu_mappings(struct gcip_image_config_parser *parser,
				struct gcip_image_config *config)
{
	int i, ret;
	dma_addr_t daddr;
	size_t size;
	phys_addr_t paddr;

	for (i = 0; i < config->num_iommu_mappings; i++) {
		daddr = config->iommu_mappings[i].virt_address;
		if (unlikely(!daddr)) {
			dev_warn(parser->dev, "Invalid config, device address is zero");
			ret = -EIO;
			goto err;
		}
		size = gcip_config_to_size(config->iommu_mappings[i].image_config_value);
		paddr = config->iommu_mappings[i].image_config_value & GCIP_IMG_CFG_ADDR_MASK;

		dev_dbg(parser->dev, "Image config adding IOMMU mapping: %pad -> %pap", &daddr,
			&paddr);

		if (unlikely(daddr + size <= daddr || paddr + size <= paddr)) {
			ret = -EOVERFLOW;
			goto err;
		}
		ret = parser->ops->map(parser->data, daddr, paddr, size,
				       GCIP_IMAGE_CONFIG_FLAGS_SECURE);
		if (ret) {
			dev_err(parser->dev,
				"Unable to Map: %d dma_addr: %pad phys_addr: %pap size: %#lx\n",
				ret, &daddr, &paddr, size);
			goto err;
		}
	}

	return 0;

err:
	while (i--) {
		daddr = config->iommu_mappings[i].virt_address;
		size = gcip_config_to_size(config->iommu_mappings[i].image_config_value);
		parser->ops->unmap(parser->data, daddr, size, GCIP_IMAGE_CONFIG_FLAGS_SECURE);
	}
	return ret;
}

static void clear_iommu_mappings(struct gcip_image_config_parser *parser,
				 struct gcip_image_config *config)
{
	dma_addr_t daddr;
	size_t size;
	int i;

	for (i = config->num_iommu_mappings - 1; i >= 0; i--) {
		daddr = config->iommu_mappings[i].virt_address;
		size = gcip_config_to_size(config->iommu_mappings[i].image_config_value);
		dev_dbg(parser->dev, "Image config removing IOMMU mapping: %pad size=%#lx", &daddr,
			size);
		parser->ops->unmap(parser->data, daddr, size, GCIP_IMAGE_CONFIG_FLAGS_SECURE);
	}
}

static int setup_ns_iommu_mappings(struct gcip_image_config_parser *parser,
				   struct gcip_image_config *config)
{
	dma_addr_t daddr;
	size_t size;
	int ret, i;
	phys_addr_t paddr = 0;

	for (i = 0; i < config->num_ns_iommu_mappings; i++) {
		daddr = config->ns_iommu_mappings[i] & GCIP_IMG_CFG_ADDR_MASK;
		if (unlikely(!daddr)) {
			dev_warn(parser->dev, "Invalid config, device address is zero");
			ret = -EIO;
			goto err;
		}
		size = gcip_ns_config_to_size(config->ns_iommu_mappings[i]);
		dev_dbg(parser->dev, "Image config adding NS IOMMU mapping: %pad -> %pap", &daddr,
			&paddr);
		if (unlikely(daddr + size <= daddr || paddr + size <= paddr)) {
			ret = -EOVERFLOW;
			goto err;
		}
		ret = parser->ops->map(parser->data, daddr, paddr, size, 0);
		if (ret)
			goto err;
		paddr += size;
	}

	return 0;

err:
	while (i--) {
		size = gcip_ns_config_to_size(config->ns_iommu_mappings[i]);
		daddr = config->ns_iommu_mappings[i] & GCIP_IMG_CFG_ADDR_MASK;
		parser->ops->unmap(parser->data, daddr, size, 0);
	}
	return ret;
}

static void clear_ns_iommu_mappings(struct gcip_image_config_parser *parser,
				    struct gcip_image_config *config)
{
	dma_addr_t daddr;
	size_t size;
	int i;

	for (i = config->num_ns_iommu_mappings - 1; i >= 0; i--) {
		size = gcip_ns_config_to_size(config->ns_iommu_mappings[i]);
		daddr = config->ns_iommu_mappings[i] & GCIP_IMG_CFG_ADDR_MASK;
		dev_dbg(parser->dev, "Image config removing NS IOMMU mapping: %pad size=%#lx",
			&daddr, size);
		parser->ops->unmap(parser->data, daddr, size, 0);
	}
}

static int map_image_config(struct gcip_image_config_parser *parser,
			    struct gcip_image_config *config)
{
	int ret = setup_ns_iommu_mappings(parser, config);

	if (ret)
		return ret;
	if (gcip_image_config_is_ns(config)) {
		ret = setup_iommu_mappings(parser, config);
		if (ret)
			clear_ns_iommu_mappings(parser, config);
	}
	return ret;
}

static void unmap_image_config(struct gcip_image_config_parser *parser,
			       struct gcip_image_config *config)
{
	if (gcip_image_config_is_ns(config))
		clear_iommu_mappings(parser, config);
	clear_ns_iommu_mappings(parser, config);
}

int gcip_image_config_parser_init(struct gcip_image_config_parser *parser,
				  const struct gcip_image_config_ops *ops, struct device *dev,
				  void *data)
{
	if (!ops->map || !ops->unmap) {
		dev_err(dev, "Missing mandatory operations for image config parser");
		return -EINVAL;
	}
	parser->dev = dev;
	parser->data = data;
	parser->ops = ops;
	memset(&parser->last_config, 0, sizeof(parser->last_config));
	return 0;
}

int gcip_image_config_parse(struct gcip_image_config_parser *parser,
			    struct gcip_image_config *config)
{
	int ret;

	if (!memcmp(config, &parser->last_config, sizeof(*config)))
		return 0;
	unmap_image_config(parser, &parser->last_config);
	ret = map_image_config(parser, config);
	if (ret) {
		dev_err(parser->dev, "Map image config failed: %d", ret);
		/*
		 * Weird case as the mappings in the last config were just removed - might happen
		 * if the IOMMU driver state is corrupted. We can't help to rescue it so let's
		 * simply log a message.
		 */
		if (unlikely(map_image_config(parser, &parser->last_config)))
			dev_err(parser->dev, "Failed to roll back the last image config");
		return ret;
	}
	memcpy(&parser->last_config, config, sizeof(parser->last_config));
	return 0;
}

void gcip_image_config_clear(struct gcip_image_config_parser *parser)
{
	unmap_image_config(parser, &parser->last_config);
	memset(&parser->last_config, 0, sizeof(parser->last_config));
}
