/*
 * Copyright(c) 2019 Lockheed Martin Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and 
 * to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of 
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 */

#include <config.h>

#include "sre_domain.h"

#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include <libxml/xpathInternals.h>
#include "virstring.h"
#include "virutil.h"
#include "virfile.h"
#include "virtime.h"
#include "virsystemd.h"

#define VIR_FROM_THIS VIR_FROM_SRE

VIR_LOG_INIT("sre.sre_domain");

typedef char sre_message_t;

#define SRE_CONTINUE_MSG 's'

/**
 * sreWaitForContinue:
 * @control: Control FD from parent
 *
 * This function will wait for the container continue message from the
 * parent process.  It will send this message on the socket pair stored in
 * the vm structure once it has completed the post clone container setup.
 *
 * Returns 0 on success or -1 in case of error
 */

/* messages between parent and container */

int
sreWaitForContinue(int control)
{
    sre_message_t msg;
    int readLen;

    readLen = saferead(control, &msg, sizeof(msg));
    if (readLen != sizeof(msg)) {
        if (readLen >= 0)
            errno = EIO;
        return -1;
    }
    if (msg != SRE_CONTINUE_MSG) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int
sreSendContinue(int control)
{
    int rc = -1;
    sre_message_t msg = SRE_CONTINUE_MSG;
    int writeCount = 0;

    writeCount = safewrite(control, &msg, sizeof(msg));
    if (writeCount != sizeof(msg))
        goto error_out;

    rc = 0;
  error_out:
    return rc;
}

static void
sreDomainDefNamespaceFree(void *data)
{
    sreDomainNamespaceDefPtr nsdata = data;
    size_t i;
    char *buffer_str = NULL;

    if (!nsdata)
        return;

    for (i = 0; i < nsdata->portal_count; i++) {
        VIR_FREE(nsdata->portal_info[i].name);
        VIR_FREE(nsdata->portal_info[i].unit);
    }

    buffer_str = virBufferContentAndReset(&nsdata->data);
    if (buffer_str)
        VIR_FREE(buffer_str);

    VIR_FREE(nsdata);
}

static const char *
sreDomainDefNamespaceHref(void)
{
    return "xmlns:sre='" SRE_NAMESPACE_HREF "'";
}

static int
sreDomainDefNamespaceParse(xmlDocPtr xml,
                           xmlNodePtr root,
                           xmlXPathContextPtr ctxt, void **data)
{
    xmlNodePtr *nodes = NULL;
    sreDomainNamespaceDefPtr nsdata = NULL;

    (void) root;
    xmlXPathContextPtr temp_ctxt = NULL;

    temp_ctxt = xmlXPathNewContext(xml);
    temp_ctxt->node = xmlDocGetRootElement(xml);
    int n = 0;
    virBuffer buff = VIR_BUFFER_INITIALIZER;
    char *temp = NULL;

#ifdef VUB_SUPPORT
    char *temp_extra = NULL;
#endif
    unsigned int temp_num = 0;
    char *tempNodeVal;
    char *buff_str = NULL;

    if (xmlXPathRegisterNs(ctxt, BAD_CAST "sre",
                           BAD_CAST SRE_NAMESPACE_HREF) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to register xml namespace '%s'"),
                       SRE_NAMESPACE_HREF);
        goto error;
    }

    if (xmlXPathRegisterNs(temp_ctxt, BAD_CAST "sre",
                           BAD_CAST SRE_NAMESPACE_HREF) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to register xml namespace '%s'"),
                       SRE_NAMESPACE_HREF);
        goto error;
    }

    if (VIR_ALLOC(nsdata) < 0)
        goto error;

    ctxt->node = xmlDocGetRootElement(xml);
    //parse extended cpu feature actions
    if ((n = virXPathNodeSet("//sre:policy/*", ctxt, &nodes)) <= 0) {
        VIR_DEBUG("no policy elements %d", n);
    }

    for (int i = 0; i < n; i++) {
        if (STREQ((char *) nodes[i]->name, "ostype")) {
            tempNodeVal =
                virXPathString("string(./sre:policy/sre:ostype)", ctxt);

            virBufferAsprintf(&buff, "<sre:ostype>%s</sre:ostype>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);
        }

        if (strcmp((char *) nodes[i]->name, "paging") == 0) {
            tempNodeVal =
                virXPathString("string(./sre:policy/sre:paging)", ctxt);
            virBufferAsprintf(&buff, "<sre:paging>%s</sre:paging>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);
        }
        //optional provided header info
        if (STREQ((char *) nodes[i]->name, "ph_domain_info")) {
            tempNodeVal =
                virXPathString("string(./sre:policy/sre:ph_domain_info)",
                               ctxt);
            virBufferAsprintf(&buff,
                              "<sre:ph_domain_info>%s</sre:ph_domain_info>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);
        }

        if (STREQ((char *) nodes[i]->name, "ph_domain_sha")) {
            tempNodeVal =
                virXPathString("string(./sre:policy/sre:ph_domain_sha)",
                               ctxt);
            virBufferAsprintf(&buff,
                              "<sre:ph_domain_sha>%s</sre:ph_domain_sha>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);
        }

        if (STREQ((char *) nodes[i]->name, "ph_domain_sig")) {
            tempNodeVal =
                virXPathString("string(./sre:policy/sre:ph_domain_sig)",
                               ctxt);
            virBufferAsprintf(&buff,
                              "<sre:ph_domain_sig>%s</sre:ph_domain_sig>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);
        }

        if (STREQ((char *) nodes[i]->name, "domainSalt")) {
            tempNodeVal =
                virXPathString("string(./sre:policy/sre:domainSalt)",
                               ctxt);
            virBufferAsprintf(&buff,
                              "<sre:domainSalt>%s</sre:domainSalt>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);
        }

        if (strcmp((char *) nodes[i]->name, "secure") == 0) {
            tempNodeVal =
                virXPathString("string(./sre:policy/sre:secure)", ctxt);
            virBufferAsprintf(&buff, "<sre:secure>%s</sre:secure>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);
        }

        temp_num = 0;
        if (strcmp((char *) nodes[i]->name, "cacheWays") == 0) {
            virXPathUInt("string(./sre:policy/sre:cacheWays)", ctxt,
                         &temp_num);
            virBufferAsprintf(&buff, "<sre:cacheWays>%u</sre:cacheWays>\n",
                              temp_num);
        }

        temp_num = 0;
        if (strcmp((char *) nodes[i]->name, "dmaSize") == 0) {
            temp = virXMLPropString(nodes[i], "unit");
            virXPathUInt("string(./sre:policy/sre:dmaSize)", ctxt,
                         &temp_num);
            virBufferAsprintf(&buff,
                              "<sre:dmaSize unit='%s'>%u</sre:dmaSize>\n",
                              temp, temp_num);
            VIR_FREE(temp);
        }

        temp_num = 0;
        if (strcmp((char *) nodes[i]->name, "hashPageThreshold") == 0) {
            temp = virXMLPropString(nodes[i], "unit");
            virXPathUInt("string(./sre:policy/sre:hashPageThreshold)",
                         ctxt, &temp_num);
            virBufferAsprintf(&buff,
                              "<sre:hashPageThreshold unit='%s'>%u</sre:hashPageThreshold>\n",
                              temp, temp_num);
            VIR_FREE(temp);
        }

        if (strcmp((char *) nodes[i]->name, "devicePolicy") == 0) {
            xmlBufferPtr test = NULL;

            if (VIR_ALLOC(test) < 0)
                goto error;

            temp = virXMLPropString(nodes[i], "action");
            if (xmlNodeBufGetContent(test, nodes[i])) {
                VIR_WARN("error getting node value");
                goto error;
            }


            virBufferAsprintf(&buff,
                              "<sre:devicePolicy action='%s'>%s</sre:devicePolicy>\n",
                              temp, test->content);
            VIR_FREE(temp);
            VIR_FREE(test->content);
            VIR_FREE(test);
        }

        if (strcmp((char *) nodes[i]->name, "featurePolicy") == 0) {
            xmlBufferPtr test = NULL;

            if (VIR_ALLOC(test) < 0)
                goto error;

            temp = virXMLPropString(nodes[i], "action");
            if (xmlNodeBufGetContent(test, nodes[i])) {
                VIR_WARN("error getting node value");
                goto error;
            }
            virBufferAsprintf(&buff,
                              "<sre:featurePolicy action='%s'>%s</sre:featurePolicy>\n",
                              temp, test->content);
            VIR_FREE(temp);
            VIR_FREE(test->content);
            VIR_FREE(test);
        }

        if (strcmp((char *) nodes[i]->name, "exception") == 0) {
            xmlBufferPtr test = NULL;

            if (VIR_ALLOC(test) < 0) {
                goto error;
            }

            temp = virXMLPropString(nodes[i], "action");
            if (xmlNodeBufGetContent(test, nodes[i])) {
                VIR_WARN("error getting node value");
                goto error;

            }
            virBufferAsprintf(&buff,
                              "<sre:exception action='%s'>%s</sre:exception>\n",
                              temp, test->content);
            VIR_FREE(temp);
            VIR_FREE(test->content);
            VIR_FREE(test);
        }
        if (strcmp((char *) nodes[i]->name, "console") == 0) {
            xmlBufferPtr test = NULL;

            if (VIR_ALLOC(test) < 0) {
                goto error;
            }

            temp = virXMLPropString(nodes[i], "action");
            if (xmlNodeBufGetContent(test, nodes[i])) {
                VIR_WARN("error getting node value");
                goto error;
            }
            virBufferAsprintf(&buff,
                              "<sre:console action='%s'>%s</sre:console>\n",
                              temp, test->content);
            VIR_FREE(temp);
            VIR_FREE(test->content);
            VIR_FREE(test);
        }

        if (strcmp((char *) nodes[i]->name, "serial") == 0) {
            xmlBufferPtr test = NULL;

            if (VIR_ALLOC(test) < 0)
                goto error;

            temp = virXMLPropString(nodes[i], "action");
#ifdef VUB_SUPPORT
            temp_extra = virXMLPropString(nodes[i], "port_id");
#endif
            if (xmlNodeBufGetContent(test, nodes[i])) {
                VIR_WARN("error getting node value");
                goto error;

            }
#ifdef VUB_SUPPORT
            if (temp_extra) {
                if (nsdata->vub_count == MAX_NUM_SERIAL_PORTS) {
                    goto error;
                }
                if (virStrToLong_i
                    (temp_extra, NULL, 10,
                     &nsdata->vub_info[nsdata->vub_count].vub_channel)) {
                    VIR_ERROR("Error getting vub channel value");
                }
                if (virStrToLong_i
                    ((char *) test->content, NULL, 10,
                     &nsdata->vub_info[nsdata->vub_count].vub_portval)) {
                    VIR_ERROR("Error getting vub port value");
                }
                virBufferAsprintf(&buff,
                                  "<sre:serial action='%s' port_id='%s'>%s</sre:serial>\n",
                                  temp, temp_extra, test->content);
                nsdata->vub_count++;
            } else {
                VIR_DEBUG("no vub port option");
#endif
                virBufferAsprintf(&buff,
                                  "<sre:serial action='%s' >%s</sre:serial>\n",
                                  temp, test->content);
#ifdef VUB_SUPPORT
            }

            VIR_FREE(temp_extra);
#endif
            VIR_FREE(temp);
            VIR_FREE(test->content);
            VIR_FREE(test);
        }

        if (strcmp((char *) nodes[i]->name, "hostdev") == 0) {
            char *type = NULL, *start = NULL;

            type = virXMLPropString(nodes[i], "type");
            start = virXMLPropString(nodes[i], "startupPolicy");
            virBufferAsprintf(&buff,
                              "<sre:hostdev type='%s' startupPolicy='%s'>\n",
                              type, start);
            virBufferAdjustIndent(&buff, 2);
            temp_ctxt->node = nodes[i];

            char *domain = NULL, *bus = NULL, *slot = NULL, *function =
                NULL;
            xmlNodePtr *addr_node;

            virXPathNodeSet("./sre:address", temp_ctxt, &addr_node);
            domain = virXMLPropString(addr_node[0], "domain");
            bus = virXMLPropString(addr_node[0], "bus");
            slot = virXMLPropString(addr_node[0], "slot");
            function = virXMLPropString(addr_node[0], "function");
            virBufferAsprintf(&buff,
                              "<sre:address domain='%s' bus='%s' slot='%s' function='%s'/>\n",
                              domain, bus, slot, function);
            VIR_FREE(type);
            VIR_FREE(start);
            VIR_FREE(domain);
            VIR_FREE(bus);
            VIR_FREE(slot);
            VIR_FREE(function);
            VIR_FREE(addr_node);

            tempNodeVal =
                virXPathString("string(./sre:vendor)", temp_ctxt);
            virBufferAsprintf(&buff, "<sre:vendor>%s</sre:vendor>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);

            tempNodeVal =
                virXPathString("string(./sre:device)", temp_ctxt);
            virBufferAsprintf(&buff, "<sre:device>%s</sre:device>\n",
                              tempNodeVal);
            VIR_FREE(tempNodeVal);


            if ((tempNodeVal =
                 virXPathString("string(./sre:class)",
                                temp_ctxt)) != NULL) {
                virBufferAsprintf(&buff, "<sre:class>%s</sre:class>\n",
                                  tempNodeVal);
                VIR_FREE(tempNodeVal);
            }

            if ((tempNodeVal =
                 virXPathString("string(./sre:function)",
                                temp_ctxt)) != NULL) {
                virBufferAsprintf(&buff,
                                  "<sre:function>%s</sre:function>\n",
                                  tempNodeVal);
                VIR_FREE(tempNodeVal);
            }

            if ((tempNodeVal =
                 virXPathString("string(./sre:targetVendor)",
                                temp_ctxt)) != NULL) {
                virBufferAsprintf(&buff,
                                  "<sre:targetVendor>%s</sre:targetVendor>\n",
                                  tempNodeVal);
                VIR_FREE(tempNodeVal);
            }

            if ((tempNodeVal =
                 virXPathString("string(./sre:targetDevice)",
                                temp_ctxt)) != NULL) {
                virBufferAsprintf(&buff,
                                  "<sre:targetDevice>%s</sre:targetDevice>\n",
                                  tempNodeVal);
                VIR_FREE(tempNodeVal);
            }

            if ((tempNodeVal =
                 virXPathString("string(./sre:dmaBlocked)",
                                temp_ctxt)) != NULL) {
                virBufferAsprintf(&buff,
                                  "<sre:dmaBlocked>%s</sre:dmaBlocked>\n",
                                  tempNodeVal);
                VIR_FREE(tempNodeVal);
            }

            if ((tempNodeVal =
                 virXPathString("string(./sre:instance)",
                                temp_ctxt)) != NULL) {
                virBufferAsprintf(&buff,
                                  "<sre:instance>%s</sre:instance>\n",
                                  tempNodeVal);
                VIR_FREE(tempNodeVal);
            }

            virBufferAdjustIndent(&buff, -2);
            virBufferAddLit(&buff, "</sre:hostdev>\n");
        }

        if (strcmp((char *) nodes[i]->name, "ioPort") == 0) {
            xmlBufferPtr test = NULL;

            if (VIR_ALLOC(test) < 0)
                goto error;

            temp = virXMLPropString(nodes[i], "action");
            if (xmlNodeBufGetContent(test, nodes[i])) {
                VIR_WARN("error getting node value");
            }
            virBufferAsprintf(&buff,
                              "<sre:ioPort action='%s'>%s</sre:ioPort>\n",
                              temp, test->content);
            VIR_FREE(temp);
            VIR_FREE(test->content);
            VIR_FREE(test);
        }
        if (strcmp((char *) nodes[i]->name, "portal") == 0
            && nsdata->portal_count < MAX_VNIC) {
            char *channel, *ifchannel;
            xmlBufferPtr value = NULL;

            if (VIR_ALLOC(value) < 0)
                goto error;
            nsdata->portal_info[nsdata->portal_count].unit =
                virXMLPropString(nodes[i], "unit");
            nsdata->portal_info[nsdata->portal_count].name =
                virXMLPropString(nodes[i], "name");
            channel = virXMLPropString(nodes[i], "channel");
            ifchannel = virXMLPropString(nodes[i], "ifchannel");        //this is optional

            if (xmlNodeBufGetContent(value, nodes[i])) {
                VIR_WARN("Error getting node value");
            }

            if (value->content && virStrToLong_ui
                ((const char *) value->content, NULL, 10,
                 &nsdata->portal_info[nsdata->portal_count].size)) {
                VIR_ERROR("Error getting portal size value");
            }

            if (channel && virStrToLong_i
                (channel, NULL, 10,
                 &nsdata->portal_info[nsdata->portal_count].
                 portal_channel)) {
                VIR_ERROR("Error getting portal channel value");
            }
            if (ifchannel) {
                if (virStrToLong_i
                    (ifchannel, NULL, 10,
                     &nsdata->portal_info[nsdata->portal_count].
                     portal_interface_id)) {
                    VIR_ERROR("Error getting portal ifchannel value");
                }
                VIR_FREE(ifchannel);
            }
            nsdata->portal_count++;
            if (value) {
                VIR_FREE(value->content);
                VIR_FREE(value);
            }
            VIR_FREE(channel);
        }
    }
    buff_str = virBufferContentAndReset(&buff);
    if (buff_str) {
        virBufferAddStr(&(nsdata->data), buff_str);
        VIR_FREE(buff_str);
    }
    xmlXPathFreeContext(temp_ctxt);
    VIR_FREE(nodes);

    *data = nsdata;
    return 0;

  error:
    VIR_FREE(nodes);
    buff_str = virBufferContentAndReset(&buff);
    if (buff_str)
        VIR_FREE(buff_str);
    sreDomainDefNamespaceFree(nsdata);
    xmlXPathFreeContext(temp_ctxt);
    return -1;
}

static int
sreDomainDefNamespaceFormatXML(virBufferPtr buf, void *nsdata)
{
    sreDomainNamespaceDefPtr name_space_data = nsdata;
    int i = 0;

    virBufferAddLit(buf, "<sre:policy>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferAddStr(buf, virBufferCurrentContent(&name_space_data->data));
    for (i = 0; i < name_space_data->portal_count; i++) {
        portal_policy_info_t portal_policy =
            name_space_data->portal_info[i];
        if (portal_policy.portal_channel > 0) {
            virBufferAsprintf(buf,
                              "<sre:portal name='%s' channel='%d' unit='%s' >%d</sre:portal>\n",
                              portal_policy.name,
                              portal_policy.portal_channel,
                              portal_policy.unit, portal_policy.size);
        } else if (portal_policy.portal_channel == -1) {
            virBufferAsprintf(buf,
                              "<sre:portal name='%s' channel='%d' ifchannel='%d' unit='%s' >%d</sre:portal>\n",
                              portal_policy.name,
                              portal_policy.portal_channel,
                              portal_policy.portal_interface_id,
                              portal_policy.unit, portal_policy.size);
        } else {
            VIR_ERROR("portal channel should not be greater than zero");
        }
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</sre:policy>\n");

    return 0;
}

virDomainXMLNamespace virSREDriverDomainXMLNamespace = {
    .parse = sreDomainDefNamespaceParse,
    .free = sreDomainDefNamespaceFree,
    .format = sreDomainDefNamespaceFormatXML,
    .href = sreDomainDefNamespaceHref,
};

//per vm private data callbacks
static int
virSREDomainObjInitJob(virSREDomainObjPrivatePtr priv)
{
    memset(&priv->job, 0, sizeof(priv->job));

    if (virCondInit(&priv->job.cond) < 0)
        return -1;

    return 0;
}

static void
virSREDomainObjFreeJob(virSREDomainObjPrivatePtr priv)
{
    ignore_value(virCondDestroy(&priv->job.cond));
}

static void *
virSREDomainObjPrivateAlloc(void *opaque ATTRIBUTE_UNUSED)
{
    virSREDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    if (virSREDomainObjInitJob(priv) < 0) {
        VIR_FREE(priv);
        return NULL;
    }

    return priv;
}


static void
virSREDomainObjPrivateFree(void *data)
{
    virSREDomainObjPrivatePtr priv = data;

    virSREDomainObjFreeJob(priv);
    VIR_FREE(priv);
}

static int
virSREDomainObjPrivateXMLFormat(virBufferPtr buf, virDomainObjPtr vm)
{
    virSREDomainObjPrivatePtr priv = vm->privateData;

    virBufferAsprintf(buf, "<init pid='%lld'/>\n",
                      (long long) priv->initpid);

    return 0;
}

static int
virSREDomainObjPrivateXMLParse(xmlXPathContextPtr ctxt,
                               virDomainObjPtr vm,
                               virDomainDefParserConfigPtr config
                               ATTRIBUTE_UNUSED)
{
    virSREDomainObjPrivatePtr priv = vm->privateData;
    long long thepid;

    if (virXPathLongLong("string(./init[1]/@pid)", ctxt, &thepid) < 0) {
        VIR_WARN("Failed to load init pid from state %s",
                 virGetLastErrorMessage());
        priv->initpid = 0;
    } else {
        priv->initpid = thepid;
    }

    return 0;
}

virDomainXMLPrivateDataCallbacks virSREDriverPrivateDataCallbacks = {
    .alloc = virSREDomainObjPrivateAlloc,
    .free = virSREDomainObjPrivateFree,
    .format = virSREDomainObjPrivateXMLFormat,
    .parse = virSREDomainObjPrivateXMLParse,
};
