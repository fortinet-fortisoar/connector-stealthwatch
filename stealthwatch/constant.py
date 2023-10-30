""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
api_auth = "/token/v2/authenticate"
api_application_traffic_domainid = []
api_application_traffic_domainid.append('/smc/rest/domains/')
api_application_traffic_domainid.append('/hostgroups/dashboard/')

api_all_domain = '/sw-reporting/v1/tenants'

api_application_traffic_exporterip = []
api_application_traffic_exporterip.append('/smc/rest/domains/')
api_application_traffic_exporterip.append('/exporters/')
api_application_traffic_exporterip.append('/interfaceApplicationTraffic')

api_application_traffic_hostgroupid = []
api_application_traffic_hostgroupid.append('/smc/rest/domains/')
api_application_traffic_hostgroupid.append('/hostgroups/')
api_application_traffic_hostgroupid.append('/applicationTraffic')

list_host = '/sw-reporting/v1/tenants/{tenantId}/{host_type}/tags'
threats_alarms = '/sw-reporting/v1/tenants/{tenantId}/externalThreats/tags/{tagId}/alarms/topHosts'
tenant_alarms = '/sw-reporting/v1/tenants/{tenantId}/externalThreats/alarms/topHosts'  # not working

flow_search = '/sw-reporting/v2/tenants/{tenantId}/flows/queries'
top_conversation = '/sw-reporting/v1/tenants/{tenantId}/flow-reports/top-conversations/queries'
top_conversation_result = '/sw-reporting/v1/tenants/{tenantId}/flow-reports/top-conversations/results/{queryId}'
flowanalysis = '/smc/rest/domains/{tenantId}/searches'

empty_value = [{
    "applicationId": "",
    "trafficOutboundBps": "",
    "trafficWithinBps": "",
    "applicationName": "",
    "trafficInboundBps": ""
}]

empty_data = [{"timePeriod": "",
               "applicationTrafficPerApplication": empty_value}]

PARAM_MAPPING = {
    "Custom Hosts": 'customHosts',
    "External Geos": 'externalGeos',
    "External Hosts": 'externalHosts',
    "External Threats": 'externalThreats',
    "Internal Hosts": 'internalHosts'
}
