""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json, arrow
import requests
from requests import request, exceptions as req_exceptions
from datetime import datetime
from connectors.core.connector import Connector, get_logger, ConnectorError
from .constant import *

logger = get_logger('stealthwatch')


def validate_json(host_filters):
    try:
        temp = {}
        for k, v in host_filters.items():
            sub_dict = {}
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    if not sub_v == []:
                        sub_dict[sub_k] = sub_v
                temp[k] = sub_dict
            elif isinstance(v, list):
                sub_dict = {}
                sub_list = []
                for i in range(len(v)):
                    temp_dict = v[i]
                    try:
                        for sub_k, sub_v in temp_dict.items():
                            if sub_v != "":
                                sub_dict[sub_k] = sub_v
                                sub_list.append(sub_dict)
                        temp[k] = sub_list
                    except:
                        temp[k] = v
            else:
                temp[k] = v
        return temp
    except Exception as err:
        logger.error("validate_json: {0}".format(err))
        raise ConnectorError("validate_json: {0}".format(err))


def handle_datetime(value, flag=False):
    try:
        if not flag:
            date = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%dT%H:%M:%S')
        else:
            date = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%dT%H:%M:%SZ')
        return date
    except Exception as err:
        logger.error("handle_datetime: {0}".format(err))
        raise ConnectorError("handle_datetime: {0}".format(err))


def check_health(config):
    logger.info("Invoking check_health")
    try:
        server_url, username, password, verify_ssl = get_config_params(config)
        cookie = get_token(server_url, username, password, verify_ssl)
        if cookie:
            return True
    except Exception as Err:
        logger.exception("Invalid URL or Credentials. {0}".format(str(Err)))
        raise ConnectorError(Err)


def get_config_params(config):
    server_url = config.get("server_url", None).strip('/')
    if server_url[:7] != 'http://' and server_url[:8] != 'https://':
        server_url = 'https://{0}'.format(server_url)
    username = config.get('username', None)
    password = config.get('password', None)
    verify_ssl = config.get("verify_ssl", False)
    return server_url, username, password, verify_ssl


def parse_output(result):
    try:
        for list_data in result:
            if list_data["applicationTrafficPerApplication"] == []:
                list_data["applicationTrafficPerApplication"] = empty_value
        return result
    except Exception as Err:
        logger.exception("Fail: {0}".format(Err))
        raise ConnectorError(Err)


def make_rest_call(config, endpoint='', method="GET", params=None, data=None, body=None, flag=False):
    """Common handler for all HTmake_rest_callTP requests."""
    try:
        server_url, username, password, verify_ssl = get_config_params(config)
        cookies = get_token(server_url, username, password, verify_ssl)
        url = server_url + endpoint
        headers = {'Cookie': cookies[0],
                   'X-XSRF-TOKEN': cookies[1]
                  }
        logger.info('Making API call with url {0}'.format(url))
        response = request(method=method, url=url, headers=headers, data=data, json=body, params=params,
                           verify=verify_ssl)
        if flag:  # will not disturb the previous implementation
            if response.ok:
                if len(response.content) != 2:
                    return parse_output(json.loads(str(response.content.decode('utf-8'))))
                else:
                    return empty_data
            else:
                res_json = json.loads(response.content.decode('utf-8'))
                raise ConnectorError(
                    'Fail Error Code: {0}, Status Code: {1}, Error Massage: {2}'.format(res_json.get("errorCode"),
                                                                                        res_json.get("statusCode"),
                                                                                        res_json.get("exception",
                                                                                                     {}).get(
                                                                                            "message")))
        else:
            if response.status_code != 200 and response.status_code != 201:
                try:
                    res_json = json.loads(response.content.decode('utf-8'))
                except Exception as e:
                    logger.exception('Exception : {0} '.format(e))
                    raise ConnectorError('Response not in JSON format.\n{0}'.format(response.text))
                raise ConnectorError(res_json)
            try:
                return response.json()
            except Exception as e:
                logger.error(e)
                raise ConnectorError(e)
    except req_exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except req_exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except req_exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except req_exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)


def get_token(server_url, username, password, verify_ssl):
    logger.info("Generating Token")
    try:
        params = {
            "username": username,
            "password": password
        }
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        url = server_url + api_auth
        api_response = requests.post(url, data=params, headers=headers, verify=verify_ssl)
        if api_response.ok:
            logger.debug('Cookies: {0}'.format(str(api_response.cookies)))
            cookies = api_response.cookies['stealthwatch.jwt']
            cookies = 'stealthwatch.jwt=' + cookies
            xsrfCookies = api_response.cookies['XSRF-TOKEN']
            return [ cookies, xsrfCookies ]
        else:
            logger.error(
                'Error to request url: {url} {text} with reason: {reason}'.format(url=url, text=api_response.text,
                                                                                  reason=api_response.reason))
            raise ConnectorError('Invalid URL or Credentials.')
    except req_exceptions.SSLError as e:
        logger.error('An SSL error occurred: {}'.format(e))
        raise ConnectorError('An SSL error occurred')
    except requests.exceptions.ConnectionError as e:
        status_code = "Invalid endpoint: {}".format(e)
        raise ConnectorError(status_code)
    except Exception as Err:
        logger.exception("Cookies generation fail: {0}".format(str(Err)))
        raise ConnectorError(Err)


def get_domain_details(config, params, **kwargs):
    try:
        res = make_rest_call(config, api_all_domain)
        return res
    except Exception as Err:
        logger.exception("{0}".format(str(Err)))
        raise ConnectorError(Err)


def application_traffic_domainid(config, params, **kwargs):
    try:
        domain_id = params.get('domain_id')
        remove_keys(params, ['domain_id'])
        query_params = build_payload(params)
        url = str(api_application_traffic_domainid[0]) + str(domain_id) + str(
            api_application_traffic_domainid[1])
        api_response = make_rest_call(config, endpoint=url, params=query_params, flag=True)
        return api_response
    except Exception as Err:
        if '404' in str(Err):
            logger.exception('Domain ID not found')
            raise ConnectorError('Domain ID not found')
        logger.exception('{0}'.format(str(Err)))
        raise ConnectorError(Err)


def application_traffic_ip(config, params, **kwargs):
    try:
        exporter_ip = params.get('exporterip')
        flow_collector_device_id = params.get('flowcollectordeviceid')
        interface = params.get('interface')
        domain_id = params.get('domain_id')
        start = params.get('start', None)
        end = params.get('end', None)
        query_params = {}
        if start:
            query_params.update({'start': start})
        if end:
            query_params.update({'end': end})
        url = str(api_application_traffic_exporterip[0]) + str(domain_id) + str(
            api_application_traffic_exporterip[1]) + str(flow_collector_device_id) + '/' + str(exporter_ip) + '/' + str(
            interface) + str(api_application_traffic_exporterip[2])
        api_response = make_rest_call(config, endpoint=url, params=query_params, flag=True)
        return api_response
    except Exception as Err:
        logger.exception("Fail, {0}".format(str(Err)))
        raise ConnectorError(Err)


def application_traffic_hostgroupid(config, params, **kwargs):
    try:
        domain_id = params.get('domain_id')
        host_grou_pid = params.get('hostgroupid')
        remove_keys(params, ['domain_id', 'hostgroupid'])
        url = str(api_application_traffic_hostgroupid[0]) + str(domain_id) + str(
            api_application_traffic_hostgroupid[1]) + str(host_grou_pid) + str(api_application_traffic_hostgroupid[2])
        query_params = build_payload(params)
        api_response = make_rest_call(config, endpoint=url, params=query_params, flag=True)
        return api_response
    except Exception as Err:
        logger.exception("{0}".format(str(Err)))
        raise ConnectorError(Err)


def initiate_flow_search(config, params, **kwargs):
    try:
        tenant_id = params.get("tenant_id")
        remove_keys(params, ['tenant_id'])
        payload = build_payload(params)
        endpoint = flow_search.format(tenantId=tenant_id)
        return make_rest_call(config, endpoint, method="POST", body=payload)
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_flow_search_status(config, params, **kwargs):
    try:
        endpoint = flow_search.format(tenantId=params.get("tenant_id"))
        endpoint += '/' + params.get("query_id")
        return make_rest_call(config, endpoint)
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_flow_search_results(config, params, **kwargs):
    try:
        endpoint = flow_search.format(tenantId=params.get("tenant_id"))
        endpoint += "/{query_id}/results".format(query_id=params.get("query_id"))
        return make_rest_call(config, endpoint)
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def list_host_groups(config, params, **kwargs):
    try:
        tenant_id = params.get("tenant_id")
        host_type = PARAM_MAPPING.get(params.get("host_type"))
        hierarchy_view = params.get("hierarchy_view")
        endpoint = list_host.format(tenantId=tenant_id, host_type=host_type)
        if hierarchy_view:
            endpoint += '/tree'
        res = make_rest_call(config, endpoint)
        return res
    except Exception as Err:
        logger.exception("{0}".format(str(Err)))
        raise ConnectorError(Err)


def get_host_details(config, params, **kwargs):
    try:
        tenant_id = params.get("tenant_id")
        host_type = PARAM_MAPPING.get(params.get("host_type"))
        host_group_id = params.get("hostGroupId")
        endpoint = list_host.format(tenantId=tenant_id, host_type=host_type) + '/{id}'.format(id=host_group_id)
        res = make_rest_call(config, endpoint)
        return res
    except Exception as Err:
        logger.exception("{}".format(str(Err)))
        raise ConnectorError(Err)


def convert_date(k, v):
    try:
        format_date = {
            'start': arrow.get(v).format("YYYY-MM-DDThh:mm:ss.SSS+0000"),
            'end': arrow.get(v).format("YYYY-MM-DDThh:mm:ss.SSS+0000"),
            'startDateTime': handle_datetime(v, True),
            'endDateTime': handle_datetime(v, True),
            'startTime': v.strip('Z'),
            'endTime': v.strip('Z')
        }
        return format_date.get(k)
    except Exception as e:
        logger.error(e)
        raise ConnectorError(e)


def build_payload(params):
    query = {}
    date_params = ["startTime", 'endTime', 'startDateTime', 'endDateTime', 'start', 'end']
    validate_json_params = ['subject', 'peer', 'flow', 'connection']
    list_value = ['flowCollectors']
    for k, v in params.items():
        if isinstance(v, bool):
            query[k] = v
        elif v:
            if k in validate_json_params:
                payload = validate_json(v)
                query[k] = payload
            elif k in date_params:
                query[k] = convert_date(k, v)
            else:
                query[k] = list(map(lambda x: x.strip(' '), str(v).split(","))) if k in list_value and not isinstance(v,
                                                                                                                 list) else v
    logger.debug('query: {}'.format(query))
    return query


def remove_keys(params, keys):
    for i in keys:
        if i in list(params.keys()):
            params.pop(i)


def threats_top_alarms(config, params, **kwargs):
    try:
        tenant_id = params.get('tenantId')
        tag_id = params.get('tagId')
        remove_keys(params, ['tenantId', 'tagId'])
        query_params = build_payload(params)
        res = make_rest_call(config, endpoint=threats_alarms.format(tenantId=tenant_id, tagId=tag_id),
                             params=query_params)
        return res
    except Exception as Err:
        logger.exception("{0}".format(str(Err)))
        raise ConnectorError(Err)


def top_conversation_flow(config, params, **kwargs):
    try:
        tenant_id = params.get("tenant_id")
        remove_keys(params, ['tenant_id'])
        payload = build_payload(params)
        endpoint = top_conversation.format(tenantId=tenant_id)
        return make_rest_call(config, endpoint, "POST", body=payload)
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_top_conversation_status(config, params, **kwargs):
    try:
        query_id = params.get("query_id")
        tenant_id = params.get("tenant_id")
        endpoint = top_conversation.format(tenantId=tenant_id) + '/{query_id}'.format(query_id=query_id)
        return make_rest_call(config, endpoint)
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_top_conversation_result(config, params, **kwargs):
    try:
        query_id = params.get("query_id")
        tenant_id = params.get("tenant_id")
        endpoint = top_conversation_result.format(tenantId=tenant_id, queryId=query_id)
        return make_rest_call(config, endpoint)
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))

def initiate_flow_analysis(config, params, **kwargs):
    try:
        tenant_id = params.get("tenantID")
        payload = params.get("flowAnalysis")
        logger.debug('Payload: {0}'.format(str(payload)))
        endpoint = flowanalysis.format(tenantId=tenant_id)
        return make_rest_call(config, endpoint, method="POST", body=payload)
    except Exception as err:
        logger.debug("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))

operations = {
    'application_traffic_domainid': application_traffic_domainid,
    'get_domain_details': get_domain_details,
    'application_traffic_ip': application_traffic_ip,
    'application_traffic_hostgroupid': application_traffic_hostgroupid,
    'initiate_flow_search': initiate_flow_search,
    'get_flow_search_status': get_flow_search_status,
    'get_flow_search_results': get_flow_search_results,
    'list_host_groups': list_host_groups,
    'get_host_details': get_host_details,
    'threats_top_alarms': threats_top_alarms,
    'top_conversation_flow': top_conversation_flow,
    'get_top_conversation_status': get_top_conversation_status,
    'get_top_conversation_result': get_top_conversation_result,
    'initiate_flow_analysis': initiate_flow_analysis
}
