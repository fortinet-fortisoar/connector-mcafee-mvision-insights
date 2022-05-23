""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, base64, logging
from connectors.core.connector import get_logger, ConnectorError
from requests_toolbelt.utils import dump
from .constants import *

logger = get_logger('mcafee-mvision-insights')


class McAfeeMvisionInsights(object):
    def generate_token(self):
        try:
            base64_string = self.client_id + ':' + self.client_secret
            token = base64.b64encode(base64_string.encode("ascii")).decode("ascii")
            headers = {
                'Authorization': 'Basic ' + token
            }
            params = (
                ('grant_type', 'client_credentials'),
                ('scope', ["ins.user | ins.suser | ins.ms.r | rp.gen.r"])
            )
            response = requests.get('https://iam.mcafee-cloud.com/iam/v1.0/token', headers=headers, params=params)
            if response.ok:
                return response.json().get("access_token")
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(errors.get(response.status_code, '')))
        except Exception as err:
            logger.exception("{0}".format(str(err)))
            raise ConnectorError("{0}".format(str(err)))

    def __init__(self, config, *args, **kwargs):
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.api_key = config.get('api_key')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/'.format(url)
        else:
            self.url = url + '/'
        self.token = self.generate_token()
        self.ssl_verify = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, json_data=None, params=None, header=None, host=None):
        try:

            url = host + url if host else self.url + url

            logger.debug("Endpoint URL: {0}".format(url))
            header = {'x-api-key': self.api_key, 'Content-Type': 'application/vnd.api+json',
                      'Authorization': 'Bearer ' + self.token}
            response = requests.request(method, url, headers=header, verify=self.ssl_verify, json=json_data, data=data, params=params)
            logger.warning('REQUESTS_DUMP:>>>>>>>>>>>>>>>>>>>>>>>>>>>\n{}'.format(dump.dump_all(response).decode('utf-8')))  
            if response.ok or response.status_code == 204:
                if 'api+json' in str(response.headers):
                    return response.json()
                else:
                    return response.content
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(errors.get(response.status_code, response.text)))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))

    def build_payload(self, params):
        payload = {k: v for k, v in params.items() if v is not None and v != ''}
        logger.debug("Query Parameters: {0}".format(payload))
        return payload


def get_ioc_list(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/iocs"
        fields = params.get('fields')
        if fields:
            fields = IOC_FIELDS.get(fields)
        payload = {
            'page[offset]': params.get('offset'),
            'page[limit]': params.get('limit'),
            'filter[campaign][id]': params.get('id'),
            'filter[type]': params.get('type'),
            'fields[iocs]': fields
        }
        payload = mv.build_payload(payload)
        response = mv.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_ioc_details(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/iocs/{0}".format(params.get('id'))
        fields = params.get('fields')
        if fields:
            fields = IOC_FIELDS.get(fields)
        query_parameter = {
            'fields[iocs]': fields
        }
        payload = mv.build_payload(query_parameter)
        response = mv.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_ioc_campaigns(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/iocs/{0}/campaigns".format(params.get('id'))
        response = mv.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_ioc_relationship_campaigns(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/iocs/{0}/relationships/campaigns".format(params.get('id'))
        response = mv.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_artefacts(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/artefacts/files"
        response = mv.make_rest_call(endpoint, 'GET', params=params)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaigns_list(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/campaigns"
        include = params.get('include')
        if include:
            include = "prevalence"
        fields = params.get('fields')
        if fields:
            fields = CAMPAIGN_FIELDS.get(fields)
        payload = {
            'page[offset]': params.get('offset'),
            'page[limit]': params.get('limit'),
            'filter[sector][name][eq]': params.get('sector'),
            'include': include,
            'fields[campaigns]': fields
        }
        filter_by = params.get('filter_by')
        if filter_by == 'Like':
            payload.update({'filter[name][like]': params.get('campaign_name')})
        elif filter_by == 'Exact':
            payload.update({'filter[name][eq]': params.get('campaign_name')})
        payload = mv.build_payload(payload)
        response = mv.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaign_details(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        include = params.get('include')
        if include:
            include = "prevalence"
        fields = params.get('fields')
        if fields:
            fields = CAMPAIGN_FIELDS.get(fields)
        payload = {
            'include': include,
            'fields[campaigns]': fields
        }
        payload = mv.build_payload(payload)
        endpoint = "insights/v2/campaigns/{0}".format(params.get('id'))
        response = mv.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaign_iocs(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/campaigns/{0}/iocs".format(params.get('id'))
        response = mv.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaigns_relationship_iocs(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/campaigns/{0}/relationships/iocs".format(params.get('id'))
        response = mv.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaign_galaxies(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/campaigns/{0}/galaxies".format(params.get('id'))
        response = mv.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaigns_relationship_galaxies(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/campaigns/{0}/relationships/galaxies".format(params.get('id'))
        response = mv.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_campaigns_detected(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/campaigns/detected"
        include = params.get('include')
        if include:
            include = "prevalence"
        fields = params.get('fields')
        if fields:
            fields = CAMPAIGN_FIELDS.get(fields)
        payload = {
            'page[offset]': params.get('offset'),
            'page[limit]': params.get('limit'),
            'filter[sector][name][eq]': params.get('sector'),
            'filter[last_detected_on][eq]': params.get('last_detected_on'),
            'include': include,
            'fields[campaigns]': fields
        }
        filter_by = params.get('filter_by')
        if filter_by == 'Like':
            payload.update({'filter[name][like]': params.get('campaign_name')})
        elif filter_by == 'Exact':
            payload.update({'filter[name][eq]': params.get('campaign_name')})
        payload = mv.build_payload(payload)
        response = mv.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_events_list(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/events"
        fields = params.get('fields')
        if fields:
            fields = EVENT_FIELDS.get(fields)
        payload = {
            'page[offset]': params.get('offset'),
            'page[limit]': params.get('limit'),
            'filter[artefact_type][eq]': params.get('artefact_type'),
            'filter[artefact_value][eq]': params.get('artefact_value'),
            'filter[ma_id][eq]': params.get('agent_guid'),
            'filter[campaign_id][eq]': params.get('id'),
            'filter[from_date][eq]': params.get('from_date'),
            'filter[to_date][eq]': params.get('to_date'),
            'fields[events]': fields
        }
        payload = mv.build_payload(payload)
        response = mv.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_insights_events_list(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = 'api/v2/events'
        if not INSIGHT_URL.startswith('https://') and not INSIGHT_URL.startswith('http://'):
            insights_url = 'https://{0}/'.format(INSIGHT_URL)
        else:
            insights_url = INSIGHT_URL + '/'
        payload = {
            'page[offset]': params.get('offset'),
            'page[limit]': params.get('limit'),
            'filter[artefact_type][eq]': params.get('artefact_type'),
            'filter[artefact_value][eq]': params.get('artefact_value'),
            'filter[ma_id][eq]': params.get('agent_guid'),
            'filter[campaign_id][eq]': params.get('id'),
            'filter[from_date][eq]': params.get('from_date'),
            'filter[to_date][eq]': params.get('to_date')
        }
        payload = mv.build_payload(payload)
        response = mv.make_rest_call(endpoint, 'GET', params=payload, host=insights_url)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_galaxies_list(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = "insights/v2/galaxies"
        category = params.get('category')
        if category:
            category = GALAXIES_CATEGORY.get(params.get('category'))
        fields = params.get('fields')
        if fields:
            fields = GALAXIES_FIELDS.get(fields)
        payload = {
            'page[offset]': params.get('offset'),
            'page[limit]': params.get('limit'),
            'filter[campaign][id]': params.get('id'),
            'filter[category]': category,
            'fields[galaxies]': fields
        }
        payload = mv.build_payload(payload)
        response = mv.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_related_samples(config, params):
    try:
        mv = McAfeeMvisionInsights(config)
        endpoint = 'realprotect/v2/staticAssociations'
        payload = {
            'page[offset]': params.get('offset'),
            'page[limit]': params.get('limit'),
            'samplemd5': params.get('samplemd5'),
            'sfvecmd5': params.get('sfvecmd5'),
            'version': params.get('version'),
            'lastseen': params.get('lastseen')
        }
        payload = mv.build_payload(payload)
        return mv.make_rest_call(endpoint, 'GET', params=payload)

    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        response = get_ioc_list(config, params={})
        if response:
            return True
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_ioc_list': get_ioc_list,
    'get_ioc_details': get_ioc_details,
    'get_ioc_campaigns': get_ioc_campaigns,
    'get_ioc_relationship_campaigns': get_ioc_relationship_campaigns,
    'get_artefacts': get_artefacts,
    'get_campaigns_list': get_campaigns_list,
    'get_campaign_details': get_campaign_details,
    'get_campaign_iocs': get_campaign_iocs,
    'get_campaigns_relationship_iocs': get_campaigns_relationship_iocs,
    'get_campaign_galaxies': get_campaign_galaxies,
    'get_campaigns_relationship_galaxies': get_campaigns_relationship_galaxies,
    'get_campaigns_detected': get_campaigns_detected,
    'get_events_list': get_events_list,
    'get_insights_events_list': get_insights_events_list,
    'get_galaxies_list': get_galaxies_list,
    'get_related_samples': get_related_samples
}
