"""Shared responses are projected on the server before leaving the API."""
from copy import deepcopy


def project_network(payload, keys):
    monitoring = 'network_sentinel.monitoring' in keys
    history = 'network_sentinel.outage_history' in keys
    if monitoring and history:
        return payload
    result = deepcopy(payload)

    def service(item):
        if not isinstance(item,dict):
            return
        if not monitoring:
            item['status'] = None
            item['metrics'] = {}
        if not history:
            item['active_outage'] = None

    if isinstance(result,list):
        for item in result:
            service(item)
        return result
    if not isinstance(result,dict):
        return result
    for item in result.get('services',[]):
        service(item)
    service(result.get('service'))
    if not monitoring:
        for name in ('samples','raw_rows'):
            if name in result:
                result[name] = []
        for name in ('metrics','overview'):
            if name in result:
                result[name] = {}
    if not history:
        for name in ('active_outages','recent_events','events','outages'):
            if name in result:
                result[name] = []
        result.get('overview',{}).pop('recent_event_count',None)
        result.get('overview',{}).pop('active_incidents',None)
        result.get('metrics',{}).pop('outage_count_diagnostic_window',None)
    return result
