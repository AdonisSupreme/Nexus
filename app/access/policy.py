"""Portable access policy. Generated copies are checked by scripts/sync_access.py."""
import json
from pathlib import Path

MODULES = json.loads(Path(__file__).with_name('modules.json').read_text(encoding='utf-8'))
MODULE_KEYS = frozenset(m['module_key'] for m in MODULES)


def effective_keys(role, section_active, assigned, active):
    # ADMIN is explicitly the system administrator. Disabled resources stay disabled.
    if str(role).upper() == 'ADMIN':
        return set(active)
    return set(assigned).intersection(active) if section_active else set()


def resolve_access(user, connection):
    """One joined query per request; no session cache to invalidate on reassignment."""
    with connection.cursor() as cur:
        cur.execute('''SELECT m.module_key, m.is_active,
            s.id::text, s.section_name, s.is_active,
            sm.module_id IS NOT NULL
            FROM access_modules m
            LEFT JOIN users u ON u.id = %s
            LEFT JOIN sections s ON s.id = u.section_id
            LEFT JOIN section_modules sm ON sm.section_id = s.id AND sm.module_id = m.id''',
            (user['id'],))
        rows = cur.fetchall()
    active = {r[0] for r in rows if r[1]}
    assigned = {r[0] for r in rows if r[5]}
    section = {'id': rows[0][2], 'name': rows[0][3], 'is_active': rows[0][4]} if rows and rows[0][2] else None
    keys = effective_keys(user.get('role'), section and section['is_active'], assigned, active)
    return {'role': str(user.get('role', '')).upper(), 'section': section,
            'modules': sorted(keys), 'registry': MODULES}


def required_modules(path, method='GET'):
    """Ordered API resource mapping. Tuple means any of these consumers may read it.

    Shared responses must contain only data belonging to these consumers. Mutations
    retain their original role checks in addition to this entitlement check.
    """
    path = path.rstrip('/')
    write = method not in ('GET', 'HEAD', 'WEBSOCKET')
    if path.startswith('/api/pdf'):
        return ('checklists.execution',)
    if not path.startswith('/api/v1/'):
        return ()
    p = path[8:]
    if p in ('query', 'classify') or p.startswith('sops/'):
        return ('nexus.sops',)
    if p.startswith('network-sentinel'):
        if write:
            return ('network_sentinel.configuration',)
        if p.endswith('/services') or p.endswith('/command-center') or p.endswith('/investigation'):
            return ('network_sentinel.monitoring', 'network_sentinel.configuration', 'network_sentinel.outage_history')
        if p.endswith('/outages'):
            return ('network_sentinel.outage_history',)
        return ('network_sentinel.monitoring',)
    if p.startswith('trustlink'):
        if '/pipeline/config' in p:
            return ('trustlink.configuration',) if write else ('trustlink.daily_extraction', 'trustlink.configuration')
        if p.endswith('/run') or '/run/overwrite' in p:
            return ('trustlink.manual_run',)
        if p.endswith('/runs/today'):
            return ('trustlink.daily_extraction', 'trustlink.manual_run')
        if p.endswith('/runs'):
            return ('trustlink.run_history',)
        if write:
            return ('trustlink.run_history',)
        return ('trustlink.run_history', 'trustlink.daily_extraction')
    if p.startswith('tasks'):
        return ('task_manager.tasks',)
    if p.startswith('users/by-section'):
        return ('checklists.execution','task_manager.tasks','team.scheduling','team.schedule')
    if p.startswith('gamification'):
        return ('performance.dashboard',)
    if p.startswith('dashboard'):
        return ('database.statistics',)
    if p.startswith('checklists'):
        tail = p[len('checklists'):]
        if tail in ('/authorization-policy', '/state-policy'):
            return ()  # Public role definitions, no operational data.
        if tail.startswith('/templates'):
            return ('checklists.templates',) if write else ('checklists.templates', 'checklists.execution')
        if tail.startswith('/performance'):
            return ('performance.dashboard',)
        if any(tail.startswith('/' + item) for item in ('shifts', 'scheduled-shifts', 'shift-patterns', 'bulk-assign-shifts', 'days-off', 'shift-exception', 'my-schedule')):
            return ('team.scheduling',) if write else ('team.scheduling', 'team.schedule')
        if tail == '/ws':
            return ('checklists.execution', 'trustlink.daily_extraction', 'trustlink.run_history')
        return ('checklists.execution',)
    if p.startswith('nexus/'):
        if p.startswith('nexus/agents/') and (p.endswith(('/heartbeat', '/config', '/probe-report', '/diagnostic-results', '/control-results'))):
            return ()  # Machine agent authentication remains in its existing dependency.
        if p.startswith('nexus/reports/hovering/settings'):
            return ('reports.hovering_settings',)
        for prefix, key in (
            ('nexus/reports/crb', 'reports.crb'),
            ('nexus/reports/hovering', 'reports.hovering'),
            ('nexus/trustlink/rtgs', 'trustlink.rtgs'),
            ('nexus/clearing', 'funds_custody.workspace'),
            ('nexus/rollover', 'nexus.rollover'),
            ('nexus/sops', 'nexus.sops'),
        ):
            if p.startswith(prefix):
                return (key,)
        if p.startswith('nexus/catalog/services'):
            if '/database/test-connection' in p:
                return ('nexus.databases',)
            # A single service catalog supplies these three workspaces.
            return ('nexus.services','nexus.databases','nexus.onboarding')
        if p.startswith('nexus/services/'):
            return ('nexus.services','nexus.databases','nexus.incidents')
        for prefix,key in (
            ('nexus/incidents','nexus.incidents'),
            ('nexus/notifications','nexus.incidents'),
            ('nexus/change-events','nexus.incidents'),
            ('nexus/agents/token','nexus.onboarding'),
            ('nexus/agents','nexus.agents'),
            ('nexus/sync','nexus.onboarding'),
            ('nexus/catalog/clusters','nexus.clusters'),
            ('nexus/catalog/business-flows','nexus.flows'),
            ('nexus/catalog/dependencies','nexus.dependencies'),
            ('nexus/fabric-summary','nexus.dashboard'),
        ):
            if p.startswith(prefix):
                return (key,)
        return ('__unregistered_module__',)
    return ()


def event_modules(path, event):
    """The checklist stream also carries Trustlink events: filter before delivery."""
    if '/checklists/ws' in path:
        if event.get('type') in ('CHECKLIST_UPDATE','USER_UPDATE') and isinstance(event.get('data'),dict):
            event = event['data']
        kind = str(event.get('type', '')).upper()
        if kind in ('CONNECTION_ESTABLISHED', 'WELCOME', 'PING', 'PONG', 'ERROR', 'SUBSCRIBED'):
            return ()
        if 'TRUSTLINK' in kind:
            if event.get('event') == 'pipeline_config':
                return ('trustlink.daily_extraction', 'trustlink.configuration')
            return ('trustlink.daily_extraction', 'trustlink.run_history')
        return ('checklists.execution',)
    return required_modules(path, 'WEBSOCKET')
