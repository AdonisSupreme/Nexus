"""Filter notification records by their resource, before pagination or delivery."""
from .policy import resolve_access

# Use the same stable resource classification in SQL so hidden records do not
# occupy page slots or contribute to the unread badge.
MODULE_CASE = """CASE
 WHEN related_entity LIKE 'nexus%%' THEN 'nexus.incidents'
 WHEN related_entity LIKE 'checklist%%' OR related_entity IN ('item_action','subitem_action') OR related_entity LIKE 'handover%%' THEN 'checklists.execution'
 WHEN related_entity LIKE 'task%%' THEN 'task_manager.tasks'
 WHEN related_entity LIKE 'trustlink%%' THEN 'trustlink.daily_extraction'
 WHEN related_entity LIKE 'network%%' THEN 'network_sentinel.monitoring'
 WHEN related_entity LIKE 'clearing%%' THEN 'funds_custody.workspace'
 WHEN related_entity LIKE 'hovering%%' THEN 'reports.hovering'
 WHEN related_entity LIKE 'crb%%' THEN 'reports.crb'
 ELSE NULL END"""
NOTIFICATION_FILTER = '(' + MODULE_CASE + ' IS NULL OR ' + MODULE_CASE + ' = ANY(%s::text[]))'


def notification_module(entity):
    entity = str(entity or '').lower()
    if entity.startswith('nexus'):
        return 'nexus.incidents'
    if entity.startswith(('checklist', 'item_', 'subitem_', 'handover')):
        return 'checklists.execution'
    for prefix, key in [('task','task_manager.tasks'),('trustlink','trustlink.daily_extraction'),
                        ('network','network_sentinel.monitoring'),('clearing','funds_custody.workspace'),
                        ('hovering','reports.hovering'),('crb','reports.crb')]:
        if entity.startswith(prefix):
            return key
    return None  # Account and generic system notifications remain available.


def visible(notification, keys):
    key = notification_module(notification.get('related_entity'))
    return key is None or key in keys


def user_keys(conn, user_id):
    with conn.cursor() as cur:
        cur.execute('''SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id
            WHERE ur.user_id=%s ORDER BY CASE r.name WHEN 'admin' THEN 0 WHEN 'manager' THEN 1 ELSE 2 END LIMIT 1''',(str(user_id),))
        row = cur.fetchone()
    return resolve_access({'id':str(user_id),'role':row[0] if row else 'user'},conn)['modules']
