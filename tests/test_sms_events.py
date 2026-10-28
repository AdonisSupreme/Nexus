import asyncio
from unittest.mock import MagicMock
from app.nexus import sms_events as module
from app.nexus import sms_monitor
from app.api.sms_monitor import events
from pydantic import SecretStr


def test_subscribers_share_one_source_listener(monkeypatch):
    thread = MagicMock()
    monkeypatch.setattr(module, 'Thread', thread)
    hub = module.SmsEvents()
    hub.subscribe(); hub.subscribe()
    assert thread.call_count == 1 and thread.return_value.start.call_count == 1
    hub.unsubscribe(); assert hub.active()
    hub.unsubscribe(); assert not hub.active()


def test_source_event_invalidates_cache_without_exposing_payload():
    hub = module.SmsEvents()
    revision = sms_monitor._source_revision
    hub.publish('realtime')
    assert sms_monitor._source_revision == revision + 1
    assert sms_monitor._overview_until == 0
    assert hub.snapshot() == {'revision':1, 'mode':'realtime'}


def test_stalled_source_listener_is_not_advertised_as_live():
    hub = module.SmsEvents()
    hub.publish('realtime')
    hub.last_seen -= 6
    assert hub.snapshot()['mode'] == 'unavailable'


def listener(monkeypatch, ready, notifications):
    import psycopg
    monkeypatch.setattr(module.settings, 'SMSAL_PASSWORD', SecretStr('test-only'))
    connect = MagicMock()
    conn = connect.return_value.__enter__.return_value
    conn.notifies.side_effect = notifications
    monkeypatch.setattr(psycopg, 'connect', connect)
    monkeypatch.setattr(module, 'sleep', lambda _: None)
    hub = module.SmsEvents()
    hub.trigger_ready = lambda _: ready
    hub.active = MagicMock(side_effect=[True, True, False])
    hub.publish = MagicMock()
    hub.listen()
    return hub, connect, conn


def test_committed_change_triggers_invalidation_without_waiting_for_poll(monkeypatch):
    hub, connect, conn = listener(monkeypatch, True, [[object()], []])
    assert hub.publish.call_count == 2  # reconnect snapshot plus the actual event
    assert all(call.args == ('realtime',) for call in hub.publish.call_args_list)
    conn.execute.assert_called_with('LISTEN sentinelops_sms_queue')
    assert connect.call_args.kwargs['autocommit'] is True
    assert 'default_transaction_read_only=on' in connect.call_args.kwargs['options']


def test_missing_trigger_is_explicit_one_second_fallback(monkeypatch):
    hub, _, conn = listener(monkeypatch, False, [[], []])
    assert hub.publish.call_count == 3
    assert all(call.args == ('polling',) for call in hub.publish.call_args_list)
    assert all(call.kwargs['timeout'] == 1 for call in conn.notifies.call_args_list)


def test_stream_cleans_up_subscription_and_does_not_contain_customer_data(monkeypatch):
    from app.api import sms_monitor as api
    hub = MagicMock()
    hub.snapshot.return_value = {'revision':7,'mode':'realtime'}
    monkeypatch.setattr(api, 'sms_events', hub)
    class Request:
        async def is_disconnected(self): return False
    async def check():
        response = await events(Request())
        assert response.headers['x-accel-buffering'] == 'no'
        stream = response.body_iterator
        frame = await anext(stream)
        assert frame == 'data: {"revision": 7, "mode": "realtime"}\n\n'
        await stream.aclose()
    asyncio.run(check())
    hub.subscribe.assert_called_once(); hub.unsubscribe.assert_called_once()


def test_invalidation_during_overview_cannot_mark_old_snapshot_current(monkeypatch):
    from contextlib import contextmanager
    monkeypatch.setattr(sms_monitor.SmsMonitor,'configured',property(lambda _:True))
    monkeypatch.setattr(sms_monitor,'_overview_cache',None)
    gateway = sms_monitor.SmsMonitor()
    cursor = MagicMock()
    cursor.fetchone.return_value = {'retained':1}
    cursor.fetchall.return_value = []
    @contextmanager
    def connection():
        yield cursor
        sms_monitor.invalidate_sms_cache()
    gateway.connection = connection
    gateway.overview()
    assert sms_monitor._overview_revision != sms_monitor._source_revision
    gateway.overview()
    assert cursor.execute.call_count == 6
