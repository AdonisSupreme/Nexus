"""ASGI enforcement for HTTP and existing authenticated WebSocket transports."""
import json
from datetime import date
from urllib.parse import parse_qs
from fastapi import HTTPException
from starlette.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from .policy import required_modules, resolve_access, event_modules
from .notifications import visible
from .projections import project_network
from .request_context import request_identity


class ModuleAccessMiddleware:
    def __init__(self, app, authenticate, connect):
        self.app, self.authenticate, self.connect = app, authenticate, connect

    def access(self, user):
        with self.connect() as conn:
            return resolve_access(user, conn)

    def can_receive_event(self, path, payload, keys):
        if '/checklists/ws' not in path:
            return True
        event = payload.get('data', payload)
        if not isinstance(event, dict) or str(event.get('type', '')).lower() != 'trustlink_update':
            return True
        if event.get('event') == 'pipeline_config' or 'trustlink.run_history' in keys:
            return True  # Module classification is checked separately.
        # Daily-only subscriptions must not receive historical run/step updates.
        run_id = event.get('run_id')
        if not run_id:
            return False
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute('SELECT run_date FROM trustlink_runs WHERE id::text=%s', (str(run_id),))
            row = cur.fetchone()
        return bool(row and row[0] == date.today())

    async def __call__(self, scope, receive, send):
        kind = scope['type']
        if kind not in ('http', 'websocket') or scope.get('method') == 'OPTIONS':
            return await self.app(scope, receive, send)
        required = required_modules(scope['path'], scope.get('method', 'WEBSOCKET'))
        notification_stream = kind == 'websocket' and scope['path'].rstrip('/') == '/api/v1/notifications/ws'
        if not required and not notification_stream:
            return await self.app(scope, receive, send)
        headers = dict(scope.get('headers', []))
        authorization = headers.get(b'authorization', b'').decode()
        if kind == 'websocket':
            token = parse_qs(scope.get('query_string', b'').decode()).get('token', [''])[0]
            authorization = authorization or ('Bearer ' + token if token else '')

        async def load_access():
            user = await self.authenticate(authorization)
            result = user.get('access')
            if result is None:
                result = await run_in_threadpool(self.access, user)
            scope.setdefault('state', {})['module_access'] = result
            scope['state']['authenticated_user'] = user
            if required and not set(required).intersection(result['modules']):
                raise HTTPException(403, 'Your section cannot access this module.')
            return result

        try:
            await load_access()
        except HTTPException as exc:
            if kind == 'websocket':
                return await send({'type': 'websocket.close', 'code': 1008, 'reason': exc.detail})
            return await JSONResponse({'detail': exc.detail}, status_code=exc.status_code)(scope, receive, send)

        async def serve_http():
            keys = scope['state']['module_access']['modules']
            needs_projection = not {'network_sentinel.monitoring', 'network_sentinel.outage_history'}.issubset(keys)
            if needs_projection and scope['path'].startswith('/api/v1/network-sentinel/') and scope.get('method') in ('GET','HEAD'):
                start = None
                chunks = []
                project_json = False
                async def projected_send(message):
                    nonlocal start, project_json
                    if message['type'] == 'http.response.start':
                        start = message
                        headers = dict(message.get('headers', []))
                        project_json = b'application/json' in headers.get(b'content-type', b'') and scope.get('method') != 'HEAD'
                        if not project_json:
                            await send(message)
                    elif message['type'] == 'http.response.body':
                        if not project_json:
                            return await send(message)
                        chunks.append(message.get('body',b''))
                        if not message.get('more_body'):
                            body = b''.join(chunks)
                            headers = dict(start.get('headers',[]))
                            if 'application/json' in headers.get(b'content-type',b'').decode():
                                body = json.dumps(project_network(json.loads(body),scope['state']['module_access']['modules'])).encode()
                                start['headers'] = [(k,v) for k,v in start['headers'] if k.lower()!=b'content-length'] + [(b'content-length',str(len(body)).encode())]
                            await send(start)
                            await send({'type':'http.response.body','body':body})
                    else:
                        await send(message)
                return await self.app(scope,receive,projected_send)
            return await self.app(scope, receive, send)

        if kind == 'http':
            identity_token = request_identity.set((authorization, scope['state']['authenticated_user']))
            try:
                return await serve_http()
            finally:
                request_identity.reset(identity_token)

        closed = False
        async def secured_receive():
            if closed:
                return {'type':'websocket.disconnect','code':1008}
            return await receive()

        async def secured_send(message):
            nonlocal closed
            if closed:
                return
            if message['type'] == 'websocket.send':
                try:
                    access = await load_access()  # Includes session/role/section revocation.
                    payload = json.loads(message.get('text') or message.get('bytes') or '{}')
                    if notification_stream:
                        body = payload.get('payload', {})
                        if 'notification' in body and not visible(body['notification'], access['modules']):
                            return
                        if 'notifications' in body:
                            body['notifications'] = [n for n in body['notifications'] if visible(n,access['modules'])]
                            body['count'] = len(body['notifications'])
                        message = {'type':'websocket.send','text':json.dumps(payload)}
                    needed = event_modules(scope['path'], payload)
                    if needed and not set(needed).intersection(access['modules']):
                        return
                    if not await run_in_threadpool(self.can_receive_event, scope['path'], payload, access['modules']):
                        return
                except HTTPException:
                    closed = True
                    return await send({'type': 'websocket.close', 'code': 1008, 'reason': 'Access changed. Reconnect.'})
            await send(message)
        await self.app(scope, secured_receive, secured_send)
