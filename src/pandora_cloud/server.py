# -*- coding: utf-8 -*-
import json
import logging
import traceback
from os.path import join, abspath, dirname

from flask import Flask, jsonify, request, render_template, redirect, url_for, make_response, Response
from pandora.exts.hooks import hook_logging
from pandora.exts.token import check_access_token
from pandora.openai.api import API, ChatGPT
from pandora.openai.auth import Auth0
from waitress import serve
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler


class ChatBot:
    __default_ip = '0.0.0.0'
    __default_port = 8018
    __build_id = 'tTShkecJDS0nIc9faO2vC'

    def __init__(self, proxy, debug=False, sentry=False, login_local=False, pwd='', token_file=None):
        self.proxy = proxy
        self.debug = debug
        self.sentry = sentry
        self.login_local = login_local
        self.pwd = pwd
        self.token_file = token_file
        self.log_level = logging.DEBUG if debug else logging.WARN
        self.api_prefix = 'http://chat.jclass24.com'
        self.chatgpt = ChatGPT(self.load_token_file())

        hook_logging(level=self.log_level, format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
        self.logger = logging.getLogger('waitress')

    def run(self, bind_str, threads=4):
        host, port = self.__parse_bind(bind_str)

        resource_path = abspath(join(dirname(__file__), 'flask'))
        app = Flask(__name__, static_url_path='',
                    static_folder=join(resource_path, 'static'),
                    template_folder=join(resource_path, 'templates'))
        app.wsgi_app = ProxyFix(app.wsgi_app, x_port=1)
        app.after_request(self.__after_request)

        app.route('/api/models')(self.list_models)
        app.route('/api/conversations')(self.list_conversations)
        app.route('/api/conversations', methods=['DELETE'])(self.clear_conversations)
        app.route('/api/conversation/<conversation_id>')(self.get_conversation)
        app.route('/api/conversation/<conversation_id>', methods=['DELETE'])(self.del_conversation)
        app.route('/api/conversation/<conversation_id>', methods=['PATCH'])(self.set_conversation_title)
        app.route('/api/conversation/gen_title/<conversation_id>', methods=['POST'])(self.gen_conversation_title)
        app.route('/api/conversation/talk', methods=['POST'])(self.talk)
        app.route('/api/conversation/regenerate', methods=['POST'])(self.regenerate)
        app.route('/api/conversation/goon', methods=['POST'])(self.goon)

        app.route('/api/auth/session')(self.session)
        app.route('/api/accounts/check')(self.check)
        app.route('/api/auth/signout', methods=['POST'])(self.logout)
        app.route('/_next/data/{}/chat.json'.format(self.__build_id))(self.chat_info)

        app.route('/')(self.chat)
        app.route('/chat')(self.chat)
        app.route('/chat/<conversation_id>')(self.chat)

        app.route('/login')(self.login)
        app.route('/login', methods=['POST'])(self.login_post)
        app.route('/login_token', methods=['POST'])(self.login_token)

        if not self.debug:
            self.logger.warning('Serving on http://{}:{}'.format(host, port))

        WSGIRequestHandler.protocol_version = 'HTTP/1.1'
        serve(app, host=host, port=port, ident=None, threads=threads)

    @staticmethod
    def __after_request(resp):
        __version__ = '0.07'
        resp.headers['X-Server'] = 'pandora-cloud/{}'.format(__version__)

        return resp

    def __parse_bind(self, bind_str):
        sections = bind_str.split(':', 2)
        if len(sections) < 2:
            try:
                port = int(sections[0])
                return self.__default_ip, port
            except ValueError:
                return sections[0], self.__default_port

        return sections[0], int(sections[1])

    @staticmethod
    def __set_cookie(resp, token, expires):
        resp.set_cookie('access-token', token, expires=expires, path='/', domain=None, httponly=True, samesite='Lax')

    def __get_userinfo(self):
        payload = self.load_token_file()
        access_token = request.cookies.get('access-token')
        if payload.get("accessToken") == access_token:
            user_id = payload.get("user").get('id')
            email = payload.get("user").get('email')
            access_token = payload.get("accessToken")
            return False, user_id, email, access_token, payload
        else:
            return True, None, None, None, None

    def logout(self):
        resp = jsonify({'url': url_for('login')})
        self.__set_cookie(resp, '', 0)

        return resp

    def login(self):
        return render_template('login.html', api_prefix=self.api_prefix)

    def login_post(self):
        username = request.form.get('username')
        password = request.form.get('password')
        error = None

        if username and password:
            try:
                access_token = Auth0(username, password, self.proxy).auth(self.login_local)
                payload = check_access_token(access_token)

                resp = make_response('please wait...', 302)
                resp.headers.set('Location', url_for('chat'))
                self.__set_cookie(resp, access_token, payload['exp'])

                return resp
            except Exception as e:
                error = str(e)

        return render_template('login.html', username=username, error=error, api_prefix=self.api_prefix)

    def login_token(self):
        access_token = request.form.get('access_token')
        error = None

        if access_token:
            try:
                if access_token == self.pwd:
                    payload = self.load_token_file()

                    resp = jsonify({'code': 0, 'url': url_for('chat')})
                    self.__set_cookie(resp, payload.get('accessToken'), payload.get('expires'))

                    return resp
            except Exception as e:
                error = str(e)
                print(traceback.format_exc())

        return jsonify({'code': 500, 'message': 'Invalid password: {}'.format(error)})

    def chat(self, conversation_id=None):
        err, user_id, email, _, _ = self.__get_userinfo()
        if err:
            return redirect(url_for('login'))

        props = {
            'props': {
                'pageProps': {
                    'user': {
                        'id': user_id,
                        'name': email,
                        'email': email,
                        'image': None,
                        'picture': None,
                        'groups': []
                    },
                    'serviceStatus': {},
                    'userCountry': 'US',
                    'geoOk': True,
                    'serviceAnnouncement': {
                        'paid': {},
                        'public': {}
                    },
                    'isUserInCanPayGroup': True
                },
                '__N_SSP': True
            },
            'page': '/chat/[[...chatId]]',
            'query': {'chatId': [conversation_id]} if conversation_id else {},
            'buildId': self.__build_id,
            'isFallback': False,
            'gssp': True,
            'scriptLoader': []
        }

        return render_template('chat.html', pandora_sentry=self.sentry, api_prefix=self.api_prefix, props=props)

    def session(self):
        err, user_id, email, access_token, payload = self.__get_userinfo()
        if err:
            return jsonify({})

        ret = {
            'user': {
                'id': user_id,
                'name': email,
                'email': email,
                'image': None,
                'picture': None,
                'groups': []
            },
            'expires': payload.get("expires"),
            'accessToken': access_token
        }

        return jsonify(ret)

    def chat_info(self):
        err, user_id, email, _, _ = self.__get_userinfo()
        if err:
            return jsonify({'pageProps': {'__N_REDIRECT': '/login', '__N_REDIRECT_STATUS': 307}, '__N_SSP': True})

        ret = {
            'pageProps': {
                'user': {
                    'id': user_id,
                    'name': email,
                    'email': email,
                    'image': None,
                    'picture': None,
                    'groups': []
                },
                'serviceStatus': {},
                'userCountry': 'US',
                'geoOk': True,
                'serviceAnnouncement': {
                    'paid': {},
                    'public': {}
                },
                'isUserInCanPayGroup': True
            },
            '__N_SSP': True
        }

        return jsonify(ret)

    @staticmethod
    def check():
        ret = {
            'account_plan': {
                'is_paid_subscription_active': True,
                'subscription_plan': 'chatgptplusplan',
                'account_user_role': 'account-owner',
                'was_paid_customer': True,
                'has_customer_object': True,
                'subscription_expires_at_timestamp': 3774355199
            },
            'user_country': 'US',
            'features': [
                'model_switcher',
                'dfw_message_feedback',
                'dfw_inline_message_regen_comparison',
                'model_preview',
                'system_message',
                'can_continue',
            ],
        }

        return jsonify(ret)

    def load_token_file(self):
        """
        Load data from json file in temp path.
        """
        if self.token_file:
            with open(self.token_file, mode="r", encoding="UTF-8") as f:
                data = json.load(f)
            return data

    def list_models(self):
        return self.__proxy_result(self.chatgpt.list_models(True, self.__get_token_key()))

    def list_conversations(self):
        offset = request.args.get('offset', '1')
        limit = request.args.get('limit', '20')

        return self.__proxy_result(self.chatgpt.list_conversations(offset, limit, True, self.__get_token_key()))

    def get_conversation(self, conversation_id):
        return self.__proxy_result(self.chatgpt.get_conversation(conversation_id, True, self.__get_token_key()))

    def del_conversation(self, conversation_id):
        return self.__proxy_result(self.chatgpt.del_conversation(conversation_id, True, self.__get_token_key()))

    def clear_conversations(self):
        return self.__proxy_result(self.chatgpt.clear_conversations(True, self.__get_token_key()))

    def set_conversation_title(self, conversation_id):
        title = request.json['title']

        return self.__proxy_result(
            self.chatgpt.set_conversation_title(conversation_id, title, True, self.__get_token_key()))

    def gen_conversation_title(self, conversation_id):
        payload = request.json
        model = payload['model']
        message_id = payload['message_id']

        return self.__proxy_result(
            self.chatgpt.gen_conversation_title(conversation_id, model, message_id, True, self.__get_token_key()))

    def talk(self):
        payload = request.json
        prompt = payload['prompt']
        model = payload['model']
        message_id = payload['message_id']
        parent_message_id = payload['parent_message_id']
        conversation_id = payload.get('conversation_id')
        stream = payload.get('stream', True)

        return self.__process_stream(
            *self.chatgpt.talk(prompt, model, message_id, parent_message_id, conversation_id, stream,
                               self.__get_token_key()), stream)

    def goon(self):
        payload = request.json
        model = payload['model']
        parent_message_id = payload['parent_message_id']
        conversation_id = payload.get('conversation_id')
        stream = payload.get('stream', True)

        return self.__process_stream(
            *self.chatgpt.goon(model, parent_message_id, conversation_id, stream, self.__get_token_key()), stream)

    def regenerate(self):
        payload = request.json

        conversation_id = payload.get('conversation_id')
        if not conversation_id:
            return self.talk()

        prompt = payload['prompt']
        model = payload['model']
        message_id = payload['message_id']
        parent_message_id = payload['parent_message_id']
        stream = payload.get('stream', True)

        return self.__process_stream(
            *self.chatgpt.regenerate_reply(prompt, model, conversation_id, message_id, parent_message_id, stream,
                                           self.__get_token_key()), stream)

    @staticmethod
    def __process_stream(status, headers, generator, stream):
        if stream:
            return Response(API.wrap_stream_out(generator, status), mimetype=headers['Content-Type'], status=status)

        last_json = None
        for json in generator:
            last_json = json

        return make_response(last_json, status)

    @staticmethod
    def __proxy_result(remote_resp):
        resp = make_response(remote_resp.text)
        resp.content_type = remote_resp.headers['Content-Type']
        resp.status_code = remote_resp.status_code

        return resp

    @staticmethod
    def __get_token_key():
        return "accessToken"
