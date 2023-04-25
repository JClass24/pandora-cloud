# -*- coding: utf-8 -*-
import json
import logging
import traceback
from os.path import join, abspath, dirname

from flask import Flask, jsonify, request, render_template, redirect, url_for, make_response
from pandora.exts.hooks import hook_logging
from pandora.exts.token import check_access_token
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
        self.api_prefix = 'https://chat-api.zhile.io'

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

        user_id = payload.get("user").get('id')
        email = payload.get("user").get('email')
        access_token = payload.get("accessToken")

        return False, user_id, email, access_token, payload

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
