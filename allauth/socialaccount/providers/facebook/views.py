import hashlib
import hmac
import logging
import requests
<<<<<<< HEAD
from datetime import timedelta

from django.utils import timezone

from allauth.socialaccount import app_settings, providers
from allauth.socialaccount.helpers import (
    complete_social_login,
    render_authentication_error,
)
from allauth.socialaccount.models import SocialLogin, SocialToken
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
=======

from django.utils.cache import patch_response_headers
from django.shortcuts import render, redirect


from allauth.socialaccount.models import (SocialLogin,
                                          SocialToken)
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount.helpers import render_authentication_error
from allauth.socialaccount import providers
from allauth.account.utils import get_next_redirect_url
from allauth.socialaccount.providers.oauth2.views import (OAuth2Adapter,
                                                          OAuth2LoginView,
                                                          OAuth2CallbackView)
>>>>>>> a3f1d6a73666e4d4aa1b21afc6abba4594a816b1

from .forms import FacebookConnectForm
from .provider import GRAPH_API_URL, FacebookProvider


logger = logging.getLogger(__name__)


def compute_appsecret_proof(app, token):
    # Generate an appsecret_proof parameter to secure the Graph API call
    # see https://developers.facebook.com/docs/graph-api/securing-requests
    msg = token.token.encode('utf-8')
    key = app.secret.encode('utf-8')
    appsecret_proof = hmac.new(
        key,
        msg,
        digestmod=hashlib.sha256).hexdigest()
    return appsecret_proof


def fb_complete_login(request, app, token):
<<<<<<< HEAD
    provider = providers.registry.by_id(FacebookProvider.id, request)
    resp = requests.get(
        GRAPH_API_URL + '/me',
        params={
            'fields': ','.join(provider.get_fields()),
            'access_token': token.token,
            'appsecret_proof': compute_appsecret_proof(app, token)
        })
=======
    try:
        resp = requests.get(GRAPH_API_URL + '/me', params={
          'access_token': token.token,
          'fields': ','.join(['id',
            'email',
            'name',
            'first_name',
            'last_name',
            'verified',
            'locale',
            'timezone',
            'link',
            'gender',
            'birthday',
            'updated_time'])
        }, timeout=2)
    except Exception as e:
        raise requests.RequestException(e.message)
>>>>>>> a3f1d6a73666e4d4aa1b21afc6abba4594a816b1
    resp.raise_for_status()
    extra_data = resp.json()
    login = provider.sociallogin_from_response(request, extra_data)
    return login


class FacebookOAuth2Adapter(OAuth2Adapter):
    provider_id = FacebookProvider.id
    provider_default_auth_url = 'https://www.facebook.com/dialog/oauth'

    settings = app_settings.PROVIDERS.get(provider_id, {})

    authorize_url = settings.get('AUTHORIZE_URL', provider_default_auth_url)
    access_token_url = GRAPH_API_URL + '/oauth/access_token'
    expires_in_key = 'expires_in'

    def complete_login(self, request, app, access_token, **kwargs):
        return fb_complete_login(request, app, access_token)


oauth2_login = OAuth2LoginView.adapter_view(FacebookOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(FacebookOAuth2Adapter)


def login_by_token(request):
    ret = None
    next_url = get_next_redirect_url(request)
    auth_exception = None
    if request.method == 'POST':
        form = FacebookConnectForm(request.POST)
        if form.is_valid():
            try:
                provider = providers.registry.by_id(
                    FacebookProvider.id, request)
                login_options = provider.get_fb_login_options(request)
                app = provider.get_app(request)
                access_token = form.cleaned_data['access_token']
                expires_at = None
                if login_options.get('auth_type') == 'reauthenticate':
                    info = requests.get(
                        GRAPH_API_URL + '/oauth/access_token_info',
                        params={'client_id': app.client_id,
                                'access_token': access_token}).json()
                    nonce = provider.get_nonce(request, pop=True)
                    ok = nonce and nonce == info.get('auth_nonce')
                else:
                    ok = True
                if ok and provider.get_settings().get('EXCHANGE_TOKEN'):
                    resp = requests.get(
                        GRAPH_API_URL + '/oauth/access_token',
                        params={'grant_type': 'fb_exchange_token',
                                'client_id': app.client_id,
                                'client_secret': app.secret,
                                'fb_exchange_token': access_token}).json()
                    access_token = resp['access_token']
                    expires_in = resp.get('expires_in')
                    if expires_in:
                        expires_at = timezone.now() + timedelta(
                            seconds=int(expires_in))
                if ok:
                    token = SocialToken(app=app,
<<<<<<< HEAD
                                        token=access_token,
                                        expires_at=expires_at)
                    login = fb_complete_login(request, app, token)
=======
                                        token=access_token)
                    login = fb_complete_login(request, app, token, next_url)
>>>>>>> a3f1d6a73666e4d4aa1b21afc6abba4594a816b1
                    login.token = token
                    login.state = SocialLogin.state_from_request(request)
                    ret = complete_social_login(request, login)
            except requests.RequestException as e:
                logger.exception('Error accessing FB user profile')
                auth_exception = e
    if not ret:
        redir_url = '%s?fbpr=%s' % (next_url.split('?fbpr=y')[0],'y')
        return redirect(redir_url)
    return ret
