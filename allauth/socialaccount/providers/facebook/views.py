import logging
import requests

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

from .forms import FacebookConnectForm
from .provider import FacebookProvider, GRAPH_API_URL


logger = logging.getLogger(__name__)


def fb_complete_login(request, app, token):
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
    resp.raise_for_status()
    extra_data = resp.json()
    login = providers.registry \
        .by_id(FacebookProvider.id) \
        .sociallogin_from_response(request, extra_data)
    return login


class FacebookOAuth2Adapter(OAuth2Adapter):
    provider_id = FacebookProvider.id

    authorize_url = 'https://www.facebook.com/dialog/oauth'
    access_token_url = GRAPH_API_URL + '/oauth/access_token'
    expires_in_key = 'expires'

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
                provider = providers.registry.by_id(FacebookProvider.id)
                login_options = provider.get_fb_login_options(request)
                app = providers.registry.by_id(FacebookProvider.id) \
                    .get_app(request)
                access_token = form.cleaned_data['access_token']
                if login_options.get('auth_type') == 'reauthenticate':
                    info = requests.get(
                        GRAPH_API_URL + '/oauth/access_token_info',
                        params={'client_id': app.client_id,
                                'access_token': access_token}).json()
                    nonce = provider.get_nonce(request, pop=True)
                    ok = nonce and nonce == info.get('auth_nonce')
                else:
                    ok = True
                if ok:
                    token = SocialToken(app=app,
                                        token=access_token)
                    login = fb_complete_login(request, app, token, next_url)
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


def channel(request):
    provider = providers.registry.by_id(FacebookProvider.id)
    locale = provider.get_locale_for_request(request)
    response = render(request, 'facebook/channel.html',
                      {'facebook_jssdk_locale': locale})
    cache_expire = 60 * 60 * 24 * 365
    patch_response_headers(response, cache_expire)
    response['Pragma'] = 'Public'
    return response
