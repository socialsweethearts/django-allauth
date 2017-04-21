from importlib import import_module

from django.conf.urls import url, patterns, include

from allauth.socialaccount import providers

from . import app_settings

# urlpatterns = patterns('', url('^', include('allauth.account.urls')))
# NAM-1629: We decide to disable all urls with manual login, change password, etc.
urlpatterns = patterns('')

if app_settings.SOCIALACCOUNT_ENABLED:
    urlpatterns += [url(r'^social/', include('allauth.socialaccount.urls'))]

for provider in providers.registry.get_list():
    try:
        prov_mod = import_module(provider.get_package() + '.urls')
    except ImportError:
        continue
    prov_urlpatterns = getattr(prov_mod, 'urlpatterns', None)
    if prov_urlpatterns:
        urlpatterns += prov_urlpatterns
