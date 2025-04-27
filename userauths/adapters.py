from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings

class LoginAdapter(DefaultAccountAdapter):
    def get_login_redirect_url(self, request):
        myadmin = request.user
        if myadmin.is_authenticated and myadmin.is_superuser:
            return "/myadmin"
        else:
            return "/" 