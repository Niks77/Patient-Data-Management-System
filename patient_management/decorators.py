from django.shortcuts import redirect
from ratelimit.decorators import ratelimit


def login(login_func):
    @ratelimit(key='ip', rate='100/h', block=True)
    def admin_login(request, **kwargs):
        return login_func(request, **kwargs)
    return admin_login