from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.hashers import check_password
from patient_management.models import User
class CustomAuthentication(ModelBackend):
    def authenticate(self,username, password,**kwargs):
        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                return user
        except:
            pass


    