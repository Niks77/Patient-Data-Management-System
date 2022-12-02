from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.hashers import check_password
from patient_management.models import User
class CustomAuthentication(ModelBackend):
    def authenticate(self,request,**credentials):
        try:
            # print(username
            # print(request.POST)
            user = User.objects.get(username=credentials['username'])
            print(check_password(credentials['password'],user.password))
            if check_password(credentials['password'],user.password):
                return user
        except:
            pass


    