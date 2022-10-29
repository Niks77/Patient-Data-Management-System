from django.contrib import admin
from patient_management import models
from django.contrib.auth.admin import UserAdmin
# Register your models here.

class UserAdmin(UserAdmin):
    list_display = ('email','username','last_login','is_admin', 'is_staff','is_superuser',
    'banned' , 'approved', 'password')
    search_fields = ('email', 'username')
    # readonly_fields = ('last_login')

    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
admin.site.register(models.User,UserAdmin)