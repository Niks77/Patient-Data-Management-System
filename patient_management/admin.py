from django.contrib import admin
from patient_management import models
from django.contrib.auth.admin import UserAdmin
from django.contrib.admin import ModelAdmin

# Register your models here.

class UsersAdmin(UserAdmin):
    list_display = ('email','username','last_login','is_admin', 'is_staff','is_superuser',
    'banned' , 'approved', 'password')
    search_fields = ('email', 'username')
    # readonly_fields = ('last_login')

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password', 'is_admin'),
        }),
    )
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
# class OrgAdmin(UserAdmin):
#     list_display = ('username','password','description','location','contactDetails', 'banned','approved',
#     'type')
#     search_fields = ('username',)
#     # readonly_fields = ('last_login')

#     add_fieldsets = (
#         (None, {
#             'classes': ('wide',),
#             'fields': ('username','description','location','contactDetails', 'banned','approved',
#     'type'),
#         }),
#     )
#     filter_horizontal = ()
#     list_filter = ()
#     fieldsets = ()
#     ordering = ('username',)

class ProductAdmin(ModelAdmin):
    list_display = ('name','price','slug','by', 'description','image')
    search_fields = ('name',)
    # readonly_fields = ('last_login')

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('name','price','slug','by', 'description','image'),
        }),
    )
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
    ordering = ('name',)

class FileAdmin(ModelAdmin):
    list_display = ('user','title','description','file_path', 'date_created','date_updated',
    'cipher')
    search_fields = ('title',)
    # readonly_fields = ('last_login')

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('user','name','price','slug','by', 'description','image'),
        }),
    )
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
    ordering = ('title',)

class HCPDocumentAdmin(ModelAdmin):
    list_display = ('user','identity_proof','license_proof')
    search_fields = ('user',)
    # readonly_fields = ('last_login')

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('user','identity_proof','license_proof'),
        }),
    )
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
    ordering = ('user',)

class PDocumentAdmin(ModelAdmin):
    list_display = ('user','identity_proof')
    search_fields = ('user',)
    # readonly_fields = ('last_login')

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('user','identity_proof'),
        }),
    )
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
    ordering = ('user',)

admin.site.register(models.User,UsersAdmin)
# admin.site.register(models.Organization,OrgAdmin)
admin.site.register(models.Product,ProductAdmin)

admin.site.register(models.File,FileAdmin)

admin.site.register(models.HCPDocument,HCPDocumentAdmin)

admin.site.register(models.PDocument,PDocumentAdmin)
