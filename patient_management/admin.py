from django.contrib import admin
from patient_management import models

# Register your models here.

admin.site.register([
    models.User,
    models.Organization,
    models.OrganizationImage
])