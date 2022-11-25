"""
WSGI config for fcs_project project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/howto/deployment/wsgi/
"""


import os, sys
sys.path.append('/mnt/sdb2/Study_Material/Project/Patient-Data-Management-System/fcs_project/')

sys.path.append('/mnt/sdb2/Study_Material/Project/Patient-Data-Management-System/fcs_project/core/')
sys.path.append('/mnt/sdb2/Study_Material/Project/Patient-Data-Management-System/fcsproject/lib/python3.10/site-packages')

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fcs_project.settings')

application = get_wsgi_application()
