# Generated by Django 4.1.2 on 2022-11-02 13:14

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('username', models.CharField(max_length=50, primary_key=True, serialize=False, unique=True)),
                ('name', models.CharField(max_length=150)),
                ('email', models.EmailField(max_length=100, unique=True)),
                ('password', models.CharField(max_length=100)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('is_superuser', models.BooleanField(default=False)),
                ('banned', models.BooleanField(default=False)),
                ('approved', models.BooleanField(default=False)),
                ('type', models.CharField(choices=[('p', 'patient'), ('h', 'health care professionals'), ('a', 'admin')], default='p', max_length=1)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('name', models.CharField(max_length=150, primary_key=True, serialize=False, unique=True)),
                ('description', models.CharField(max_length=1000)),
                ('location', models.CharField(max_length=250)),
                ('contactDetails', models.CharField(max_length=10)),
                ('banned', models.BooleanField()),
                ('approved', models.BooleanField()),
                ('type', models.CharField(choices=[('p', 'pharmacy'), ('h', 'hospital'), ('i', 'insurance firms')], max_length=1)),
            ],
        ),
        migrations.CreateModel(
            name='PDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('identity_proof', models.FileField(upload_to='documents/')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='OrganizationImage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(upload_to='images/')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='patient_management.organization')),
            ],
        ),
        migrations.CreateModel(
            name='HCPDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('identity_proof', models.FileField(upload_to='documents/')),
                ('license_proof', models.FileField(upload_to='documents/')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=250)),
                ('description', models.TextField(blank=True, null=True)),
                ('file_path', models.FileField(blank=True, null=True, upload_to='documents/')),
                ('date_created', models.DateTimeField(default=datetime.datetime.now)),
                ('date_updated', models.DateTimeField(auto_now=True)),
                ('cipher', models.CharField(blank=True, max_length=1000, null=True)),
                ('share', models.ManyToManyField(blank=True, related_name='SharedUsers', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
