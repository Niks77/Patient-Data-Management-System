from distutils.command.upload import upload
import email
from enum import unique
from secrets import choice
from unittest.util import _MAX_LENGTH
from django.db import models

# Create your models here.

class User(models.Model):
    TYPE_OF_USER = (
        ('p','patient'),
        ('h', 'health care professionals'),
        ('a', 'admin')
    )
    username = models.CharField(max_length = 50, unique = True)
    name = models.CharField(max_length = 150)
    email = models.EmailField(max_length = 100, unique = True, primary_key = True)
    password = models.CharField(max_length = 100)
    is_admin = models.BooleanField()
    banned = models.BooleanField()
    approved = models.BooleanField()
    type = models.CharField(max_length = 1, choices = TYPE_OF_USER)
    @classmethod
    def create_user(cls,username,name,email,password):
        user = cls(username = username, name = name, email = email, password = password)
        return user

    def __str__(self):
        return self.name
        
class HCPDocument(models.Model):
    organization = models.ForeignKey('User',on_delete = models.CASCADE)
    identity_proof = models.FileField(upload_to='documents/') 
    license_proof = models.FileField(upload_to='documents/')

class PDocument(models.Model):
    organization = models.ForeignKey('User',on_delete = models.CASCADE)
    identity_proof = models.FileField(upload_to='documents/') 

class Organization(models.Model):
    TYPE_OF_ORG = (
        ('p','pharmacy'),
        ('h', 'hospital'),
        ('i', 'insurance firms')
    )
    name = models.CharField(max_length = 150,unique = True, primary_key = True)
    description = models.CharField(max_length = 1000)
    location = models.CharField(max_length = 250)
    contactDetails = models.CharField(max_length = 10)
    banned = models.BooleanField()
    approved = models.BooleanField()
    type = models.CharField(max_length = 1, choices = TYPE_OF_ORG)
    def __str__(self):
        return self.name
class OrganizationImage(models.Model):
    organization = models.ForeignKey('Organization',on_delete = models.CASCADE)
    image = models.ImageField(upload_to='images/') 
