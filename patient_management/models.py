
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

# Create your models here.
class UserManager(BaseUserManager):
    def create_user(self,username,type,name,email,password):
        if not email:
            raise ValueError("User must have an email")
        if not username:
            raise ValueError("User must have a username")
        if not name:
            raise ValueError("User must have a name")
        if not password:
            raise ValueError("User must have a password")
        user = self.model(
            email=self.normalize_email(email),
            username = username)
        if type == "Patient":
            user.type = 'p'
        elif type == "Healthcare Professional":
            user.type = 'h'
        user.set_password(password)
        user.name = name
        # user = self.create(username = username, name = name, email = email, password = password)
        user.save(using=self._db)
        return user

    def create_superuser(self,username,name,email,password):
        if not email:
            raise ValueError("User must have an email")
        if not username:
            raise ValueError("User must have a username")
        if not name:
            raise ValueError("User must have a name")
        if not password:
            raise ValueError("User must have a password")
        user = self.create_user(
            email=self.normalize_email(email),
            username = username,
            name = name ,
            password=password)
        user.name = name
        user.type = 'a'
        user.approved = True
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True 
        # user = self.create(username = username, name = name, email = email, password = password)
        user.save(using=self._db)
        return user
    

class User(AbstractBaseUser):
    TYPE_OF_USER = (
        ('p','patient'),
        ('h', 'health care professionals'),
        ('a', 'admin')
    )
    username = models.CharField(max_length = 50, unique = True,primary_key = True)
    name = models.CharField(max_length = 150)
    email = models.EmailField(max_length = 100, unique = True)
    password = models.CharField(max_length = 100)
    is_admin = models.BooleanField(default = False)
    is_staff = models.BooleanField(default = False)
    is_active = models.BooleanField(default = True)
    is_superuser = models.BooleanField(default = False)
    banned = models.BooleanField(default = False)
    approved = models.BooleanField(default = False)
    type = models.CharField(max_length = 1, choices = TYPE_OF_USER, default = 'p')
    objects = UserManager()
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email','password','name']


    def __str__(self):
        return self.name
        
    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True


class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=250)
    description = models.TextField(blank=True, null=True)
    file_path = models.FileField(upload_to='uploads/',blank=True, null=True)
    date_created = models.DateTimeField(default=timezone.now)
    date_updated = models.DateTimeField(auto_now=True)
    share = models.ManyToManyField('User', blank=True,
                                   related_name="SharedUsers")
    def __str__(self):
        return self.user.username + '-' + self.title

class HCPDocument(models.Model):
    user = models.ForeignKey('User',on_delete = models.CASCADE)
    identity_proof = models.FileField(upload_to='documents/') 
    license_proof = models.FileField(upload_to='documents/')

class PDocument(models.Model):
    user = models.ForeignKey('User',on_delete = models.CASCADE)
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
