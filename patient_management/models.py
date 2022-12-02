
from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager)
from datetime import datetime, timezone

from django.core.exceptions import ValidationError
from .validator import validate_file_size
# Create your models here.



class UserManager(BaseUserManager):

    def create_org(self,username,name,description,location,contactDetails,password, type=None):
        if not username:
            raise ValueError("Org must have an username")
        if not description:
            raise ValueError("Org must have a description")
        if not location:
            raise ValueError("Org must have a location")
        if not contactDetails:
            raise ValueError("Org must have a contactDetails")
        


        if not name:
            raise ValueError("Org must have a name")
        if not password:
            raise ValueError("Org must have a password")

    
        org = self.model(
            username=username,
            orgName=name
            )
        if type == "r":
            org.type = 'r'
        elif type == "t":
            org.type = 't'
        elif type == "i":
            org.type = 'i'
        else:#default 
            org.type = 'r'
        org.isUser = False
        org.is_active = True
    
        org.set_password(password)
        org.description = description
        org.location = location
        org.contactDetails = contactDetails
    
        # user = self.create(username = username, name = name, email = email, password = password)
        org.save(using=self._db)
        return org

    def create_user(self,username,name,email,password,type=None):
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
        if type == "p":
            user.type = 'p'
        elif type == "h":
            user.type = 'h'
        else :
            user.type = 'p'
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
        user.approved = True
        user.is_active = True
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
        ('a', 'admin'),
        ('r','pharmacy'),
        ('t', 'hospital'),
        ('i', 'insurance firms')
    )
    username = models.CharField(max_length = 50, unique = True,primary_key = True)
    name = models.CharField(max_length = 150,blank=True,null=True)
    orgName = models.CharField(max_length = 150,blank=True, null=True)
    email = models.EmailField(max_length = 100,blank=True,null=True)
    password = models.CharField(max_length = 100)
    is_admin = models.BooleanField(default = False)
    is_staff = models.BooleanField(default = False)
    is_active = models.BooleanField(default = False)
    is_superuser = models.BooleanField(default = False)
    banned = models.BooleanField(default = False)
    approved = models.BooleanField(default = False)
    isUser = models.BooleanField(default=True)
    type = models.CharField(max_length = 1, choices = TYPE_OF_USER, default = 'p')
    description = models.CharField(max_length = 1000, blank=True, null=True)
    location = models.CharField(max_length = 250, blank=True, null=True)
    contactDetails = models.CharField(max_length = 10, blank=True, null=True)
    objects = UserManager()
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email','password','name']


    def __str__(self):
        return self.name
        
    def has_perm(self, perm, obj=None):
        return self.is_admin
    
    def has_module_perms(self, app_label):
        return True
    
    # def clean(self):
    #     if (self.name is not None) and (not self.name.isalnum()):
    #         raise ValidationError("name are incorrect")
    #     elif (self.orgName is not None) and (not self.orgName.isalnum()):
    #         raise ValidationError("orgName are incorrect")
    #     elif (self.description is not None) and (not self.description.isalnum()):
    #         raise ValidationError("description are incorrect")
    #     elif (self.location is not None) and (not self.location.isalnum()):
    #         raise ValidationError("location are incorrect")
    #     elif (self.contactDetails is not None) and (not self.contactDetails.isalnum()):
    #         raise ValidationError("contactDetails are incorrect")
    #     elif (self.username is None) and (not self.username.isalnum()):
    #         raise ValidationError("username are incorrect")
        


class Product(models.Model):
    name = models.CharField(max_length=191)
    price = models.DecimalField(max_digits=7, decimal_places=2)
    slug = models.SlugField()
    by = models.ForeignKey('User',on_delete = models.CASCADE)
    description = models.TextField()
    image = models.ImageField(upload_to='images/', blank=True)
    USERNAME_FIELD = 'name'
    def __str__(self):
        return self.name

class File(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    title = models.CharField(max_length=250)
    description = models.TextField(blank=True, null=True)
    file_path = models.FileField(upload_to='documents/',blank=True, null=True,validators=[validate_file_size])
    date_created = models.DateTimeField(default=datetime.now)
    date_updated = models.DateTimeField(auto_now=True)
    share = models.ManyToManyField('User',blank=True,related_name="SharedUsers")
    verified = models.BooleanField(default=False)
    cipher = models.FileField(upload_to='documents/', blank = True, null = True,validators=[validate_file_size])
    def __str__(self):
        return self.user.username + '-' + self.title

class HCPDocument(models.Model):
    user = models.ForeignKey('User',on_delete = models.CASCADE)
    identity_proof = models.FileField(upload_to='documents/',validators=[validate_file_size]) 
    license_proof = models.FileField(upload_to='documents/',validators=[validate_file_size])
    

class PDocument(models.Model):
    user = models.ForeignKey('User',on_delete = models.CASCADE)
    identity_proof = models.FileField(upload_to='documents/',validators=[validate_file_size]) 
    


# class Organization(AbstractBaseUser):
#     TYPE_OF_ORG = (
#         ('p','pharmacy'),
#         ('h', 'hospital'),
#         ('i', 'insurance firms')
#     )
#     username = models.CharField(max_length = 150,unique = True, primary_key = True)
#     description = models.CharField(max_length = 1000)
#     location = models.CharField(max_length = 250)
#     contactDetails = models.CharField(max_length = 10)
    
#     password = models.CharField(max_length = 100)
#     banned = models.BooleanField(default=False)
#     approved = models.BooleanField(default=False)
#     USERNAME_FIELD = 'username'
#     REQUIRED_FIELDS = ['description','contactDetails','location','password']
#     type = models.CharField(max_length = 1, choices = TYPE_OF_ORG)
#     def __str__(self):
#         return self.name

#     def has_perm(self, perm, obj=None):
#         return self.is_admin
    
#     def has_module_perms(self, app_label):
#         return True

class OrganizationImage(models.Model):
    organization = models.ForeignKey('User',on_delete = models.CASCADE)
    image = models.ImageField(upload_to='images/',validators=[validate_file_size]) 


class CartItem(models.Model):
    cart_id = models.CharField(max_length=50)
    price = models.DecimalField(max_digits=7, decimal_places=2)
    quantity = models.IntegerField()
    date_added = models.DateTimeField(auto_now_add=True)
    product = models.ForeignKey(Product, on_delete=models.PROTECT)

    def __str__(self):
        return "{}:{}".format(self.product.name, self.id)

    def update_quantity(self, quantity):
        self.quantity = self.quantity + quantity
        self.save()

    def total_cost(self):
        return self.quantity * self.price


class Order(models.Model):
    name = models.CharField(max_length=191)
    email = models.EmailField()
    postal_code = models.IntegerField()
    address = models.CharField(max_length=191)
    date = models.DateTimeField(auto_now_add=True)
    paid = models.BooleanField(default=False)

    def __str__(self):
        return "{}:{}".format(self.id, self.email)

    def total_cost(self):
        return sum([ li.cost() for li in self.lineitem_set.all() ] )


class Tokens(models.Model):
    token = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    expire = models.PositiveBigIntegerField()
    used = models.BooleanField(default=False)

# class InsuranceClaim(models.Model):
#     by = models.ForeignKey('User',on_delete = models.CASCADE,related_name='UserBy')
#     to = models.ForeignKey('User',on_delete = models.CASCADE, related_name='UserTo')
#     appproved = models.BooleanField(default=False)
#     rejected = models.BooleanField(default=False)
#     file = models.ForeignKey('File', on_delete=models.CASCADE,related_name="claimfile")

class PharmacyOrder(models.Model):
    by = models.ForeignKey('User',on_delete = models.CASCADE, related_name='PhUserBy')
    to = models.ForeignKey('User', on_delete=models.CASCADE,  related_name='PhUserTo')
    appproved = models.BooleanField(default=False)
    rejected = models.BooleanField(default=False)



class LineItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=7, decimal_places=2)
    quantity = models.IntegerField()
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{}:{}".format(self.product.name, self.id)

    def cost(self):
        return self.price * self.quantity