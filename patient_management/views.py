
import re
from fcs_project import settings
from  gmpy2 import mpz
from django.shortcuts import HttpResponse, redirect, render,get_object_or_404, reverse
from patient_management.models import  User , PDocument, OrganizationImage, HCPDocument , File, Product, Order, LineItem, Tokens
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import check_password
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, send_mail
from django.views.decorators.csrf import csrf_exempt
from paypal.standard.forms import PayPalPaymentsForm
from .forms import CartForm, CheckoutForm, FormWithCaptcha,SignupForm
from . import cart
import requests
import datetime
import html
import random
from django.core.files import File as file
from decimal import Decimal
from patient_management.certificate import (verifyfile, generate_key) 
from . tokens import generate_token
from ratelimit.decorators import ratelimit
# Create your views here.


def validate_password(password):

        special_symbols =['$', '@', '#', '%']
        
        
        if len(password) < 6:
                print('Password must have atleast 6 characters.')
                return False
                    
        if len(password) > 20:
                # print('Password cannot have more than 20 characters.')
                return False
        
        if not any(characters.isdigit() for characters in password):
                # print('Password must have at least one numeric character.')
                return False
                
   
        if not any(characters.isupper() for characters in password):
                # print('Password must have at least one uppercase character')
                return False
        
  
        if not any(characters.islower() for characters in password):
                # print('Password must have at least one lowercase character')
                return False
                   
        if not any(characters in special_symbols for characters in password):
                # print('Password should have at least one of the symbols $@#%')
                return False
        else:
            return True
def is_ascii(s):
    try: 
        return all(ord(c) < 128 for c in s)
    except:
        return False
        
def validateinput(s, length):
    return len(s) > length or not is_ascii(s)

def signupOrg(request):
    if request.method == "POST":
        username = request.POST.get('username')
        name = request.POST.get('orgName')
        description = request.POST.get('description')
        location = request.POST.get('location')
        password = request.POST.get('password')
        password1 = request.POST.get('password1')
        contactDetails = request.POST.get('contactDetails')
        type = request.POST.get('type')
        captchaForm = FormWithCaptcha(request.POST)
        if not captchaForm.is_valid():
            messages.error(request, "Invalid captcha")
            return redirect('signin') 
        else:
            pass
        try:
            image1 = request.FILES['image1']
        except:
            image1 = None
     
        try:
            image2 = request.FILES['image2']
        except:
            image2 =  None
        # print("type ",type)
        if type is None:
            messages.error("Please select Organization type")
            return redirect('signupOrg')
        if username is None:
            messages.error(request, "Organization should have username")
            return redirect('signupOrg')
        if name is None:
            messages.error(request, "Organization should have name")
            return redirect('signupOrg')
        if description is None:
            messages.error(request, "Organization should have description")
            return redirect('signupOrg')
        if location is None:
            messages.error(request, "Organization should have location")
            return redirect('signupOrg')
        if contactDetails is None:
            messages.error(request, "Organization should have contactDetails")
            return redirect('signupOrg')
        if validateinput(username,50):
            messages.error(request, "Organization should have username")
            return redirect('signupOrg')
        if validateinput(name,50):
            messages.error(request, "Organization should have name")
            return redirect('signupOrg')
        if validateinput(description,100):
            messages.error(request, "Organization should have description")
            return redirect('signupOrg')
        if validateinput(location,250):
            messages.error(request, "Organization should have contactDetails")
            return redirect('signupOrg')
        if validateinput(location,10):
            messages.error(contactDetails, "Organization should have contactDetails")
            return redirect('signupOrg')
        username = html.escape(username)
        name = html.escape(name)
        description = html.escape(description)
        # description = request.POST.get('description')
        location = html.escape(location)
        contactDetails = html.escape(contactDetails)
        type = html.escape(type)
        
        if User.objects.filter(username=username):
            messages.error(request, "Organization username already exist! Please try some other username.")
            return redirect('signupOrg')
        if User.objects.filter(orgName=name):
            messages.error(request, "Organization name already exist! Please try some other name.")
            return redirect('signupOrg')
        if type == None:
            messages.error(request, "Please select organization type")
            return redirect('signupOrg')
        if (type != "r") and (type != "t") and (type != "i"):
            messages.error(request, "Please select valid user type")
            return redirect('signupOrg')
        if image1 == None:
            messages.error(request,"Image 1 is compulsory")
            return redirect('signupOrg')
        if image2 == None:
            messages.error(request,"Image 2 is compulsory")
            return redirect('signupOrg')
        if password != password1:
            messages.error(request, "Passwords didn't matched!!")
            return redirect('signupOrg')

        if not username.isalnum():
            messages.error(request, "Organization must be Alpha-Numeric!!")
            return redirect('signupOrg')

        if not validate_password(password=password):
            messages.error(request, "Enter Strong password")
            return redirect('signupOrg')
    
        myuser = User.objects.create_org(username,name,description,location,contactDetails,password,type)
 
        try:
            doc = OrganizationImage(organization=myuser,image=image1)
            doc.save()
            doc1 = OrganizationImage(organization=myuser,image=image2)
            doc1.save()
        except:
            myuser.delete()
            messages.error(request, "Unknown error occured")
            return redirect('signupOrg')
        messages.success(request, "Your Account has been created succesfully")
        return redirect('signin')
    captchaForm = FormWithCaptcha()

    return render(request,"patient_management/signupOrg.html",{
        'form':captchaForm,
    })


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def home(request):
    if request.method == "GET":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else: 
            user = request.user
            if user == None:
                messages.error(request, "Session expired")
                return redirect('signin')
            else:
                if user.type == 't':
                    return redirect('sharefilehospital')
                if user.type == 'h':
                    return redirect('sharefilehospital')
        all_products = Product.objects.all()
        current_site = get_current_site(request)
    
        return render(request,"patient_management/Productcard.html",{
                                    'all_products': all_products,
                                    'urls' : current_site
                                    })
    else:
        return HttpResponse("Not found")


@ratelimit(key='ip', rate='100/h', block=True)
def signup(request):
    if request.method == "POST":
        sigupForm= SignupForm(request.POST)
        if sigupForm.is_valid():
            cleanData = sigupForm.cleaned_data
            username = cleanData.get('username')
            name = cleanData.get('name')
            email = cleanData.get('email')
            password = cleanData.get('password')
            password1 = cleanData.get('password1')
            # captchaForm = FormWithCaptcha(request.POST)
            type = request.POST.get('type')
            try:
                license = request.FILES['license']
            except:
                license = None
        
            try:
                identity = request.FILES['identity']
            except:
                identity =  None
            try: 
                name = html.escape(name)
                username = html.escape(username)
            # description = request.POST.get('description')
                type = html.escape(type)
            except:
                name = None
                username = None
            # description = request.POST.get('description')
                # location = None
                # contactDetails = None
                type = None
                
            if type is None:
                messages.error(request, "Please select valid user type")
                return redirect('signup')
            if name is None:
                messages.error(request, "Please select enter valid name")
                return redirect('signup')
            if username is None:
                messages.error(request, "Please select enter valid username")
                return redirect('signup')
            if (type != "p") and (type != "h"):
                messages.error(request, "Please select valid user type")
                return redirect('signup')
            if User.objects.filter(email=email).exists():
                messages.error(request, "Email Already Registered!!")
                return redirect('signup')
            if type == "h" and license == None:
                messages.error(request,"License document is compulsory")
                return redirect('signup')
            if password != password1:
                messages.error(request, "Passwords didn't matched!!")
                return redirect('signup')
            if username is None:
                messages.error(request, "Enter proper username")
                return redirect('signup')
            if not username.isalnum():
                messages.error(request, "Username must be Alpha-Numeric!!")
                return redirect('signup')
            if not validate_password(password=password):
                messages.error(request, "Enter Strong password")
                return redirect('signup')
            # print("hii")
            myuser = User.objects.create_user(username,name,email,password,type)
            if(type == "p"):
                try:
                    doc = PDocument(user = myuser,identity_proof = identity)
                    doc.save()
                except:
                    myuser.delete()
                    messages.error(request, "Unknown error occured")
                    return redirect('signup')
            elif(type == "h"):
                try:
                    doc = HCPDocument(user = myuser,identity_proof = identity, license_proof= license)
                    doc.save()
                except:
                    myuser.delete()
                    messages.error(request, "Unknown error occured")
                    return redirect('signup')

        
            messages.success(request, "Your Account has been created succesfully!! Please check your email to confirm your email address in order to activate your account.")
            current_site = get_current_site(request)
            email_subject = "Confirm your Email Django Login!!"
            message2 = render_to_string('patient_management/email_confirmation.html',{
                
                'name': myuser.name,
                'domain': current_site.domain,
                'username':(myuser.username),
                'token': generate_token.make_token(myuser)
            })
            email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
            )
            email.fail_silently = True
            email.send()
            
            return redirect('signin')
        else:
            # print(sigupForm.errors)

            messages.error(request,"Error occured")
            return redirect('signup')
    
    captchaForm = FormWithCaptcha()

    return render(request,"patient_management/signup.html",{
        'form':captchaForm,
    })

@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def editProfile(request):
    if request.method == "POST":
        user = request.user
        if user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
       
        try:
            fname = request.POST.get('fname')
            fname = html.escape(fname)
            user.name = fname
            user.save()
        except:
            messages.error('Something went wrong')
            return redirect('home')
        messages.success(request, "Your account name has been changed successfully")
        return redirect('home')

    return render(request,"patient_management/signup.html")

@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def search(request):
    
	if request.method == "POST":
		query = request.POST.get("q",None)
		type = request.POST.get("type",None)
		if type is None:
			messages.error(request,"Search type is required")
			return redirect("home")
		if type == "name":
			if query is not None:
				hsp = User.objects.filter(
					type = 'h',
					name__contains=query
					) 
				pharma = User.objects.filter(
					type = 'r',
					orgName__contains=query
					) 
				hospital = User.objects.filter(
					type = 't',
					orgName__contains=query
					) 
				insuranceFirm = User.objects.filter(
					type = 'i',
					orgName__contains=query
					) 
				return render(request,"patient_management/index.html", {"data":
					{"hsp":hsp,
					"pharma":pharma,
					"hospital":hospital,
					"insuranceFirm":insuranceFirm
					}
					})
		elif type == "type":
				
			if query is not None:
					
				if query == "health care professionals":
					type_of_user = 'h'
					hsp = User.objects.filter(
					type=type_of_user) 
						
					return render(request,"patient_management/index.html", {"data":{"hsp":hsp}})
				if query == "pharmacy":
					
					type_of_user = 'r'
                                        
					user = User.objects.filter(
					type=type_of_user) 
					# print(user)
					return render(request,"patient_management/index.html", {"data":{"pharma":user}})
				elif query == "hospital":
					type_of_user = 't'
					user = User.objects.filter(
					type=type_of_user) 
					return render(request,"patient_management/index.html", {"data":{"hospital":user}})
				elif query == "insurance firms":
					type_of_user = 'i'
					user = User.objects.filter(
					type=type_of_user) 
					return render(request,"patient_management/index.html", {"data":{"insuranceFirm":user}})
				else: 
					type_of_user = 'h'
					hsp = User.objects.filter(
					type=type_of_user) 
						
					return render(request,"patient_management/index.html", {"data":{"hsp":hsp}})
				
		elif type == "location":
			if query is not None:
				hsp = User.objects.filter(
					type = 'h',
					location__contains=query
					) 
				pharma = User.objects.filter(
					type = 'r',
					location__contains=query
					) 
				hospital = User.objects.filter(
					type = 't',
					location__contains=query
					) 
				insuranceFirm = User.objects.filter(
					type = 'i',
					location__contains=query
					) 
			
				return render(request,"patient_management/index.html", {"data":
					{"hsp":hsp,
					"pharma":pharma,
					"hospital":hospital,
					"insuranceFirm":insuranceFirm
					}
					})
		else:
			if query is not None:
				hsp = User.objects.filter(
					type = 'h',
					name__contains=query
					) 
				pharma = User.objects.filter(
					type = 'r',
					name__contains=query
					) 
				hospital = User.objects.filter(
					type = 't',
					name__contains=query
					) 
				insuranceFirm = User.objects.filter(
					type = 'i',
					name__contains=query
					) 
				return render(request,"patient_management/index.html", {"data":
					{"hsp":hsp,
					"pharma":pharma,
					"hospital":hospital,
					"insuranceFirm":insuranceFirm
					}
					})
    
	return render(request,"patient_management/index.html")
    
        

@ratelimit(key='ip', rate='100/h', block=True)
def forgotpassword(request):
    logout(request)
    if request.method == "POST":
        username = request.POST.get('username')
        if username is not None:
            username = html.escape(username)
        try:
            myuser = User.objects.get(username = username)
        except (TypeError,ValueError,OverflowError,User.DoesNotExist):
            myuser = None

        if myuser is not None:
            if not myuser.isUser:
                messages.error(request,"organization are  not able to reset password")
                return redirect('home')
            current_site = get_current_site(request)
            gen_token = generate_token.make_token(myuser)
            email_subject = "Forgot password for Patient FCS IIITD !!"
            message2 = render_to_string('patient_management/forgot_password.html',{ 
                'name': myuser.name,
                'domain': current_site.domain,
                'username':(myuser.username),
                'token': gen_token
            })
            email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
            )
            email.fail_silently = True
            email.send()
            alreadyExist = Tokens.objects.filter(token=gen_token)
            # print(alreadyExist)
            # print("hoo")
            if not alreadyExist.exists():
                try:
                    # print("hoo1")
                    date = (datetime.datetime.now() + datetime.timedelta(seconds=300)).timestamp()
                    # print(type(date))
                    tokenobj =Tokens(token = gen_token,username = myuser.username,expire=round(date))
                    # print('date')
                    tokenobj.save()
                    # print('save')
                except Exception as e:
                    print(e)
                    messages.error(request,"Something went wrong")
                    return redirect('home')
            else:
                messages.error(request,"token already exists")
                return redirect('home')
            messages.success(request, "Your Have request for password , please check mail for verfication")
            
        return redirect('home')
    return render(request,"patient_management/forgot_pass.html")


@ratelimit(key='ip', rate='100/h', block=True)
def reset(request,username,token):
    if request.method == "POST":
        if username == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else: 
            try:
                tokenobj = Tokens.objects.get(token=token)
            except:
                tokenobj = None

            try:
                user = User.objects.get(username=username)
            except:
                user = None
            if tokenobj == None:
                messages.error(request, "token doesnt exists")
                return redirect('signin')
            if user  == None:
                messages.error(request, "user doesnt exists")
                return redirect('signin')
            if tokenobj.expire <= round(datetime.datetime.now().timestamp()):
                messages.error("Token is valid for 5 mins")
                return redirect('sigin')
            else:
                if tokenobj.used == True:
                    messages.error(request, "Token already used")
                    return redirect('signin')
                if tokenobj.username != username:
                    messages.error(request, "Invalid Token")
                    return redirect('signin')
                new_password = request.POST.get('newpassword')
                confirm_password = request.POST.get('confirmpassword')
    
                if new_password != confirm_password:
                    messages.error(request, "New password and confirm password are not same")
                    return redirect('reset')
                
                else:
                    tokenobj.used = True
                    tokenobj.save()
                    user.set_password(new_password)
                    user.save()
                    messages.success(request, "Password has been successfully changed")
     
                    return redirect('home')
    # print("hii")
    try:
        myuser = User.objects.get(username = username)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None
    # print("hii1")
    try:
        tokenobj = Tokens.objects.get(token=token)
    except:
        tokenobj = None
    # print("hii2")
    if tokenobj is None:
        messages.error(request, "Token not found or expired")
        return render(request,'patient_management/activation_failed.html')

    print(type(tokenobj.expire))
    if tokenobj.expire <= round(datetime.datetime.now().timestamp()):
        messages.error(request,"Token is valid for 5 mins")
        return redirect('signin')
    if myuser is not None and generate_token.check_token(myuser,token):
        #  todo check if token already exists
        alreadyExist = Tokens.objects.filter(token=token)
        if alreadyExist is not None:
            messages.success(request, "You can change the password!!")
            return render(request,"patient_management/resetpassword.html", {
                'token':token,
                'username':username,
            })  
        else:
            messages.error(request, "Token not found or expired")
            return render(request,'patient_management/activation_failed.html')
    else:
        return render(request,'patient_management/activation_failed.html')



@ratelimit(key='ip', rate='100/h', block=True)
def activate(request,username,token):
    try:
        myuser = User.objects.get(username = username)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        myuser.save()
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request,'patient_management/activation_failed.html')


@ratelimit(key='ip', rate='100/h', block=True) 
def removeshare(request):
    if request.method == "POST":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else:  
            user = request.user

            if user == None:
                messages.error(request, "Session expired")
                return redirect('your_docs')
            else:
                share_username = request.POST.get('share_username')
                filepk = request.POST.get('filekey')
                if share_username is not None:
                    share_username = html.escape(share_username)
                if filepk is not None:
                    filepk = html.escape(filepk)
                try:
                    share_user = User.objects.get(username = share_username)
                except:
                    share_user = None
                # print(share_user)
                if filepk is None:
                    messages.error(request,"File key doesnt exists")
                    return redirect('sharefile')
                if share_user is None:
                    messages.error(request,"User doesnt exists")
                    return redirect('sharefile')
                if share_username == user.username:
                    messages.error(request,"You cannot revoke share with yourself")
                    return redirect('sharefile')
                if share_user.banned:
                    messages.error(request,"share user is banned, hence this operation is not possible")
                    return redirect('sharefile')
                if not share_user.approved:
                    messages.error(request,"share user is not approved to use platform")
                    return redirect('sharefile')
                try:
                    fileObj = File.objects.get(pk=filepk)
                except:
                    fileObj = None
                if fileObj is None:
                    messages.error(request,"something went wrong")
                    return redirect('sharefile')
                if fileObj.user.username != user.username:
                    messages.error(request, "your are not owner of the file")
                    return redirect('sharefile')
                
                try:
                    fileObj.share.remove(share_user)
                    fileObj.save()
                    messages.success(request,"successfully revoked shared access with user:" + str(share_user.username))
                    return redirect('your_docs')
                except:
                    messages.error(request,"unknown error occured")
                    return redirect('sharefiles')

    return HttpResponse("Not allowed")


@ratelimit(key='ip', rate='100/h', block=True)
def load_dropdown(request):
     type = request.GET.get('type')
  
     return render(request, 'patient_management/fileupload.html', {'type': type})


@ratelimit(key='ip', rate='10/h', block=True)
@login_required(login_url='signin')
def verify(request) :
    if request.method == "POST":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else:  
            user = request.user
            pk = request.POST.get('file')
            # print(user)
            if  pk == None:
                messages.error(request, "File name is required")
                return redirect('verify')
            if user == None:
                messages.error(request, "Session expired")
                return redirect('signin')
            else:
                pk = html.escape(pk)
                try:
                    file = File.objects.get(pk=pk)
                except:
                    file = None
                if file is None:
                    messages.error(request,"File is missing or wrong request")
                    return redirect('verify')
                else:
                    if file.verified:
                        messages.success(request, "File is verified")
                        return redirect('verify')
                    if verifyfile(file.cipher,user.username,file.file_path):
                        file.verified = True
                        file.save()
                        messages.success(request, "File is verified")
                        return redirect('verify')

                    else :
                        messages.error(request, "File is not verified")
                        return redirect('verify')
    return redirect('home')



@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def delete(request) :
    if request.method == "POST":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else:  
            user = request.user
            pk = request.POST.get('file')

            try:
                user = html.escape(user)
                pk = html.escape(pk)
            except:
                user = None
                pk = None
                    
            if user == None:
                messages.error(request, "Session expired")
                return redirect('signin')

            if  pk == None:
                messages.error(request, "File name is required")
                return redirect('delete')
            else:
                
                try:
                    file = File.objects.get(pk=pk)
                except:
                    file = None
                if file is None:
                    messages.error(request,"File is missing or wrong request")
                    return redirect('your_docs')
                else:
                    if file.user == user:
                        file.delete()
                        messages.success(request,"File is deleted")
                        return redirect('your_docs')
                    messages.error(request,"you are not owner of the files cannot delete that !!")
                    return redirect('your_docs')
    return HttpResponse("Not allowed")

        


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def sharefile(request):
    # print("name" + request.user .username)
    if request.method == "POST":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('your_docs')
        else:  
            user = request.user

            if user == None:
                messages.error(request, "Session expired")
                return redirect('your_docs')
            else:
                share_username = request.POST.get('share_username')
                filepk = request.POST.get('filekey')

                if share_username is None:
                    if filepk is None:
                        messages.error(request,"File key doesnt exists")
                        return redirect('your_docs')
                    try:
                        
                        fileObj = File.objects.get(pk=filepk)
                    except:
                        fileObj = None
                    if fileObj is None:
                        messages.error(request,"No such file exists")
                        return redirect('your_docs')
                    if fileObj.user.username != user.username:
                        messages.error(request,"You are not file owner")
                        return redirect('your_docs')
                        # share_username = html.escape(share_username)
                    users = fileObj.share.all()
                    return  render(request,"patient_management/sharefile.html", {
                    'filekey' : filepk,
                    'users': users,
 
                    })         
                
                try:
                    share_username = html.escape(share_username)
                    share_user = User.objects.get(username = share_username)
                except:
                    share_user = None
                # print(share_user)
                if filepk is None:
                    messages.error(request,"File key doesnt exists")
                    return redirect('home')
                if share_user is None:
                    # print("hii")
                    messages.error(request,"User doesnt exists")
                    return redirect('home')
                if share_username == user.username:
                    messages.error(request,"You cannot share with yourself")
                    return redirect('home')
                if share_user.banned:
                    messages.error(request,"share user is banned")
                    return redirect('home')
                if not share_user.approved:
                    messages.error(request,"share user is not approved to use platform")
                    return redirect('home')
                try:
                    fileObj = File.objects.get(pk=filepk)
                except:
                    fileObj = None
                if fileObj is None:
                    messages.error(request,"something went wrong")
                    return redirect('sharefile')
                if fileObj.user.username != user.username:
                    messages.error(request, "your are not owner of the file")
                    return redirect('sharefile')
                

                fileObj.share.add(share_user)
                fileObj.save()
                messages.success(request,"files has successfully shared with user:" + str(share_user.username))
                return redirect('your_docs')
    return HttpResponse("Not allowed")
    # print(request.user)
     


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def upload_files_by_hospital(request):
    if request.method == "POST":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else:  
            user = request.user       
            if user == None:
                messages.error(request, "Session expired")
                return redirect('signin')
            elif user.type != 't' and user.type != 'h':
                return HttpResponse("Unauthorized access")
            else:
                title = request.POST.get('title')
                description = request.POST.get('description')
                try:
                    title = html.escape(title)
                    description = html.escape(description)
                except:
                    title = None
                    description =None
                try:
                    file_path = request.FILES['docs']
                except:
                    file_path = None

                share_username = request.POST.get('share_username')
                try:
                    share_user = User.objects.get(username = share_username)
                except:
                    share_user = None
                # print(share_user)
                if share_user is None:
                    messages.error(request,"User doesnt exists")
                    return redirect('sharefilehospital')
                if share_username == user.username:
                    messages.error(request,"You cannot share with yourself")
                    return redirect('sharefilehospital')
                if title is None:
                    messages.error(request,"title is required")
                    return redirect('sharefilehospital')
                if description is None:
                    messages.error(request,"description is required")
                    return redirect('sharefilehospital')
                if file_path is None:
                    messages.error(request,"file is needed to be upload")
                    return redirect('sharefilehospital')
                if share_user.banned:
                    messages.error(request,"share user is banned")
                    return redirect('sharefilehospital')
                if not share_user.approved:
                    messages.error(request,"share user is not approved to use platform")
                    return redirect('sharefilehospital')
                fileObj = File(user=share_user,title=title,description=description,file_path=file_path)
                fileObj.save()
                cipherpath = generate_key(share_username,fileObj.file_path.path)
                # print(cipherpath)
                if cipherpath != None:
                    try:
                        cipherfile = open(cipherpath)
                        djangocipherfile = file(cipherfile)
                        fileObj.cipher.save('new', djangocipherfile)
                        cipherfile.close()
                        fileObj.save()
                    except:
                        pass
                
                messages.success(request,"files has successfully shared with user:" + str(share_user.username))
                return redirect('home')
    user = request.user
    if user == None:
        messages.error(request, "Session expired")
        return redirect('signin')
    else:
        if user.type != 't' and user.type !='h':
            return HttpResponse("restricted access")
    return  render(request,"patient_management/indexHos.html")   


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def upload_files(request):
    if request.method == "POST":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else:  
            user = request.user

            if user == None:
                messages.error(request, "Session expired")
                return redirect('signin')
            else:
                title = request.POST.get('title')
                description = request.POST.get('description')
                try:
                    file_path = request.FILES['docs']
                except:
                    file_path = None

                try:
                    file_pathkey = request.FILES['docskey']
                except:
                    file_pathkey = None
                other_user_as_owner = request.POST.get('share_owner')
                share_username = request.POST.get('share_username')
                try:
                    share_user = User.objects.get(username = share_username)
                except:
                    share_user = None
                # print(share_user)
                if file_pathkey is None:
                    messages.error(request,"File path key doesnt exists")
                    return redirect('upload')
                if share_user is None:
                    messages.error(request,"User doesnt exists")
                    return redirect('upload')
                if share_username == user.username:
                    messages.error(request,"You cannot share with yourself")
                    return redirect('upload')
                if title is None:
                    messages.error(request,"title is required")
                    return redirect('upload')
                if description is None:
                    messages.error(request,"description is required")
                    return redirect('upload')
                if file_path is None:
                    messages.error(request,"file is needed to be upload")
                    return redirect('upload')
                if share_user.banned:
                    messages.error(request,"share user is banned")
                    return redirect('upload')
                if not share_user.approved:
                    messages.error(request,"share user is not approved to use platform")
                    return redirect('upload')
                if share_user.type == "p" or share_user.type == "a":
                    messages.error(request,"shared user cannot be another patient or admin")
                    return redirect('upload')
               
                try:
                    description = html.escape(description)
                    title = html.escape(title)
                    fileObj = File(user=user,title=title,description=description,file_path=file_path,cipher=file_pathkey)
                    fileObj.save()
                    fileObj.share.add(share_user)
                    fileObj.save()
                except:
                  pass  
                messages.success(request,"files has successfully shared with user:" + str(share_user.username))
                return redirect('upload')
    return  render(request,"patient_management/uploadfile.html")         


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def your_docs(request):
    if request.method == "GET":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else: 
            user = request.user
            if user == None:
                messages.error(request, "Session expired")
                return redirect('signin')
            else:
                files = user.file_set.all()
                return render(request,"patient_management/owndocs.html",{'files': files})
  

@ratelimit(key='ip', rate='100/h', block=True)  
@login_required(login_url='signin')
def shared_docs(request):
    if request.method == "GET":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else: 
            user = request.user
            if user == None:
                messages.error(request, "Session expired")
                return redirect('signin')
            else:
                files = File.objects.filter(share=user)
   
                return render(request,"patient_management/shareddocs.html",{'files': files})

@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def change_password(request):
    if request.method == "POST":
        if request.user == None:
            messages.error(request, "Session expired")
            return redirect('signin')
        else: 
            user = request.user
            if user == None:
                messages.error(request, "Session expired")
                return redirect('signin')
            else:
                old_password = request.POST.get('oldpassword')
                new_password = request.POST.get('newpassword')
                confirm_password = request.POST.get('confirmpassword')
                if old_password is None:
                    messages.error(request,"old password is empty")
                    return redirect('change_password')
                if not check_password(old_password,user.password):
                    messages.error(request, "You are entering wrong password")
                    return redirect('change_password')
                elif new_password != confirm_password:
                    messages.error(request, "New password and confirm password are not same")
                    return redirect('change_password')
                if not validate_password(password=new_password):
                    messages.error(request, "Enter Strong password")
                    return redirect('change_password')
                else:
                    user.set_password(new_password)
                    user.save()
                    messages.success(request, "Password has been successfully changed")
                    return redirect('home')

    return render(request,"patient_management/changepassword.html")  


@ratelimit(key='ip', rate='100/h', block=True)
def signin(request):
    if request.method == "POST":
        captchaForm = FormWithCaptcha(request.POST)
        if not captchaForm.is_valid():
            messages.error(request, "Invalid captcha")
            return redirect('signin') 
        password = request.POST.get('password')
        username = request.POST.get('username')
        # print(password + " "+ username)
        user = authenticate(username=username, password = password)
        # print(user)
        if user is None:
            messages.error(request, "Wrong username / password")
            return redirect('signin')
        if user.banned :
            messages.error(request, "Your account is suspended")
            return redirect('signin')
        if not user.approved:
            messages.error(request, "Your account is not been approved yet wait for admin's approval")
            return redirect('signin')
        if not user.is_active:
            messages.error(request, "Verify your email address first")
            return redirect('signin')
         
        login(request, user)
        return redirect('home')
        
    form = FormWithCaptcha()
    return render(request,"patient_management/Login.html", {
        'form':form
    })


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def signout(request):
    logout(request)
    return redirect('signin')


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def show_product(request, product_id, product_slug):
    product = get_object_or_404(Product, id=product_id)

    if request.method == 'POST':
        form = CartForm(request, request.POST)
        if form.is_valid():
            request.form_data = form.cleaned_data
            cart.add_item_to_cart(request)
            return redirect('show_cart')

    form = CartForm(request, initial={'product_id': product.id})
    return render(request, 'patient_management/product_detail.html', {
                                            'product': product,
                                            'form': form,
                                            })

@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def show_cart(request):

    if request.method == 'POST':
        if request.POST.get('submit') == 'Update':
            cart.update_item(request)
        if request.POST.get('submit') == 'Remove':
            cart.remove_item(request)

    cart_items = cart.get_all_cart_items(request)
    print(cart_items)
    cart_subtotal = cart.subtotal(request)
    print(cart_subtotal )
    return render(request, 'patient_management/cart.html', {
                                            'cart_items': cart_items,
                                            'cart_subtotal': cart_subtotal,
                                            })


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def process_payment(request):
    order_id = request.session.get('order_id')
    order = get_object_or_404(Order, id=order_id)
    host = request.get_host()

    paypal_dict = {
        'business': settings.PAYPAL_RECEIVER_EMAIL,
        'amount': '%.2f' % order.total_cost().quantize(
            Decimal('.01')),
        'item_name': 'Order {}'.format(order.id),
        'invoice': str(random.randint(1, 100000000)),
        'currency_code': 'USD',
        'notify_url': 'https://{}{}'.format("tiny-lemons-share-103-25-231-102.loca.lt",
                                           reverse('paypal-ipn')),
        'return_url': 'http://{}{}'.format(host,
                                           reverse('payment_done')),
        'cancel_return': 'http://{}{}'.format(host,
                                              reverse('payment_cancelled')),
    }

    form = PayPalPaymentsForm(initial=paypal_dict)
    return render(request, 'patient_management/process_payment.html', {'order': order, 'form': form})


@ratelimit(key='ip', rate='100/h', block=True)
@csrf_exempt
def payment_done(request):
    return render(request, 'patient_management/payment_done.html')


@ratelimit(key='ip', rate='100/h', block=True)
@csrf_exempt
def payment_canceled(request):
    return render(request, 'patient_management/payment_cancelled.html')


@ratelimit(key='ip', rate='100/h', block=True)
@login_required(login_url='signin')
def checkout(request):
    if request.method == 'POST':
        form = CheckoutForm(request.POST)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            o = Order(
                name = cleaned_data.get('name'),
                email = cleaned_data.get('email'),
                postal_code = cleaned_data.get('postal_code'),
                address = cleaned_data.get('address'),
            )
            o.save()

            all_items = cart.get_all_cart_items(request)
            for cart_item in all_items:
                li = LineItem(
                    product_id = cart_item.product_id,
                    price = cart_item.price,
                    quantity = cart_item.quantity,
                    order_id = o.id
                )

                li.save()

            cart.clear(request)

            request.session['order_id'] = o.id

            messages.add_message(request, messages.INFO, 'Order Placed!')
            return redirect('process_payment')


    else:
        form = CheckoutForm()
        return render(request, 'patient_management/checkout.html', {'form': form})

