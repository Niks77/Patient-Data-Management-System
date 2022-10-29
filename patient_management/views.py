
import re
from django.shortcuts import HttpResponse, redirect, render
from patient_management.models import User 
from django.contrib import messages
from django.contrib.auth import authenticate, login

# Create your views here.
def home(request):
    return render(request,"patient_management/fileupload.html")

def signup(request):
    if request.method == "POST":
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password1 = request.POST.get('password1')
        type = request.POST.get('type')
        emailRegex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('signup')
        if type == None:
            messages.error(request, "Please select user type")
            return redirect('signup')
        if type != "Patient" and type != "Healthcare Professional":
            messages.error(request, "Please select valid user type")
            return redirect('signup')
        if not re.fullmatch(emailRegex,email):
            messages.error(request, "Enter valid email")
            return redirect('signup')
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email Already Registered!!")
            return redirect('signup')
      
        if password != password1:
            messages.error(request, "Passwords didn't matched!!")
            return redirect('signup')

        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('signup ')
        myuser = User.objects.create_user(username,type,fname,email,password)
        messages.success(request, "Your account has been created successfully")
        return redirect('signin')

    return render(request,"patient_management/signup.html")

def load_dropdown(request):
     type = request.GET.get('type')
     return render(request, 'patient_management/fileupload.html', {'type': type})

def signin(request):
    if request.method == "POST":
        password = request.POST.get('password')
        username = request.POST.get('username')
        # print(password + " "+ email)
        user = authenticate(username=username, password = password)
        # print(user)
        if user is not None:
            login(request, user)
            return render(request, "patient_management/index.html")
        else :
            messages.error(request, "Wrong username/ password")
            return redirect('signin')
        
    return render(request,"patient_management/Login.html")

def signout(request):
    pass