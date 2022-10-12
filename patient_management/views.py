
import re
from django.shortcuts import HttpResponse, redirect, render
from django.contrib.auth.models import User 
from django.contrib import messages
from django.contrib.auth import authenticate, login

# Create your views here.
def home(request):
    return render(request,"patient_management/Login.html")

def signup(request):
    data = dict()
    if request.method == "POST":
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password1 = request.POST.get('password1')
        emailRegex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try some other username.")
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
        myuser = User.objects.create_user(username,email,password)
        myuser.first_name = fname
        myuser.save()
        messages.success(request, "Your account has been created successfully")
        return redirect('signin')

    return render(request,"patient_management/signup.html")


def signin(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password = password)
        if user is not None:
            login(request, user)
            return render(request, "patient_management/index.html")
        else :
            messages.success(request, "Wrong username/ password")
            return redirect('home')
        return redirect('signin')
    return render(request,"patient_management/Login.html")

def signout(request):
    pass