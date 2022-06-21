from typing import Type

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, send_mail
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode
from login_api import settings

from .tokens import generate_token

# Create your views here.

def home(request):
    return render(request, 'authentication/index.html')


def signup(request):

    if request.method == "POST":
        #username = request.POST.get('username')
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']

        if User.objects.filter(username=username):
            messages.error(request, "User already exists.")
            return redirect('home')

        if User.objects.filter(email=email):
            messages.error(request, "Email already registered!")
            return redirect('home')
        
        if len(username) > 12:
            messages.error(request, "Username must be under 2 characters.")
        
        if password != password2:
            messages.error(request, "Passwords didn't match.")

        if not username.isalnum():
            messages.error(request, "Username has invalid characters.")
            return redirect('home')


        myuser = User.objects.create_user(username, email, password)
        myuser.first_name = fname
        myuser.last_name = lname

        myuser.save()

        messages.success(request, "Your Account has been successfully created. Please check your email to confirm your account!")

        #Email de welcome
        subject = "Testando Confirmação por Email"
        message = "Hello " + myuser.first_name + "! \n" + "Bem vindo ao site. \n Obrigado por se registrar. \n Por favor, verifique seu email no link a seguir: "
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        #Email de Confirmação
        current_site = get_current_site(request)
        email_subject = "Confirm your email please."
        message2 = render_to_string('email_confirmation.html',{
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })

        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.meail],
        )
        email.fail_silently = True
        email.send()

        return redirect('signin')
    
    return render(request, "authentication/signup.html")

def signin(request):

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)


        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, "authentication/index.html", {'fname': fname})

        else:
            messages.error(request, "Bad Credentials.")
            return redirect('home')


    return render(request, "authentication/signin.html")

def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully")
    return redirect('home')


def activate(request, uidb64, token):
    try:
         uid = force_str(urlsafe_base64_encode(uidb64))
         myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')
