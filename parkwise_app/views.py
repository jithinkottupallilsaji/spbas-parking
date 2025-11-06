from django.shortcuts import render, redirect
from .models import Bay
from django.contrib import messages
import random

def bay_list(request):
    bays = Bay.objects.all()
    return render(request, 'parkwise_app/bay_list.html', {'bays': bays})

def home(request):
    return render(request, 'parkwise_app/home.html')

def signup(request):
    """Handle user signup with 5-digit OTP verification"""
    
    if request.method == 'POST':
        first_name = request.POST.get('firstName')
        last_name = request.POST.get('lastName')
        country = request.POST.get('country')
        county = request.POST.get('county', '')
        city = request.POST.get('city')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        employee_type = request.POST.get('employeeType')
        
        request.session['signup_data'] = {
            'first_name': first_name,
            'last_name': last_name,
            'country': country,
            'county': county,
            'city': city,
            'email': email,
            'phone': phone,
            'employee_type': employee_type,
        }
        
        otp = str(random.randint(10000, 99999))
        request.session['otp'] = otp
        
        print(f'\n========== OTP FOR {email} ==========')
        print(f'OTP Code: {otp}')
        print(f'====================================\n')
        
        messages.info(request, f'For testing: Your OTP is {otp}')
        return render(request, 'parkwise_app/signup.html')
    
    return render(request, 'parkwise_app/signup.html')

def login_view(request):
    """Handle user login"""
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        remember_me = request.POST.get('rememberMe')
        
        print(f'\n========== LOGIN ATTEMPT ==========')
        print(f'Email: {email}')
        print(f'Password: {password}')
        print(f'Remember Me: {remember_me}')
        print(f'===================================\n')
        
        messages.info(request, 'Login functionality coming soon!')
        return render(request, 'parking/login.html')
    
    return render(request, 'parkwise_app/login.html')


# Create your views here.
