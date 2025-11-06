from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('bay_list/', views.bay_list, name='bay_list'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
]
