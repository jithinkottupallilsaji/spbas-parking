from django.urls import path
from . import views

urlpatterns = [

    # -----------------------------
    # Public Pages
    # -----------------------------
    path("", views.home, name="home"),
    path("bay_list/", views.bay_list, name="bay_list"),

    # -----------------------------
    # Authentication
    # -----------------------------
    path("signup/", views.signup, name="signup"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),

    # -----------------------------
    # Dashboards
    # -----------------------------
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard"),
    path("employee-dashboard/", views.employee_dashboard, name="employee_dashboard"),
    path("security-dashboard/", views.security_dashboard, name="security_dashboard"),

    # -----------------------------
    # Admin Actions
    # -----------------------------
    path("spbas-admin/add-bay/", views.add_bay, name="add_bay"),
    path("spbas-admin/generate-demo-bays/", views.generate_demo_bays, name="generate_demo_bays"),
    path("spbas-admin/add-user/", views.add_user, name="add_user"),
    path("spbas-admin/delete-bay/<str:slot_number>/", views.delete_bay, name="delete_bay"),
    path("spbas-admin/edit-bay/<str:slot_number>/", views.edit_bay, name="edit_bay"),


    # -----------------------------
    # Employee Actions
    # -----------------------------
    path("employee/book-bay/", views.book_bay, name="book_bay"),
    path("employee/entry-otp/", views.validate_entry_otp, name="validate_entry_otp"),
    path("employee/exit-otp/", views.generate_exit_otp, name="generate_exit_otp"),

    # -----------------------------
    # Security Actions
    # -----------------------------
    path("security/entry-otp/", views.validate_entry_otp_security, name="validate_entry_otp_security"),
    path("security/exit-otp/", views.validate_exit_otp_security, name="validate_exit_otp_security"),

    # -----------------------------
    # Signup OTP (AJAX)
    # -----------------------------
    path("signup/send-otp/", views.send_signup_otp, name="send_signup_otp"),
    path("signup/verify-otp/", views.verify_signup_otp, name="verify_signup_otp"),
    
   

]
