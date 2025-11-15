from datetime import datetime
import random
import re

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout as django_logout
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.db import IntegrityError
from django.http import JsonResponse

from .models import Slot, Booking, EmployeeProfile
from .dynamo_manage import UserDDB, SlotDDB, BookingDDB   # ✅ FIXED IMPORT


# ---------------------------------------------------------
# Helper functions – sync relational data to DynamoDB
# ---------------------------------------------------------

def sync_user_to_dynamo(profile: EmployeeProfile):
    user = profile.user
    email = user.email

    try:
        item = UserDDB.get(email)
        item.first_name = user.first_name
        item.last_name = user.last_name
        item.role = profile.role
        item.emp_id = profile.emp_id
        item.save()
    except UserDDB.DoesNotExist:
        UserDDB(
            email=email,
            first_name=user.first_name,
            last_name=user.last_name,
            password="managed-in-django",
            role=profile.role,
            emp_id=profile.emp_id,
        ).save()


def sync_slot_to_dynamo(slot: Slot):
    reserved_by_email = slot.reserved_by.email if slot.reserved_by else None

    try:
        item = SlotDDB.get(slot.slot_number)
        item.zone = slot.zone
        item.level = slot.level
        item.status = slot.status
        item.reserved_by = reserved_by_email
        item.save()
    except SlotDDB.DoesNotExist:
        SlotDDB(
            slot_number=slot.slot_number,
            zone=slot.zone,
            level=slot.level,
            status=slot.status,
            reserved_by=reserved_by_email,
        ).save()


def sync_booking_to_dynamo(booking: Booking):
    entry_time = booking.entry_time.isoformat() if booking.entry_time else None
    exit_time = booking.exit_time.isoformat() if booking.exit_time else None
    duration = booking.duration_mins
    price = float(booking.total_price) if booking.total_price is not None else None

    try:
        item = BookingDDB.get(str(booking.id))
        item.user_email = booking.user.email
        item.slot_number = booking.slot.slot_number
        item.booking_date = booking.booking_date.isoformat()
        item.state = booking.state
        item.entry_otp = booking.entry_otp or ""
        item.exit_otp = booking.exit_otp or ""
        item.entry_time = entry_time
        item.exit_time = exit_time
        item.duration_mins = duration
        item.total_price = price
        item.save()
    except BookingDDB.DoesNotExist:
        BookingDDB(
            booking_id=str(booking.id),
            user_email=booking.user.email,
            slot_number=booking.slot.slot_number,
            booking_date=booking.booking_date.isoformat(),
            state=booking.state,
            entry_otp=booking.entry_otp or "",
            exit_otp=booking.exit_otp or "",
            entry_time=entry_time,
            exit_time=exit_time,
            duration_mins=duration,
            total_price=price,
        ).save()


# ---------------------------------------------------------
# BASIC PAGES
# ---------------------------------------------------------

def home(request):
    return render(request, "parkwise_app/home.html")


def bay_list(request):
    bays = Slot.objects.all().order_by("slot_number")
    return render(request, "parkwise_app/bay_list.html", {"bays": bays})


# ---------------------------------------------------------
# SIGNUP (VALIDATION + OTP SIMULATION)
# ---------------------------------------------------------

def signup(request):
    if request.method == "POST":
        first_name = request.POST.get("firstName")
        last_name = request.POST.get("lastName")
        email = request.POST.get("email")
        emp_id = request.POST.get("emp_id")
        role = request.POST.get("employeeType")

        if not re.fullmatch(r"EMP\d{3,}", emp_id):
            messages.error(request, "Invalid Employee Code format (EMP123).")
            return redirect("signup")

        if EmployeeProfile.objects.filter(emp_id=emp_id).exists():
            messages.error(request, "Employee Code already exists.")
            return redirect("signup")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect("signup")

        temp_password = "Temp123!"
        user = User.objects.create_user(
            username=email,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=temp_password,
        )

        profile = EmployeeProfile.objects.create(user=user, emp_id=emp_id, role=role)
        sync_user_to_dynamo(profile)

        otp = str(random.randint(10000, 99999))
        request.session["signup_otp"] = otp
        print("\nSIGNUP OTP:", otp, "\n")

        messages.success(request, f"Signup successful! OTP sent: {otp}")
        return redirect("login")

    return render(request, "parkwise_app/signup.html")


# ---------------------------------------------------------
# LOGIN & ROLE REDIRECTION
# ---------------------------------------------------------

def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        selected_role = request.POST.get("role")

        user = authenticate(username=email, password=password)
        if not user:
            messages.error(request, "Invalid email or password.")
            return redirect("home")

        try:
            profile = EmployeeProfile.objects.get(user=user)
        except EmployeeProfile.DoesNotExist:
            messages.error(request, "Profile missing.")
            return redirect("home")

        if profile.role.lower() != selected_role.lower():
            messages.error(
                request,
                f"Incorrect role. You are registered as {profile.role}.",
            )
            return redirect("home")

        login(request, user)

        if profile.role.lower() == "admin":
            return redirect("admin_dashboard")
        if profile.role.lower() == "employee":
            return redirect("employee_dashboard")
        if profile.role.lower() == "security":
            return redirect("security_dashboard")

        return redirect("home")

    return render(request, "parkwise_app/login.html")


def logout_view(request):
    django_logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect("login")


# ---------------------------------------------------------
# ADMIN DASHBOARD
# ---------------------------------------------------------

@login_required
def admin_dashboard(request):
    today = timezone.localdate()

    context = {
        "available_bays": Slot.objects.filter(status="available").count(),
        "reserved_bays": Slot.objects.filter(status="reserved").count(),
        "occupied_bays": Slot.objects.filter(status="occupied").count(),
        "total_bays": Slot.objects.count(),
        "total_users": EmployeeProfile.objects.count(),
        "todays_bookings": Booking.objects.filter(booking_date=today).count(),
        "active_bookings": Booking.objects.filter(state="active").count(),
        "bays": Slot.objects.order_by("slot_number"),
        "employees": EmployeeProfile.objects.select_related("user").order_by("emp_id"),
        "today": today,
    }
    return render(request, "parkwise_app/admin_dashboard.html", context)


@login_required
def add_bay(request):
    if request.method == "POST":
        slot_number = request.POST.get("slot_number")
        zone = request.POST.get("zone")
        level = request.POST.get("level")
        status = request.POST.get("status") or Slot.Status.AVAILABLE

        try:
            slot = Slot.objects.create(
                slot_number=slot_number,
                zone=zone,
                level=level,
                status=status,
            )
            sync_slot_to_dynamo(slot)
            messages.success(request, "Bay added.")
        except IntegrityError:
            messages.error(request, "Bay already exists.")
    return redirect("admin_dashboard")


@login_required
def generate_demo_bays(request):
    if request.method == "POST":
        created = 0
        patterns = [
            ("Zone A", "Ground Floor", "A", 1, 10),
            ("Zone A", "Level 1", "A1", 11, 20),
            ("Zone B", "Ground Floor", "B", 1, 10),
            ("Zone B", "Level 1", "B1", 11, 20),
        ]

        for zone, level, prefix, start, end in patterns:
            for i in range(start, end + 1):
                slot_num = f"{prefix}-{i:03}"
                slot, flag = Slot.objects.get_or_create(
                    slot_number=slot_num,
                    defaults={"zone": zone, "level": level, "status": "available"},
                )
                sync_slot_to_dynamo(slot)
                if flag:
                    created += 1

        messages.success(request, f"{created} demo bays created.")
    return redirect("admin_dashboard")


@login_required
def add_user(request):
    if request.method == "POST":
        email = request.POST.get("email")
        emp_id = request.POST.get("emp_id")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect("admin_dashboard")

        if EmployeeProfile.objects.filter(emp_id=emp_id).exists():
            messages.error(request, "Employee Code already exists.")
            return redirect("admin_dashboard")

        temp_password = "Temp123!"

        user = User.objects.create(
            username=email,
            email=email,
            first_name=request.POST.get("first_name"),
            last_name=request.POST.get("last_name"),
            password=make_password(temp_password),
        )

        profile = EmployeeProfile.objects.create(
            user=user,
            emp_id=emp_id,
            role=request.POST.get("role"),
        )
        sync_user_to_dynamo(profile)

        messages.success(request, f"User created. Temp password: {temp_password}")
    return redirect("admin_dashboard")


# ---------------------------------------------------------
# EMPLOYEE DASHBOARD
# ---------------------------------------------------------

@login_required
def employee_dashboard(request):
    user = request.user
    today = timezone.localdate()

    context = {
        "active_booking": Booking.objects.filter(
            user=user, state="active"
        ).order_by("-created_at").first(),
        "total_visits": Booking.objects.filter(
            user=user, state="completed"
        ).count(),
        "recent_bookings": Booking.objects.filter(user=user)
        .select_related("slot")
        .order_by("-created_at")[:10],
        "available_bays_list": Slot.objects.filter(status="available").order_by(
            "slot_number"
        ),
        "default_booking_date": today,
    }

    return render(request, "parkwise_app/employee_dashboard.html", context)


# ---------------------------------------------------------
# BOOK A BAY (SELF OR OTHERS)
# ---------------------------------------------------------

@login_required
def book_bay(request):
    user = request.user
    profile = EmployeeProfile.objects.get(user=user)
    can_book_for_others = profile.role.lower() in ["security", "admin"]

    if request.method == "GET":
        context = {
            "available_slots": Slot.objects.filter(status="available").order_by(
                "slot_number"
            ),
            "can_book_for_others": can_book_for_others,
            "today": timezone.localdate(),
            "total_slots": Slot.objects.count(),
            "available_count": Slot.objects.filter(status="available").count(),
            "reserved_count": Slot.objects.filter(status="reserved").count(),
            "occupied_count": Slot.objects.filter(status="occupied").count(),
        }
        return render(request, "parkwise_app/book_bay.html", context)

    booking_mode = request.POST.get("booking_mode", "self")
    target_emp_id = request.POST.get("emp_id")
    slot_choice = request.POST.get("slot_choice")
    booking_date = request.POST.get("booking_date")

    try:
        booking_date = datetime.strptime(booking_date, "%Y-%m-%d").date()
    except Exception:
        booking_date = timezone.localdate()

    target_user = user
    if booking_mode == "other" and can_book_for_others:
        try:
            target_user = EmployeeProfile.objects.get(emp_id=target_emp_id).user
        except EmployeeProfile.DoesNotExist:
            messages.error(request, "Employee not found.")
            return redirect("book_bay")

    if slot_choice == "auto":
        slot = (
            Slot.objects.filter(status="available")
            .order_by("slot_number")
            .first()
        )
        if not slot:
            messages.error(request, "No available bays.")
            return redirect("book_bay")
    else:
        try:
            slot = Slot.objects.get(id=slot_choice)
        except Slot.DoesNotExist:
            messages.error(request, "Invalid bay.")
            return redirect("book_bay")
        if slot.status != "available":
            messages.error(request, "Bay not available.")
            return redirect("book_bay")

    booking = Booking.objects.create(
        user=target_user,
        slot=slot,
        booking_date=booking_date,
        state=Booking.State.PENDING,
    )

    entry_otp = str(random.randint(10000, 99999))
    booking.entry_otp = entry_otp
    booking.save()
    sync_booking_to_dynamo(booking)

    slot.status = "reserved"
    slot.reserved_by = target_user
    slot.save()
    sync_slot_to_dynamo(slot)

    messages.info(request, f"Entry OTP: {entry_otp}")

    if profile.role.lower() == "employee":
        return redirect("employee_dashboard")
    if profile.role.lower() == "security":
        return redirect("security_dashboard")
    return redirect("admin_dashboard")


# ---------------------------------------------------------
# ENTRY OTP VALIDATION
# ---------------------------------------------------------

@login_required
def validate_entry_otp(request):
    if request.method == "POST":
        otp = request.POST.get("otp", "").strip()

        try:
            booking = Booking.objects.get(
                user=request.user, entry_otp=otp, state="pending"
            )
        except Booking.DoesNotExist:
            messages.error(request, "Invalid entry OTP.")
            return redirect("employee_dashboard")

        booking.state = "active"
        booking.entry_time = timezone.now()
        booking.save()
        sync_booking_to_dynamo(booking)

        bay = booking.slot
        bay.status = "occupied"
        bay.save()
        sync_slot_to_dynamo(bay)

        messages.success(request, "Entry validated. Welcome inside!")
    return redirect("employee_dashboard")


@login_required
def validate_entry_otp_security(request):
    if request.method == "POST":
        otp = request.POST.get("otp", "").strip()

        try:
            booking = Booking.objects.get(entry_otp=otp, state="pending")
        except Booking.DoesNotExist:
            messages.error(request, "Invalid OTP.")
            return redirect("security_dashboard")

        booking.state = "active"
        booking.entry_time = timezone.now()
        booking.save()
        sync_booking_to_dynamo(booking)

        bay = booking.slot
        bay.status = "occupied"
        bay.save()
        sync_slot_to_dynamo(bay)

        messages.success(request, "Entry validated by Security.")
    return redirect("security_dashboard")


# ---------------------------------------------------------
# EXIT OTP
# ---------------------------------------------------------

@login_required
def generate_exit_otp(request):
    try:
        booking = Booking.objects.get(user=request.user, state="active")
    except Booking.DoesNotExist:
        messages.error(request, "No active session.")
        return redirect("employee_dashboard")

    exit_otp = str(random.randint(10000, 99999))
    booking.exit_otp = exit_otp
    booking.save()
    sync_booking_to_dynamo(booking)

    messages.info(request, f"Exit OTP: {exit_otp}")
    return redirect("employee_dashboard")


@login_required
def validate_exit_otp_security(request):
    if request.method == "POST":
        otp = request.POST.get("otp", "").strip()

        try:
            booking = Booking.objects.get(exit_otp=otp, state="active")
        except Booking.DoesNotExist:
            messages.error(request, "Invalid Exit OTP.")
            return redirect("security_dashboard")

        booking.exit_time = timezone.now()
        booking.state = "completed"
        booking.save()
        sync_booking_to_dynamo(booking)

        bay = booking.slot
        bay.status = "available"
        bay.reserved_by = None
        bay.save()
        sync_slot_to_dynamo(bay)

        messages.success(request, "Exit validated. Vehicle out.")
    return redirect("security_dashboard")


# ---------------------------------------------------------
# SIGNUP OTP (AJAX)
# ---------------------------------------------------------

def send_signup_otp(request):
    if request.method != "POST":
        return JsonResponse({"success": False}, status=400)

    data = request.POST
    emp_id = data.get("emp_id")
    email = data.get("email")

    if not re.fullmatch(r"EMP\d{3,}", emp_id or ""):
        return JsonResponse({"success": False, "error": "Invalid EMP Code"}, status=400)

    if EmployeeProfile.objects.filter(emp_id=emp_id).exists():
        return JsonResponse({"success": False, "error": "EMP Code exists"}, status=400)

    if User.objects.filter(email=email).exists():
        return JsonResponse({"success": False, "error": "Email exists"}, status=400)

    otp = str(random.randint(10000, 99999))
    request.session["signup_otp"] = otp
    request.session["signup_temp"] = data.dict()

    print("\nSIGNUP OTP:", otp, "\n")
    return JsonResponse({"success": True})


def verify_signup_otp(request):
    if request.method != "POST":
        return JsonResponse({"success": False}, status=400)

    otp_entered = request.POST.get("otp")
    otp_original = request.session.get("signup_otp")

    if otp_entered != otp_original:
        return JsonResponse({"success": False, "error": "Incorrect OTP"})

    temp = request.session.get("signup_temp")

    user = User.objects.create_user(
        username=temp["email"],
        email=temp["email"],
        password="temp123",
        first_name=temp["firstName"],
        last_name=temp["lastName"],
    )

    profile = EmployeeProfile.objects.create(
        user=user,
        emp_id=temp["emp_id"],
        role=temp["employeeType"],
    )
    sync_user_to_dynamo(profile)

    del request.session["signup_otp"]
    del request.session["signup_temp"]

    return JsonResponse({"success": True})


# ---------------------------------------------------------
# SECURITY DASHBOARD
# ---------------------------------------------------------

@login_required
def security_dashboard(request):
    context = {
        "active_bookings": Booking.objects.filter(state="active").count(),
        "pending_entry": Booking.objects.filter(state="pending").count(),
        "pending_exit": Booking.objects.filter(
            state="active", exit_time__isnull=True
        ).count(),
        "recent_bookings": Booking.objects.select_related("user", "slot")
        .order_by("-created_at")[:10],
    }

    return render(request, "parkwise_app/security_dashboard.html", context)
