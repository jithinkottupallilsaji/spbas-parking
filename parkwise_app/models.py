from django.conf import settings
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


# ---------------------------------------------------------
# SLOT MODEL
# ---------------------------------------------------------

class Slot(models.Model):
    class Zone(models.TextChoices):
        ZONE_A = "Zone A", "Zone A"
        ZONE_B = "Zone B", "Zone B"

    class Level(models.TextChoices):
        GF = "Ground Floor", "Ground Floor"
        L1 = "Level 1", "Level 1"

    class Status(models.TextChoices):
        AVAILABLE = "available", "Available"
        RESERVED = "reserved", "Reserved"
        OCCUPIED = "occupied", "Occupied"

    slot_number = models.CharField(max_length=20, unique=True)
    zone = models.CharField(max_length=20, choices=Zone.choices)
    level = models.CharField(max_length=20, choices=Level.choices)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.AVAILABLE
    )

    reserved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reserved_slots"
    )

    reserved_until = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.slot_number


# ---------------------------------------------------------
# BOOKING MODEL
# ---------------------------------------------------------

class Booking(models.Model):
    class State(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        COMPLETED = "completed", "Completed"
        CANCELLED = "cancelled", "Cancelled"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    slot = models.ForeignKey(Slot, on_delete=models.PROTECT)
    booking_date = models.DateField(default=timezone.localdate)
    state = models.CharField(max_length=20, choices=State.choices, default=State.PENDING)

    created_at = models.DateTimeField(auto_now_add=True)

    # Entry / Exit data
    entry_otp = models.CharField(max_length=10, null=True, blank=True)
    exit_otp = models.CharField(max_length=10, null=True, blank=True)
    entry_time = models.DateTimeField(null=True, blank=True)
    exit_time = models.DateTimeField(null=True, blank=True)

    # Duration & Cost
    duration_mins = models.FloatField(null=True, blank=True)
    total_price = models.DecimalField(max_digits=8, decimal_places=2, null=True, blank=True)

    RATE_PER_HOUR = 4  # €4 per hour

    def calculate_duration(self):
        if self.entry_time and self.exit_time:
            seconds = (self.exit_time - self.entry_time).total_seconds()
            return round(seconds / 60, 2)
        return None

    def calculate_cost(self):
        dur = self.calculate_duration()
        if dur:
            hours = dur / 60
            return round(hours * self.RATE_PER_HOUR, 2)
        return None

    def save(self, *args, **kwargs):
        if self.entry_time and self.exit_time:
            self.duration_mins = self.calculate_duration()
            self.total_price = self.calculate_cost()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.slot.slot_number} — {self.user.username} ({self.booking_date})"


# ---------------------------------------------------------
# EMPLOYEE PROFILE MODEL
# ---------------------------------------------------------

class EmployeeProfile(models.Model):
    ROLE_CHOICES = [
        ("admin", "Admin"),
        ("employee", "Employee"),
        ("security", "Security"),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    emp_id = models.CharField(max_length=10, unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.emp_id} — {self.user.get_full_name()} ({self.role})"
