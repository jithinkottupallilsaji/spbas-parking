from pynamodb.models import Model
from pynamodb.attributes import (
    UnicodeAttribute, NumberAttribute, UTCDateTimeAttribute
)
from datetime import datetime

AWS_REGION = "us-east-1"    # REQUIRED REGION


# ============================================
# USER TABLE (DynamoDB-based authentication)
# ============================================
class UserDDB(Model):
    class Meta:
        table_name = "spbas-users"
        region = AWS_REGION

    email = UnicodeAttribute(hash_key=True)       # PK
    first_name = UnicodeAttribute(null=True)
    last_name = UnicodeAttribute(null=True)
    password = UnicodeAttribute()                 # hashed password
    role = UnicodeAttribute(default="employee")   # admin/employee/security
    emp_id = UnicodeAttribute()                   # EMPXXX


# ============================================
# SLOT TABLE
# ============================================
class SlotDDB(Model):
    class Meta:
        table_name = "spbas-slots"
        region = AWS_REGION

    slot_number = UnicodeAttribute(hash_key=True)   # PK
    zone = UnicodeAttribute()
    level = UnicodeAttribute()
    status = UnicodeAttribute(default="available")   # available/reserved/occupied

    reserved_by = UnicodeAttribute(null=True)        # user email
    reserved_until = UTCDateTimeAttribute(null=True)


# ============================================
# BOOKING TABLE
# ============================================
class BookingDDB(Model):
    class Meta:
        table_name = "spbas-bookings"
        region = AWS_REGION

    booking_id = UnicodeAttribute(hash_key=True)    # PK
    user_email = UnicodeAttribute()
    slot_number = UnicodeAttribute()
    booking_date = UnicodeAttribute()               # YYYY-MM-DD

    state = UnicodeAttribute(default="pending")     # pending/active/completed/cancelled
    entry_otp = UnicodeAttribute(null=True)
    exit_otp = UnicodeAttribute(null=True)

    entry_time = UnicodeAttribute(null=True)
    exit_time = UnicodeAttribute(null=True)

    duration_mins = NumberAttribute(null=True)
    total_price = NumberAttribute(null=True)
