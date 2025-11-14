from django.contrib import admin
from .models import Slot

@admin.register(Slot)
class SlotAdmin(admin.ModelAdmin):
    list_display = ('slot_number', 'zone', 'level', 'status', 'reserved_by', 'reserved_until')
    list_filter = ('zone', 'level', 'status')
    search_fields = ('slot_number', 'reserved_by__username')


# Register your models here.
