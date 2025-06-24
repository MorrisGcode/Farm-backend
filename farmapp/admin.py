from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import farmuser, cows, MilkProduction

class FarmUserAdmin(UserAdmin):
    """
    Admin interface for managing farm users.
    """
    list_display = ('username', 'email', 'role', 'is_staff')
    list_filter = ('role', 'is_staff', 'is_superuser')
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'role'),
        }),
    )
    search_fields = ('username', 'email')
    ordering = ('username',)

admin.site.register(farmuser, FarmUserAdmin)

@admin.register(cows)
class CowsAdmin(admin.ModelAdmin):
    """
    Admin interface for managing cows.
    """
    list_display = ('name', 'breed', 'age', 'weight', 'health_status', 'owner')
    list_filter = ('breed', 'health_status', 'owner')
    search_fields = ('name', 'breed', 'owner__username')
    ordering = ('name',)

@admin.register(MilkProduction)
class MilkProductionAdmin(admin.ModelAdmin):
    """
    Admin interface for managing milk production records.
    """
    list_display = ('cow', 'date', 'morning_amount', 'evening_amount', 'total_amount', 'recorded_by')
    list_filter = ('date', 'cow', 'recorded_by')
    search_fields = ('cow__name', 'recorded_by__username')
    ordering = ('-date',)
    date_hierarchy = 'date'

    def total_amount(self, obj):
        return f"{obj.morning_amount + obj.evening_amount} L"
    total_amount.short_description = 'Total Milk'



