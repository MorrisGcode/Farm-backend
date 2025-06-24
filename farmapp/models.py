from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model

class FarmUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'ADMIN')
        return self.create_user(username, email, password, **extra_fields)

class farmuser(AbstractBaseUser, PermissionsMixin):
    objects = FarmUserManager()  

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    
    ROLE_CHOICES = [
        ('ADMIN', 'Administrator'),
        ('MANAGER', 'Farm Manager'),
        ('WORKER', 'Farm Worker'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='WORKER')

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = 'Farm User'
        verbose_name_plural = 'Farm Users'

class cows(models.Model):
    HEALTH_STATUS_CHOICES = [
        ('HEALTHY', 'Healthy'),
        ('SICK', 'Sick'),
        ('TREATMENT', 'Under Treatment')
    ]

    name = models.CharField(max_length=100)
    breed = models.ForeignKey('Breed', on_delete=models.CASCADE, related_name='cows')
    age = models.IntegerField()
    weight = models.FloatField()
    health_status = models.CharField(
        max_length=20,
        choices=HEALTH_STATUS_CHOICES,
        default='HEALTHY'
    )
    owner = models.ForeignKey(
        'farmuser',
        on_delete=models.CASCADE,
        related_name='cows'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.breed}"

    class Meta:
        verbose_name_plural = "Cows"
        ordering = ['name']

class MilkProduction(models.Model):
    cow = models.ForeignKey(cows, on_delete=models.CASCADE, related_name='milk_records')
    date = models.DateField(default=timezone.now)
    morning_amount = models.FloatField(help_text="Amount in liters")
    evening_amount = models.FloatField(help_text="Amount in liters")
    recorded_by = models.ForeignKey(farmuser, on_delete=models.SET_NULL, null=True)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.cow.name} - {self.date} ({self.morning_amount + self.evening_amount}L)"

    class Meta:
        ordering = ['-date']
        verbose_name = "Milk Production Record"
        verbose_name_plural = "Milk Production Records"
        unique_together = ['cow', 'date']

class Breed(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Breeds"
        ordering = ['name']

class FeedType(models.Model):
    """
    Represents different types of feeds and their nutritional values.
    """
    name = models.CharField(max_length=100, unique=True, help_text="Name of the feed type (e.g., Hay, Silage, Alfalfa)")
    dry_matter_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Dry Matter (%)"
    )
    crude_protein_percent = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Crude Protein (%)"
    )
    metabolizable_energy_mj_kg = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Metabolizable Energy (MJ/kg DM)"
    )
    notes = models.TextField(
        blank=True,
        null=True,
        help_text="Any additional notes or details about this feed type"
    )

    class Meta:
        verbose_name = "Feed Type"
        verbose_name_plural = "Feed Types"
        ordering = ['name']

    def __str__(self):
        return self.name
    
class DailyFeedingLog(models.Model):
    """
    Represents a daily log of feed distributed by a worker, not specific to a single cow.
    This can be used for general feed consumption tracking across the farm.
    """
    worker_name = models.CharField(max_length=100, help_text="Name of the worker who logged the feeding")
    log_date = models.DateField(
        default=timezone.now,
        help_text="Date of the feeding log"
    )
    # Many-to-Many relationship with FeedType through DailyFeedQuantity
    feed_items = models.ManyToManyField(
        FeedType,
        through='DailyFeedQuantity',
        related_name='daily_feeding_logs',
        help_text="Specific feed types and quantities for this log"
    )
    special_feed_vitamins_notes = models.TextField(
        blank=True,
        null=True,
        help_text="Notes about any special feed or vitamins given"
    )
    general_notes = models.TextField( # Renamed from 'notes' for clarity
        blank=True,
        null=True,
        help_text="General notes about this daily distribution"
    )


    class Meta:
        verbose_name = "Daily Feeding Log"
        verbose_name_plural = "Daily Feeding Logs"
        
        ordering = ['-log_date', 'worker_name']

    def __str__(self):
        return f"Daily Log by {self.worker_name} on {self.log_date}"

class DailyFeedQuantity(models.Model):
    """
    Intermediary model for DailyFeedingLog and FeedType to store quantity and unit
    for each specific feed type in a daily log.
    """
    daily_log = models.ForeignKey(DailyFeedingLog, on_delete=models.CASCADE, related_name='feed_quantities')
    feed_type = models.ForeignKey(FeedType, on_delete=models.CASCADE)
    quantity = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        help_text="Quantity of this specific feed type"
    )
    unit = models.CharField(
        max_length=20,
        default='kg',
        help_text="Unit of measurement for this specific feed quantity"
    )

    class Meta:
        verbose_name = "Daily Feed Quantity"
        verbose_name_plural = "Daily Feed Quantities"
        unique_together = ('daily_log', 'feed_type') 

    def __str__(self):
        return f"{self.quantity} {self.unit} of {self.feed_type.name} for {self.daily_log.worker_name} on {self.daily_log.log_date}"
    
class BreedingRecords(models.Model):
    cow = models.ForeignKey(cows, on_delete=models.CASCADE, related_name='breeding_records')
    bull_name = models.CharField(max_length=100)
    breeding_date = models.DateField(help_text="Date when the cow was bred")
    insemination_method = models.CharField( max_length=50,
        choices=[
            ('NATURAL', 'Natural Breeding'),
            ('AI', 'Artificial Insemination')
        ],
        default='NATURAL',
        help_text="Method of breeding"
    )
    expected_calving_date = models.DateField(blank=True, null=True, help_text="Expected date of calving")
    notes = models.TextField(blank=True, null=True, help_text="Any additional notes about the breeding")

    class Meta:
        verbose_name = "Breeding Record"
        verbose_name_plural = "Breeding Records"
        ordering = ['-breeding_date']

    def __str__(self):
        return f"{self.cow.name} bred with {self.bull_name} on {self.breeding_date}"
   
    def save(self, *args, **kwargs):
       
        if self.breeding_date and not self.expected_calving_date:
            
            self.expected_calving_date = self.breeding_date + timedelta(days=280)
        super().save(*args, **kwargs)

class CowHealthRecord(models.Model):
    cow = models.ForeignKey(cows, on_delete=models.CASCADE, related_name='health_records')
    record_date = models.DateField(help_text="Date of this health record")
    symptoms = models.TextField(blank=True, null=True, help_text="Observed symptoms or health issues")
    diagnosis = models.TextField(blank=True, null=True, help_text="Diagnosis made by a vet or observer")
    treatment = models.TextField(blank=True, null=True, help_text="Treatment administered (e.g., medication, procedure)")
    medication_administered = models.CharField(max_length=255, blank=True, null=True, help_text="Names of medications given")
    vet_name = models.CharField(max_length=100, blank=True, null=True, help_text="Name of the veterinarian (if applicable)")
    next_checkup_date = models.DateField(blank=True, null=True, help_text="Recommended date for next check-up")
    notes = models.TextField(blank=True, null=True, help_text="Any additional notes about the health record")

    class Meta:
        verbose_name = "Cow Health Record"
        verbose_name_plural = "Cow Health Records"
        ordering = ['-record_date', 'cow__name'] # Order by latest record date, then cow name

    def __str__(self):
        return f"Health record for {self.cow.name} on {self.record_date}"
    
class Calf(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
    ]

    ear_tag_number = models.CharField(max_length=50, unique=True)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    weight_at_birth = models.DecimalField(max_digits=6, decimal_places=2, null=True, blank=True)
    
    
    dam = models.ForeignKey(cows, on_delete=models.SET_NULL, null=True, blank=True, related_name='offspring')
    sire = models.CharField(max_length=100, null=True, blank=True)
    is_weaned = models.BooleanField(default=False)
    notes = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Calf {self.ear_tag_number} ({self.gender})"

    class Meta:
        ordering = ['-date_of_birth']
        verbose_name_plural = "Calves"

class Notification(models.Model):
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    

    def __str__(self):
        return f"Notification from {self.created_by.username} at {self.created_at}"






