from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .models import farmuser, cows, MilkProduction, Breed, FeedType, DailyFeedingLog, DailyFeedQuantity, BreedingRecords, CowHealthRecord, Calf, Notification
from datetime import datetime
from django.utils import timezone

class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    Handles validation for password confirmation.
    """
    password = serializers.CharField(
        write_only=True, required=True, style={'input_type': 'password'}
    )
    password2 = serializers.CharField(
        write_only=True, required=True, style={'input_type': 'password'}
    )
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        # Fields to be included in the serializer for registration
        fields = ('username', 'email', 'password', 'password2')
        # Extra arguments for username field (e.g., uniqueness)
        extra_kwargs = {
            'username': {'required': True},
            'email': {'required': True}
        }

    def validate(self, data):
        """
        Custom validation to ensure passwords match and email is unique.
        """
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        # Check if username already exists
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError({"username": "This username is already taken."})

        # Check if email already exists
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({"email": "This email is already registered."})

        return data

    def create(self, validated_data):
        """
        Create and return a new `User` instance, given the validated data.
        """
        validated_data.pop('password2')
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    Handles authentication of username and password.
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(
        write_only=True, required=True, style={'input_type': 'password'}
    )

    def validate(self, data):
        """
        Custom validation to authenticate the user.
        """
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)
            if not user:
                raise serializers.ValidationError("Invalid credentials. Please try again.")
        else:
            raise serializers.ValidationError("Must include 'username' and 'password'.")

        data['user'] = user
        return data
    
class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model.
    Used to serialize user data for API responses.
    """
    password = serializers.CharField(write_only=True)

    class Meta:
        model = farmuser
        fields = ('id', 'username', 'email', 'password', 'role')
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = farmuser.objects.create_user(
            password=password,
            **validated_data
        )
        return user
    
class DashboardSerializer(serializers.ModelSerializer):
    class Meta:
        model = farmuser
        fields = ['username', 'email', 'role']

    def create(self, validated_data):
        user = farmuser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            role=validated_data.get('role', 'WORKER')
        )
        return user
    
class MilkProductionSerializer(serializers.ModelSerializer):
    recorded_by_name = serializers.CharField(source='recorded_by.username', read_only=True)
    cow_name = serializers.CharField(source='cow.name', read_only=True)

    class Meta:
        model = MilkProduction
        fields = [
            'id', 'cow', 'date', 'morning_amount',
            'evening_amount', 'recorded_by', 'recorded_by_name',
            'cow_name', 'notes'
        ]

        read_only_fields = ['recorded_by', 'recorded_by_name', 'cow_name']

    def validate(self, data):
        """
        Custom validation to ensure milk amounts are not negative.
        ModelSerializer handles basic field-level validation (e.g., ensuring 'cow' exists,
        'date' is a valid date, amounts are numbers) based on your model definition.
        """
        if data.get('morning_amount', 0) < 0:
            raise serializers.ValidationError(
                {"morning_amount": "Amount cannot be negative."}
            )
        if data.get('evening_amount', 0) < 0:
            raise serializers.ValidationError(
                {"evening_amount": "Amount cannot be negative."}
            )
        return data

    def create(self, validated_data):
        """
        Create and return a new `MilkProduction` instance, given the validated data.
        The `recorded_by` field is automatically set to the current authenticated user.
        """
        
        user = self.context['request'].user
        
        return MilkProduction.objects.create(recorded_by=user, **validated_data)

    def update(self, instance, validated_data):
        """
        Update and return an existing `MilkProduction` instance, given the validated data.
        """
        
        instance.cow = validated_data.get('cow', instance.cow)
        instance.date = validated_data.get('date', instance.date)
        instance.morning_amount = validated_data.get('morning_amount', instance.morning_amount)
        instance.evening_amount = validated_data.get('evening_amount', instance.evening_amount)
        instance.notes = validated_data.get('notes', instance.notes)
        instance.save()
        return instance


class CowSerializer(serializers.ModelSerializer):
    """
    Serializer for the Cow model.
    Used to serialize cow data for API responses.
    """
    total_milk_today = serializers.SerializerMethodField()
    milk_records = MilkProductionSerializer(many=True, read_only=True)
    breed_name = serializers.CharField(source='breed.name', read_only=True)

    class Meta:
        model = cows
        fields = [
            'id', 'name', 'breed', 'breed_name', 'age', 'weight',
            'health_status', 'milk_records', 'total_milk_today', 'owner'
        ]
        read_only_fields = ['owner', 'milk_records']

    def get_total_milk_today(self, obj):
        today_record = obj.milk_records.filter(date=timezone.now().date()).first()
        if today_record:
            return today_record.morning_amount + today_record.evening_amount
        return 0

    def create(self, validated_data):
        user = self.context['request'].user
        return cows.objects.create(owner=user, **validated_data)

    def validate(self, data):
        if not data.get('name'):
            raise serializers.ValidationError({"name": "This field is required."})
        if not data.get('breed'):
            raise serializers.ValidationError({"breed": "This field is required."})
        if data.get('age') is None:
            raise serializers.ValidationError({"age": "This field is required."})
        if data.get('weight') is None:
            raise serializers.ValidationError({"weight": "This field is required."})
        if not data.get('health_status'):
            raise serializers.ValidationError({"health_status": "This field is required."})
        return data

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.breed = validated_data.get('breed', instance.breed)
        instance.age = validated_data.get('age', instance.age)
        instance.weight = validated_data.get('weight', instance.weight)
        instance.health_status = validated_data.get('health_status', instance.health_status)
        instance.save()
        return instance
    
class BreedSerializer(serializers.ModelSerializer):
    """
    Serializer for the Breed model.
    Used to serialize breed data for API responses.
    """
    class Meta:
        model = Breed
        fields = ['id', 'name', 'description']

    def validate(self, data):
        if not data.get('name'):
            raise serializers.ValidationError({"name": "This field is required."})
        return data

    def create(self, validated_data):
        return Breed.objects.create(**validated_data)
    
    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        return instance

class FeedTypeSerializer(serializers.ModelSerializer):
    """
    Serializer for the FeedType model, including nutritional values.
    """
    class Meta:
        model = FeedType
        fields = [
            'id', 'name', 'dry_matter_percent', 'crude_protein_percent',
            'metabolizable_energy_mj_kg', 'notes'
        ]

class DailyFeedQuantitySerializer(serializers.ModelSerializer):
    """
    Serializer for the DailyFeedQuantity intermediary model.
    Includes feed_type_name for display.
    """
    feed_type_name = serializers.ReadOnlyField(source='feed_type.name')

    class Meta:
        model = DailyFeedQuantity
        fields = ['feed_type', 'feed_type_name', 'quantity', 'unit']


class DailyFeedingLogSerializer(serializers.ModelSerializer):
    """
    Serializer for the DailyFeedingLog model.
    Handles nested DailyFeedQuantity objects for multiple feed types.
    """
    feed_quantities = DailyFeedQuantitySerializer(many=True) 

    class Meta:
        model = DailyFeedingLog
        fields = [
            'id', 'worker_name', 'log_date', 'feed_quantities',
            'special_feed_vitamins_notes', 'general_notes'
        ]
        read_only_fields = ['worker_name'] 

    def create(self, validated_data):
        feed_quantities_data = validated_data.pop('feed_quantities')
        daily_log = DailyFeedingLog.objects.create(**validated_data)
        for fq_data in feed_quantities_data:
            DailyFeedQuantity.objects.create(daily_log=daily_log, **fq_data)
        return daily_log

    def update(self, instance, validated_data):
        feed_quantities_data = validated_data.pop('feed_quantities', [])

        # Update DailyFeedingLog fields
        instance.log_date = validated_data.get('log_date', instance.log_date)
        instance.special_feed_vitamins_notes = validated_data.get('special_feed_vitamins_notes', instance.special_feed_vitamins_notes)
        instance.general_notes = validated_data.get('general_notes', instance.general_notes)
        instance.save()

        
        instance.feed_quantities.all().delete()
        for fq_data in feed_quantities_data:
            DailyFeedQuantity.objects.create(daily_log=instance, **fq_data)

        return instance
    
class BreedingRecordsSerializer(serializers.ModelSerializer):
    """
    Serializer for the BreedingRecords model.
    Handles nested cow and breed data.
    """
    cow_name = serializers.CharField(source='cow.name', read_only=True)
    class Meta:
        model = BreedingRecords
        fields = '__all__'
        extra_kwargs = {
            'expected_calving_date': {'required': False, 'allow_null': True}
        }

    def create(self, validated_data):
        return BreedingRecords.objects.create(**validated_data)
    def validate(self, data):
        if not data.get('cow'):
            raise serializers.ValidationError({"cow": "This field is required."})
        if not data.get('breeding_date'):
            raise serializers.ValidationError({"breeding_date": "This field is required."})
        return data
    
class CowHealthRecordSerializer(serializers.ModelSerializer):
    """
    Serializer for the CowHealthRecord model.
    Handles nested cow data.
    """
    cow_name = serializers.CharField(source='cow.name', read_only=True)

    class Meta:
        model = CowHealthRecord
        fields = '__all__'
        extra_kwargs = {
            'recorded_at': {'read_only': True}
        }

    def create(self, validated_data):
        user = self.context['request'].user
        return CowHealthRecord.objects.create(**validated_data)
    def validate(self, data):
        if not data.get('cow'):
            raise serializers.ValidationError({"cow": "This field is required."})

        return data

class CalfSerializer(serializers.ModelSerializer):
    dam_details = CowSerializer(source='dam', read_only=True)
    gender_display = serializers.CharField(source='get_gender_display', read_only=True)

    class Meta:
        model = Calf
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at', 'dam_details', 'gender_display']

class NotificationSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    class Meta:
        model = Notification
        fields = ['id', 'message', 'created_at', 'created_by', 'created_by_name']
        read_only_fields = ['created_at', 'created_by', 'created_by_name']