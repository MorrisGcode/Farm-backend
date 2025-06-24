from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import generics
from rest_framework.exceptions import PermissionDenied
from django.http import Http404 # Ensure Http404 is imported for FeedTypeRetrieveUpdateDestroyAPIView
from .serializers import (
    UserSerializer, CowSerializer, MilkProductionSerializer, BreedSerializer, 
    FeedTypeSerializer, DailyFeedingLogSerializer, BreedingRecordsSerializer, 
    CowHealthRecordSerializer, CalfSerializer, NotificationSerializer,
    RegisterSerializer, LoginSerializer # Ensure these are imported if used in register/login
)
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from django.core.exceptions import ValidationError
from datetime import datetime

from .models import farmuser, cows, MilkProduction, Breed, FeedType, DailyFeedingLog, BreedingRecords, CowHealthRecord, Calf, Notification

class RegisterView(APIView):
    """
    API view for user registration.
    Allows any user (even unauthenticated) to access this endpoint.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handles POST requests for user registration.
        Validates data using RegisterSerializer and creates a new user.
        """
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Optionally, generate tokens for the newly registered user
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "User registered successfully",
                "user": serializer.data['username'],
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    """
    API view for user login.
    Allows any user to access this endpoint.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handles POST requests for user login.
        Validates credentials using LoginSerializer and returns JWT tokens.
        """
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "Login successful",
                "user": user.username,
                "role": user.role, # Include role in the login response
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProtectedView(APIView):
    """
    A simple example view that requires JWT authentication.
    Only authenticated users can access this endpoint.
    """
    permission_classes = [IsAuthenticated] # Requires authentication

    def get(self, request):
        """
        Returns a protected message for authenticated users.
        """
        return Response({"message": f"Hello, {request.user.username}! You are authenticated."})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_data(request):
    user = request.user
    
    # Ensure role is retrieved correctly and compared consistently (e.g., uppercase)
    user_role = user.role.upper() if user.role else '' 

    if user_role == 'ADMIN':
        data = {
            'role': 'ADMIN',
            'features': [
                'User Management',
                'System Settings',
                'Reports Overview',
                'Farm Analytics'
            ]
        }
    elif user_role == 'MANAGER':
        data = {
            'role': 'MANAGER',
            'features': [
                'Task Management',
                'Inventory Control',
                'Worker Schedule',
                'Daily Reports'
            ]
        }
    else: # Default to WORKER if not ADMIN or MANAGER
        data = {
            'role': 'WORKER',
            'features': [
                'My Tasks',
                'Time Tracking',
                'Daily Schedule',
                'Submit Reports'
            ]
        }
    
    return Response(data, status=status.HTTP_200_OK)


class CowsListView(APIView):
    """
    API view to list and create cows.
    Only accessible by authenticated users.
    Managers can create, all authenticated users can view.
    """
    permission_classes = [IsAuthenticated] # Keep IsAuthenticated
    # If you implemented IsManager, it would look like this:
    # permission_classes = [IsAuthenticated, IsManager] 

    def get(self, request):
        # Both workers and managers can view cows
        cows_list = cows.objects.all() # Assuming 'cows' is your model
        serializer = CowSerializer(cows_list, many=True)
        return Response(serializer.data)

    def post(self, request):
        # Only managers can add cows
        # Convert role to uppercase for consistent comparison
        if request.user.role.upper() != 'MANAGER':
            return Response(
                {'message': 'Only managers can add cows'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = CowSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save() 
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




@api_view(['GET'])
@permission_classes([IsAuthenticated])
def cow_list(request):
    all_cows = cows.objects.all()
    serializer = CowSerializer(all_cows, many=True)
    return Response(serializer.data)

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        return Response({
            'username': request.user.username,
            'role': request.user.role,
            'email': request.user.email
        })

class MilkProductionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Both managers and workers can add milk records
        serializer = MilkProductionSerializer(
            data=request.data,
            context={'request': request}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        records = MilkProduction.objects.all()
        serializer = MilkProductionSerializer(records, many=True)
        return Response(serializer.data)

    def put(self, request, record_id):
        # Only workers can update their own records, managers can update all
        try:
            record = MilkProduction.objects.get(id=record_id)
            # Convert roles to uppercase for consistent comparison
            if request.user.role.upper() != 'MANAGER' and \
               (request.user.role.upper() != 'WORKER' or record.recorded_by != request.user):
                return Response(
                    {'message': 'You can only update your own records'}, 
                    status=status.HTTP_403_FORBIDDEN
                )

            serializer = MilkProductionSerializer(record, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except MilkProduction.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def milk_production_stats(request):
    # Convert role to uppercase for consistent comparison
    user_role = request.user.role.upper() if request.user.role else ''
    
    # Allow managers AND workers to view statistics
    if user_role not in ['MANAGER', 'WORKER']:
        return Response(
            {'message': 'Only managers and workers can view statistics'},
            status=status.HTTP_403_FORBIDDEN
        )

    today = datetime.now().date()
    stats = {
        'total_today': MilkProduction.objects.filter(date=today).aggregate(
            total=Sum('morning_amount') + Sum('evening_amount')
        )['total'] or 0,
        'cow_stats': []
    }

    for cow in cows.objects.all():
        cow_stats = {
            'cow_name': cow.name,
            'today_total': MilkProduction.objects.filter(
                cow=cow, 
                date=today
            ).aggregate(
                total=Sum('morning_amount') + Sum('evening_amount')
            )['total'] or 0,
        }
        stats['cow_stats'].append(cow_stats)

    return Response(stats)

class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        try:
            # Convert role to uppercase for consistent comparison
            user_role = user.role.upper() if user.role else ''

            if user_role == 'MANAGER':
                # Manager dashboard stats
                total_cows = cows.objects.count()
                healthy_cows = cows.objects.filter(health_status='HEALTHY').count()
                sick_cows = total_cows - healthy_cows
                
                today = timezone.now().date()
                milk_records = MilkProduction.objects.filter(date=today)
                total_milk_today = sum(r.morning_amount + r.evening_amount for r in milk_records)
                
                return Response({
                    'totalCows': total_cows,
                    'healthyCows': healthy_cows,
                    'sickCows': sick_cows,
                    'totalMilkToday': total_milk_today
                })
            else: # Default to Worker stats if not MANAGER (or ADMIN if you add that logic)
                # Worker dashboard stats
                today = timezone.now().date()
                assigned_records = MilkProduction.objects.filter(
                    recorded_by=user,
                    date=today
                )
                
                total_milk = sum(r.morning_amount + r.evening_amount for r in assigned_records)
                
                return Response({
                    'assigned_cows': cows.objects.filter(milk_records__recorded_by=user).distinct().count(),
                    'records_today': assigned_records.count(),
                    'total_milk_recorded': total_milk
                })
                
        except Exception as e:
            print(f"Dashboard Error: {str(e)}")
            return Response(
                {'error': 'Failed to load dashboard data'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class MilkProductionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get filter parameters
            cow_id = request.query_params.get('cow')
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')

            queryset = MilkProduction.objects.all().select_related('cow', 'recorded_by')

            # Apply filters
            if cow_id and cow_id != 'all':
                queryset = queryset.filter(cow_id=cow_id)
            
            if start_date:
                try:
                    queryset = queryset.filter(date__gte=start_date)
                except ValidationError:
                    return Response(
                        {'error': 'Invalid start date format'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            if end_date:
                try:
                    queryset = queryset.filter(date__lte=end_date)
                except ValidationError:
                    return Response(
                        {'error': 'Invalid end date format'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            queryset = queryset.order_by('-date')
            serializer = MilkProductionSerializer(queryset, many=True)
            return Response(serializer.data)

        except Exception as e:
            print(f"Error in MilkProductionListView: {str(e)}")
            return Response(
                {'error': 'Failed to fetch milk records'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CowDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            cow = cows.objects.select_related('owner').get(pk=pk)
            serializer = CowSerializer(cow)
            return Response(serializer.data)
        except cows.DoesNotExist:
            return Response(
                {'error': 'Cow not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, pk):
        try:
            # Convert role to uppercase for consistent comparison
            if request.user.role.upper() != 'MANAGER':
                return Response(
                    {'error': 'Only managers can edit cow details'},
                    status=status.HTTP_403_FORBIDDEN
                )

            cow = cows.objects.get(pk=pk)
            serializer = CowSerializer(cow, data=request.data, partial=True)
            
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except cows.DoesNotExist:
            return Response(
                {'error': 'Cow not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )


class BreedListCreateView(generics.ListCreateAPIView):
    queryset = Breed.objects.all()
    serializer_class = BreedSerializer
    # Add permissions to restrict creation/deletion if needed, e.g., IsManager

class BreedDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Breed.objects.all()
    serializer_class = BreedSerializer
    # Add permissions to restrict creation/deletion if needed, e.g., IsManager

class FeedTypeListCreateAPIView(APIView):
    """
    API endpoint for listing and creating FeedType objects.
    Corresponds to GET and POST requests to /api/feedtypes/.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        """
        List all feed types.
        """
        feed_types = FeedType.objects.all()
        serializer = FeedTypeSerializer(feed_types, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        """
        Create a new feed type.
        Only managers should create feed types.
        """
        if request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can add feed types.")
        
        serializer = FeedTypeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FeedTypeRetrieveUpdateDestroyAPIView(APIView):
    """
    API endpoint for retrieving, updating, and deleting a single FeedType object.
    Corresponds to GET, PUT, PATCH, and DELETE requests to /api/feedtypes/<pk>/
    """
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        """
        Helper method to get a FeedType object by its primary key (pk),
        raising Http404 if not found.
        """
        try:
            return FeedType.objects.get(pk=pk)
        except FeedType.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        """
        Retrieve a single feed type.
        """
        feed_type = self.get_object(pk)
        serializer = FeedTypeSerializer(feed_type)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        """
        Update an existing feed type (full update).
        Only managers should update feed types.
        """
        if request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can update feed types.")

        feed_type = self.get_object(pk)
        serializer = FeedTypeSerializer(feed_type, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        """
        Partially update an existing feed type.
        Only managers should update feed types.
        """
        if request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can update feed types.")

        feed_type = self.get_object(pk)
        serializer = FeedTypeSerializer(feed_type, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        """
        Delete a feed type.
        Only managers should delete feed types.
        """
        if request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can delete feed types.")

        feed_type = self.get_object(pk)
        feed_type.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class DailyFeedingLogListCreateAPIView(APIView):
    """
    API endpoint for listing and creating DailyFeedingLog objects with role-based permissions.
    Supports nested creation of DailyFeedQuantity items.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        # Convert role to uppercase for consistent comparison
        user_role = request.user.role.upper() if request.user.role else ''

        if user_role == 'MANAGER':
            logs = DailyFeedingLog.objects.all()
        elif user_role == 'WORKER':
            logs = DailyFeedingLog.objects.filter(worker_name=request.user.username)
        else:
            raise PermissionDenied("You do not have permission to view feeding logs.")

        # Pass context to serializer for nested relationships if needed, though not strictly required for read-only
        serializer = DailyFeedingLogSerializer(logs, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request, format=None):
        # Convert role to uppercase for consistent comparison
        if request.user.role.upper() != 'WORKER':
            raise PermissionDenied("Only workers can add feeding logs.")

        # Worker name is handled automatically by the serializer's create method
        # Pass data directly to serializer, worker_name read_only_field handles it
        serializer = DailyFeedingLogSerializer(data=request.data)

        if serializer.is_valid():
            # Pass worker_name to serializer's save method for automatic population
            serializer.save(worker_name=request.user.username)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DailyFeedingLogRetrieveUpdateDestroyAPIView(APIView):
    """
    API endpoint for retrieving, updating, and deleting a single DailyFeedingLog object
    with role-based permissions.
    Supports nested updates for DailyFeedQuantity items.
    """
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            # Select related feed_quantities to reduce queries
            return DailyFeedingLog.objects.prefetch_related('feed_quantities').get(pk=pk)
        except DailyFeedingLog.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        log = self.get_object(pk)
        # Convert roles to uppercase for consistent comparison
        user_role = request.user.role.upper() if request.user.role else ''
        if user_role == 'MANAGER' or (user_role == 'WORKER' and log.worker_name == request.user.username):
            serializer = DailyFeedingLogSerializer(log, context={'request': request})
            return Response(serializer.data)
        else:
            raise PermissionDenied("You do not have permission to view this feeding log.")

    def put(self, request, pk, format=None):
        log = self.get_object(pk)
        
        user_role = request.user.role.upper() if request.user.role else ''
        if user_role == 'MANAGER' or (user_role == 'WORKER' and log.worker_name == request.user.username):
            #
            serializer = DailyFeedingLogSerializer(log, data=request.data, partial=False)
            if serializer.is_valid():
              
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            raise PermissionDenied("You do not have permission to update this feeding log.")

    def patch(self, request, pk, format=None):
        log = self.get_object(pk)
        # Convert roles to uppercase for consistent comparison
        user_role = request.user.role.upper() if request.user.role else ''
        if user_role == 'MANAGER' or (user_role == 'WORKER' and log.worker_name == request.user.username):
            serializer = DailyFeedingLogSerializer(log, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            raise PermissionDenied("You do not have permission to update this feeding log.")

    def delete(self, request, pk, format=None):
        log = self.get_object(pk)
        n
        user_role = request.user.role.upper() if request.user.role else ''
        if user_role == 'MANAGER' or (user_role == 'WORKER' and log.worker_name == request.user.username):
            log.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            raise PermissionDenied("You do not have permission to delete this feeding log.")
        
class BreedingRecordsListCreateView(generics.ListCreateAPIView):
    """
    API endpoint for listing and creating BreedingRecords.
    Only accessible by authenticated users.
    """
    permission_classes = [IsAuthenticated]
    queryset = BreedingRecords.objects.all()
    serializer_class = BreedingRecordsSerializer

    def perform_create(self, serializer):
       
        serializer.save()

class BreedingRecordsDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    API endpoint for retrieving, updating, and deleting a single BreedingRecord.
    Only accessible by authenticated users.
    Managers can edit/delete all, workers can only view or edit their own if applicable.
    """
    permission_classes = [IsAuthenticated]
    queryset = BreedingRecords.objects.all()
    serializer_class = BreedingRecordsSerializer

    def get_object(self):
        obj = super().get_object()
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        
        if user_role == 'MANAGER' or self.request.user.is_staff: 
            return obj
        
        raise PermissionDenied("You do not have permission to view this record.")

    def perform_update(self, serializer):
        if self.request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can update breeding records.")
        serializer.save()

    def perform_destroy(self, instance):
        if self.request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can delete breeding records.")
        instance.delete()


class CowHealthRecordListCreateAPIView(generics.ListCreateAPIView):
    """
    API endpoint to list all cow health records or create a new one.
    """
    queryset = CowHealthRecord.objects.all()
    serializer_class = CowHealthRecordSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        if user_role == 'MANAGER':
            return CowHealthRecord.objects.all().select_related('cow')
        elif user_role == 'WORKER':
            # Assuming CowHealthRecord has a 'recorded_by' field linked to farmuser
            return CowHealthRecord.objects.filter(recorded_by=self.request.user).select_related('cow')
        raise PermissionDenied("You do not have permission to view health records.")

    def perform_create(self, serializer):
        
        serializer.save(recorded_by=self.request.user)

class CowHealthRecordRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    """
    API endpoint to retrieve, update, or delete a specific cow health record.
    """
    queryset = CowHealthRecord.objects.all()
    serializer_class = CowHealthRecordSerializer
    permission_classes = [IsAuthenticated] 

    def get_object(self):
        obj = super().get_object()
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        # Managers can view/edit/delete any. Workers can only if they created it.
        if user_role == 'MANAGER' or obj.recorded_by == self.request.user:
            return obj
        raise PermissionDenied("You do not have permission to access this health record.")

    def perform_update(self, serializer):
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        if user_role == 'MANAGER' or self.get_object().recorded_by == self.request.user:
            serializer.save()
        else:
            raise PermissionDenied("You do not have permission to update this health record.")

    def perform_destroy(self, instance):
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        if user_role == 'MANAGER' or instance.recorded_by == self.request.user:
            instance.delete()
        else:
            raise PermissionDenied("You do not have permission to delete this health record.")


class CalfListCreateAPIView(generics.ListCreateAPIView):
    queryset = Calf.objects.all()
    serializer_class = CalfSerializer
    permission_classes = [IsAuthenticated] # Add IsAuthenticated

    def get_queryset(self):
       
        return Calf.objects.all()

    def perform_create(self, serializer):
        
        if self.request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can add calves.")
        serializer.save()


class CalfRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Calf.objects.all()
    serializer_class = CalfSerializer
    lookup_field = 'pk'
    permission_classes = [IsAuthenticated] 

    def get_object(self):
        obj = super().get_object()
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        
        if user_role == 'MANAGER':
            return obj
        
        raise PermissionDenied("You do not have permission to perform this action on calf records.")

    def perform_update(self, serializer):
        if self.request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can update calf records.")
        serializer.save()

    def perform_destroy(self, instance):
        if self.request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can delete calf records.")
        instance.delete()


class NotificationListCreateView(generics.ListCreateAPIView):
    queryset = Notification.objects.order_by('-created_at')
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        # Only managers can create notifications
        if self.request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can create notifications.")
        serializer.save(created_by=self.request.user)

    def get_queryset(self):
                     
        return Notification.objects.order_by('-created_at')

