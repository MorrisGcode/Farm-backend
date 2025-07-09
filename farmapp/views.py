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
from django.http import Http404 
from .serializers import (
    UserSerializer, CowSerializer, MilkProductionSerializer, BreedSerializer,
    FeedTypeSerializer, DailyFeedingLogSerializer, BreedingRecordsSerializer,
    CowHealthRecordSerializer, CalfSerializer, NotificationSerializer,
    RegisterSerializer, LoginSerializer, MilkSalesSerializer, ExpenseSerializer, ContactMessageSerializer
)
from django.db import transaction
from django.db.models import Sum, Count, F, ExpressionWrapper, fields
from django.db.models.functions import TruncDate, TruncWeek, TruncMonth
from django.utils import timezone
from django.core.exceptions import ValidationError
from datetime import datetime
from collections import defaultdict

from .models import farmuser, cows, MilkProduction, Breed, FeedType, DailyFeedingLog, BreedingRecords, CowHealthRecord, Calf, Notification, MilkSales, Expense
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.core.mail import send_mail
from django.conf import settings

class RegisterView(APIView):
    """
    API view for user registration.
    Allows any user (even unauthenticated) to access this endpoint.
    """
    serializer_class = RegisterSerializer
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
            user_role = request.user.role.upper() if request.user.role else ''
            # Allow managers and workers to view detailed milk records
            if user_role not in ['MANAGER', 'WORKER']:
                raise PermissionDenied("You do not have permission to view milk records.")

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

        except PermissionDenied as e:
            return Response({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            print(f"Error in MilkProductionListView: {str(e)}")
            return Response(
                {'error': 'Failed to fetch milk records'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# --- New Views for Milk Production Analytics ---

class BaseMilkSummaryView(generics.ListAPIView):
    """
    Base view for milk production summaries (Daily, Weekly, Monthly).
    Handles common filtering logic and permission checks.
    """
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        # Allow managers and workers to view summary statistics
        if user_role not in ['MANAGER', 'WORKER']:
            raise PermissionDenied("You do not have permission to view milk production summaries.")

        queryset = MilkProduction.objects.all()

        cow_id = self.request.query_params.get('cow')
        start_date_str = self.request.query_params.get('start_date')
        end_date_str = self.request.query_params.get('end_date')

        if cow_id:
            try:
                queryset = queryset.filter(cow_id=int(cow_id))
            except ValueError:
                raise ValidationError({"cow": "Invalid cow ID format."})
        
        if start_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                queryset = queryset.filter(date__gte=start_date)
            except ValueError:
                raise ValidationError({"start_date": "Invalid start date format. Use YYYY-MM-DD."})
        
        if end_date_str:
            try:
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
                queryset = queryset.filter(date__lte=end_date)
            except ValueError:
                raise ValidationError({"end_date": "Invalid end date format. Use YYYY-MM-DD."})
        
        return queryset

class DailyMilkSummaryView(BaseMilkSummaryView):
    """
    API endpoint for daily milk production summary.
    Aggregates total milk per day.
    """
    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            
            summary_data = queryset.annotate(
                # Renamed 'date' to 'summary_date' to avoid conflict
                summary_date=TruncDate('date') 
            ).values('summary_date').annotate(
                total_milk=Sum('morning_amount') + Sum('evening_amount'),
                record_count=Count('id')
            ).order_by('summary_date') # Order by the new alias
            
            # Convert QuerySet to a list of dictionaries for JSON response
            return Response(list(summary_data))
        except ValidationError as e:
            return Response({'error': e.detail}, status=status.HTTP_400_BAD_REQUEST)
        except PermissionDenied as e:
            return Response({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            print(f"Error in DailyMilkSummaryView: {str(e)}")
            return Response(
                {'error': 'Failed to generate daily milk summary'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class WeeklyMilkSummaryView(BaseMilkSummaryView):
    """
    API endpoint for weekly milk production summary.
    Aggregates total milk per week.
    """
    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()

            summary_data = queryset.annotate(
                # Renamed 'week_start_date' to avoid conflict
                week_start_date=TruncWeek('date') 
            ).values('week_start_date').annotate(
                total_milk=Sum('morning_amount') + Sum('evening_amount'),
                record_count=Count('id')
            ).order_by('week_start_date') # Order by the new alias

            return Response(list(summary_data))
        except ValidationError as e:
            return Response({'error': e.detail}, status=status.HTTP_400_BAD_REQUEST)
        except PermissionDenied as e:
            return Response({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            print(f"Error in WeeklyMilkSummaryView: {str(e)}")
            return Response(
                {'error': 'Failed to generate weekly milk summary'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class MonthlyMilkSummaryView(BaseMilkSummaryView):
    """
    API endpoint for monthly milk production summary.
    Aggregates total milk per month.
    """
    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            
            summary_data = queryset.annotate(
                # Renamed 'month' to 'month_start_date' to avoid conflict
                month_start_date=TruncMonth('date') 
            ).values('month_start_date').annotate(
                total_milk=Sum('morning_amount') + Sum('evening_amount'),
                record_count=Count('id')
            ).order_by('month_start_date') # Order by the new alias

            return Response(list(summary_data))
        except ValidationError as e:
            return Response({'error': e.detail}, status=status.HTTP_400_BAD_REQUEST)
        except PermissionDenied as e:
            return Response({'error': str(e)}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            print(f"Error in MonthlyMilkSummaryView: {str(e)}")
            return Response(
                {'error': 'Failed to generate monthly milk summary'},
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
        # By default, only managers can create breeding records for consistency
        if self.request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can add breeding records.")
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
        # Since 'recorded_by' is removed from the model, we can no longer filter by it.
        # Managers can see all health records.
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        if user_role == 'MANAGER':
            return CowHealthRecord.objects.all().select_related('cow')
        # If workers should see records, you'd need another way to associate them,
        # e.g., if a worker is assigned to a cow, or if 'recorded_by' was re-added.
        # For now, if no 'recorded_by' field, workers won't see records here.
        raise PermissionDenied("You do not have permission to view health records.")

    def perform_create(self, serializer):
        # Removed: serializer.save(recorded_by=self.request.user)
        # Since 'recorded_by' is removed from the model, this line must be removed.
        serializer.save() # Save without the 'recorded_by' argument

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
        # Managers can view/edit/delete any.
        # Removed: Workers can only if they created it (since 'recorded_by' is gone).
        if user_role == 'MANAGER': # Only managers can access if 'recorded_by' is removed
            return obj
        raise PermissionDenied("You do not have permission to access this health record.")

    def perform_update(self, serializer):
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        if user_role == 'MANAGER': # Only managers can update if 'recorded_by' is removed
            serializer.save()
        else:
            raise PermissionDenied("You do not have permission to update this health record.")

    def perform_destroy(self, instance):
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        if user_role == 'MANAGER': # Only managers can delete if 'recorded_by' is removed
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

class MilkSalesListCreateView(generics.ListCreateAPIView):
    """
    API endpoint for listing and creating MilkSales records.
    Only accessible by authenticated users.
    """
    queryset = MilkSales.objects.all()
    serializer_class = MilkSalesSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        # Only managers can create milk sales records
        if self.request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can add milk sales records.")
        # CORRECTED: Use 'sold_by' instead of 'created_by'
        serializer.save(sold_by=self.request.user)

class MilkSalesDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    API endpoint for retrieving, updating, and deleting a single MilkSales record.
    Only accessible by authenticated users.
    Managers can edit/delete all, workers can only view or edit their own if applicable.
    """
    queryset = MilkSales.objects.all()
    serializer_class = MilkSalesSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        obj = super().get_object()
        user_role = self.request.user.role.upper() if self.request.user.role else ''
        # ... (rest of your get_object logic) ...
        return obj # Make sure you return obj at the end

User = get_user_model() # Get your custom User model

class ExpenseListCreateView(generics.ListCreateAPIView):
    """
    API endpoint for listing and creating Expense records.
    Only accessible by authenticated users.
    Managers can create and view all. Workers can view only their recorded expenses.
    """
    serializer_class = ExpenseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            if user.role.upper() == 'MANAGER':
                return Expense.objects.all()
            elif user.role.upper() == 'WORKER':
                
                return Expense.objects.filter(Q(recorded_by=user) | Q(worker_paid=user))
        return Expense.objects.none() 

    def perform_create(self, serializer):
        user = self.request.user
        if user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can add expense records.")
        serializer.save(recorded_by=user)

class ExpenseDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    API endpoint for retrieving, updating, and deleting a single Expense record.
    Only accessible by authenticated users.
    Managers can edit/delete all. Workers can only edit/delete their own recorded expenses.
    """
    queryset = Expense.objects.all()
    serializer_class = ExpenseSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        obj = super().get_object()
        user = self.request.user

        if user.is_authenticated:
            if user.role.upper() == 'MANAGER':
                return obj # Managers can access any expense
            elif user.role.upper() == 'WORKER':
                # Workers can only access expenses they recorded
                if obj.recorded_by == user:
                    return obj
                else:
                    raise PermissionDenied("You do not have permission to access this expense record.")
        raise PermissionDenied("Authentication required to access this record.")

    def perform_update(self, serializer):
        user = self.request.user
        if user.role.upper() != 'MANAGER' and serializer.instance.recorded_by != user:
            raise PermissionDenied("You do not have permission to edit this expense record.")
        serializer.save()

    def perform_destroy(self, instance):
        user = self.request.user
        if user.role.upper() != 'MANAGER' and instance.recorded_by != user:
            raise PermissionDenied("You do not have permission to delete this expense record.")
        instance.delete()


class UserListView(generics.ListAPIView):
    """
    API endpoint for listing all farm users.
    Can be used to populate dropdowns (e.g., for 'worker_paid').
    """
    queryset = farmuser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated] # Ensure only authenticated users can access

class ContactMessageView(APIView):
    """
    API endpoint for handling contact form submissions.
    - Saves the message to the database.
    - Sends an email notification to the site administrator.
    """
    def post(self, request, format=None):
        serializer = ContactMessageSerializer(data=request.data)
        if serializer.is_valid():
            # Save the message to the database
            serializer.save()

            name = serializer.validated_data.get('name')
            email = serializer.validated_data.get('email')
            message = serializer.validated_data.get('message')

            subject = f"New Contact Form Message from {name}"
            email_message = f"""
            You have received a new message from the FarmConnect contact form.

            Name: {name}
            Email: {email}
            Message:
            {message}
            """
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [settings.EMAIL_HOST_USER] 

            try:
                send_mail(
                    subject,
                    email_message,
                    from_email,
                    recipient_list,
                    fail_silently=False, # Set to True in production to avoid crashing on email errors
                )
                return Response(
                    {"message": "Thank you for your message! We will get back to you soon."},
                    status=status.HTTP_201_CREATED
                )
            except Exception as e:
                print(f"Error sending email: {e}")
                return Response(
                    {"message": "Message received, but failed to send notification email. Please check server logs."},
                    status=status.HTTP_201_CREATED 
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MilkProductionReportView(APIView):
    """
    API endpoint to generate milk production reports.
    Filters by date range and provides total milk and daily breakdown.
    Accessible by Managers.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        if request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can generate milk production reports.")

        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')

        if not start_date_str or not end_date_str:
            return Response({'error': 'Both start_date and end_date are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)

        if start_date > end_date:
            return Response({'error': 'Start date cannot be after end date.'}, status=status.HTTP_400_BAD_REQUEST)

        # Filter milk production records within the date range
        milk_records = MilkProduction.objects.filter(
            date__range=[start_date, end_date]
        ).select_related('cow').order_by('date')

        total_milk_produced = milk_records.aggregate(
            total=Sum(F('morning_amount') + F('evening_amount'))
        )['total'] or 0.0

        # Daily breakdown
        daily_breakdown = defaultdict(float)
        for record in milk_records:
            total_daily = (record.morning_amount or 0.0) + (record.evening_amount or 0.0)
            daily_breakdown[str(record.date)] += total_daily

        # Convert to list of dicts for consistent JSON output
        daily_breakdown_list = [
            {'date': date_str, 'total_liters': round(amount, 2)}
            for date_str, amount in sorted(daily_breakdown.items())
        ]

        # Cow-wise breakdown (optional, but useful for reports)
        cow_breakdown = defaultdict(float)
        for record in milk_records:
            cow_breakdown[record.cow.name] += (record.morning_amount or 0.0) + (record.evening_amount or 0.0)
        
        cow_breakdown_list = [
            {'cow_name': cow_name, 'total_liters': round(amount, 2)}
            for cow_name, amount in sorted(cow_breakdown.items())
        ]

        report_data = {
            'start_date': start_date_str,
            'end_date': end_date_str,
            'total_milk_produced': round(total_milk_produced, 2),
            'daily_breakdown': daily_breakdown_list,
            'cow_breakdown': cow_breakdown_list,
        }

        return Response(report_data, status=status.HTTP_200_OK)

class MilkSalesReporterView(APIView):
    """
    API endpoint to generate milk sales reports.
    Filters by date range and provides total sales amount, total liters sold, and daily breakdown.
    Accessible by Managers.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        if request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can generate milk sales reports.")

        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')

        if not start_date_str or not end_date_str:
            return Response({'error': 'Both start_date and end_date are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)

        if start_date > end_date:
            return Response({'error': 'Start date cannot be after end date.'}, status=status.HTTP_400_BAD_REQUEST)

        # Filter milk sales records within the date range
        sales_records = MilkSales.objects.filter(
            sale_date__range=[start_date, end_date]
        ).select_related('milk_record__cow').order_by('sale_date')

        total_sales_amount = sales_records.aggregate(total=Sum('total_sale_amount'))['total'] or 0.0
        total_liters_sold = sales_records.aggregate(total=Sum('quantity_sold'))['total'] or 0.0

        # Daily breakdown of sales
        daily_sales_breakdown = defaultdict(lambda: {'amount': 0.0, 'liters': 0.0})
        for record in sales_records:
            daily_sales_breakdown[str(record.sale_date)]['amount'] += float(record.total_sale_amount or 0.0)
            daily_sales_breakdown[str(record.sale_date)]['liters'] += float(record.quantity_sold or 0.0)

        daily_sales_breakdown_list = [
            {'date': date_str, 'total_amount': round(data['amount'], 2), 'total_liters': round(data['liters'], 2)}
            for date_str, data in sorted(daily_sales_breakdown.items())
        ]

        report_data = {
            'start_date': start_date_str,
            'end_date': end_date_str,
            'total_sales_amount': round(total_sales_amount, 2),
            'total_liters_sold': round(total_liters_sold, 2),
            'daily_sales_breakdown': daily_sales_breakdown_list,
        }

        return Response(report_data, status=status.HTTP_200_OK)

class FeedingReportView(APIView):
    """
    API endpoint to generate feeding reports.
    Filters by date range and provides total quantity of each feed type and daily log details.
    Accessible by Managers.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        if request.user.role.upper() != 'MANAGER':
            raise PermissionDenied("Only managers can generate feeding reports.")

        start_date_str = request.query_params.get('start_date')
        end_date_str = request.query_params.get('end_date')

        if not start_date_str or not end_date_str:
            return Response({'error': 'Both start_date and end_date are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)

        if start_date > end_date:
            return Response({'error': 'Start date cannot be after end date.'}, status=status.HTTP_400_BAD_REQUEST)

        # Filter daily feeding logs within the date range
        feeding_logs = DailyFeedingLog.objects.filter(
            log_date__range=[start_date, end_date]
        ).prefetch_related('feed_quantities__feed_type').order_by('log_date')

        # Aggregate total quantity per feed type
        feed_type_totals = defaultdict(float)
        for log in feeding_logs:
            for fq in log.feed_quantities.all():
                feed_type_totals[fq.feed_type.name] += float(fq.quantity) # Convert Decimal to float for sum

        feed_type_totals_list = [
            {'feed_type_name': name, 'total_quantity': round(quantity, 2)}
            for name, quantity in sorted(feed_type_totals.items())
        ]

        # Serialize detailed daily logs for the report
        detailed_logs_serializer = DailyFeedingLogSerializer(feeding_logs, many=True)

        report_data = {
            'start_date': start_date_str,
            'end_date': end_date_str,
            'feed_type_totals': feed_type_totals_list,
            'detailed_logs': detailed_logs_serializer.data, # Includes nested feed quantities
        }

        return Response(report_data, status=status.HTTP_200_OK)
