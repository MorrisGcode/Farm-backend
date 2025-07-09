from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views
from .views import DashboardView, MilkProductionView # Ensure MilkProductionView is imported

urlpatterns = [
    # Endpoint for user login (obtaining access and refresh tokens)
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # Endpoint to refresh an access token using a refresh token
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # Endpoint for user registration
    path('register/', views.RegisterView.as_view(), name='register'),
    # A protected endpoint accessible only by authenticated users
    path('protected/', views.ProtectedView.as_view(), name='protected'),
    
    # Dashboard & User
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('user/', views.UserDetailView.as_view(), name='user-detail'),
    path('users/', views.UserListView.as_view(), name='user-list'),
    

    # Cows
    path('cows/', views.CowsListView.as_view(), name='cows-list-create'),
    path('cows/<int:pk>/', views.CowDetailView.as_view(), name='cow-detail'),
    

    # Milk Production Records & Stats
    # path('milk-production/', views.MilkProductionListView.as_view(), name='milk-production-list'),
    path('milk-production/', MilkProductionView.as_view(), name='milk-production'), 
    path('milk-production/<int:record_id>/', MilkProductionView.as_view(), name='milk-production-detail-update'), # For PUT on a specific record_id
    path('milk-production/stats/', views.milk_production_stats, name='milk-production-stats'),
    path('milk-records/', views.MilkProductionListView.as_view(), name='milk-records-list-filtered'),

    # New Milk Production Analytics
    path('milk-records/daily-summary/', views.DailyMilkSummaryView.as_view(), name='milk-daily-summary'),
    path('milk-records/weekly-summary/', views.WeeklyMilkSummaryView.as_view(), name='milk-weekly-summary'),
    path('milk-records/monthly-summary/', views.MonthlyMilkSummaryView.as_view(), name='milk-monthly-summary'),

    # Breeds
    path('breeds/', views.BreedListCreateView.as_view(), name='breed-list-create'),
    path('breeds/<int:pk>/', views.BreedDetailView.as_view(), name='breed-detail'),

    # Feed Types
    path('feedtypes/', views.FeedTypeListCreateAPIView.as_view(), name='feedtype-list-create'),
    path('feedtypes/<int:pk>/', views.FeedTypeRetrieveUpdateDestroyAPIView.as_view(), name='feedtype-detail'),

    # Daily Feeding Logs
    path('dailyfeedinglogs/', views.DailyFeedingLogListCreateAPIView.as_view(), name='dailyfeedinglog-list-create'),
    path('dailyfeedinglogs/<int:pk>/', views.DailyFeedingLogRetrieveUpdateDestroyAPIView.as_view(), name='dailyfeedinglog-detail'),
    
    # Breeding Records
    path('breeding-records/', views.BreedingRecordsListCreateView.as_view(), name='breeding-records-list-create'),
    path('breeding-records/<int:pk>/', views.BreedingRecordsDetailView.as_view(), name='breeding-records-detail'),

    # Cow Health Records
    path('health-records/', views.CowHealthRecordListCreateAPIView.as_view(), name='health-record-list-create'),
    path('health-records/<int:pk>/', views.CowHealthRecordRetrieveUpdateDestroyAPIView.as_view(), name='health-record-detail'),
    
    # Calves
    path('calves/', views.CalfListCreateAPIView.as_view(), name='calf-list-create'),
    path('calves/<int:pk>/', views.CalfRetrieveUpdateDestroyAPIView.as_view(), name='calf-detail'),
    
    # Notifications
    path('notifications/', views.NotificationListCreateView.as_view(), name='notifications'),

    # Milk Sales
    path('milk-sales/', views.MilkSalesListCreateView.as_view(), name='milk-sales-list-create'),
    path('milk-sales/<int:pk>/', views.MilkSalesDetailView.as_view(), name='milk-sales-detail-update'),

    # Expenses
    path('expenses/', views.ExpenseListCreateView.as_view(), name='expense-list-create'),
    path('expenses/<int:pk>/', views.ExpenseDetailView.as_view(), name='expense-detail-update'),

    # Contact Messages
    path('contact/', views.ContactMessageView.as_view(), name='contact-message-create'),
    # Reports
    path('reports/milk-production/', views.MilkProductionReportView.as_view(), name='milk-production-report'),
    path('reports/milk-sales/', views.MilkSalesReporterView.as_view(), name='milk-sales-report'),
    path('reports/feeding/', views.FeedingReportView.as_view(), name='feeding-report'),
]                                   