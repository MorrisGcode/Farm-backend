from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views
from .views import DashboardView

urlpatterns = [
    # Endpoint for user login (obtaining access and refresh tokens)
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # Endpoint to refresh an access token using a refresh token
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    # Endpoint for user registration
    path('register/', views.RegisterView.as_view(), name='register'),
    # A protected endpoint accessible only by authenticated users
    path('protected/', views.ProtectedView.as_view(), name='protected'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('cows/', views.CowsListView.as_view(), name='cows'),
    path('user/', views.UserDetailView.as_view(), name='user-detail'),
    path('milk-production/', views.MilkProductionView.as_view(), name='milk-production'),
    path('milk-production/<int:cow_id>/', views.MilkProductionView.as_view(), name='cow-milk-production'),
    path('milk-production/stats/', views.milk_production_stats, name='milk-production-stats'),
    path('milk-records/', views.MilkProductionListView.as_view(), name='milk-records'),
    path('cows/<int:pk>/', views.CowDetailView.as_view(), name='cow-detail'),
    path('breeds/', views.BreedListCreateView.as_view(), name='breed-list-create'),
    path('breeds/<int:pk>/', views.BreedDetailView.as_view(), name='breed-detail'),
    path('feedtypes/', views.FeedTypeListCreateAPIView.as_view(), name='feed-list-create'),
    path('feedtypes/<int:pk>/', views.FeedTypeRetrieveUpdateDestroyAPIView.as_view(), name='feedtype-detail'),
    path('dailyfeedinglogs/', views.DailyFeedingLogListCreateAPIView.as_view(), name='dailyfeedinglog-list-create'), # New
    path('dailyfeedinglogs/<int:pk>/', views.DailyFeedingLogRetrieveUpdateDestroyAPIView.as_view(), name='dailyfeedinglog-detail'),
    path('breeding-records/', views.BreedingRecordsListCreateView.as_view(), name='breeding-records-list-create'),
    path('breeding-records/<int:pk>/', views.BreedingRecordsDetailView.as_view(), name='breeding-records-detail'),
    path('health-records/', views.CowHealthRecordListCreateAPIView.as_view(), name='health-record-list-create'),
    path('health-records/<int:pk>/', views.CowHealthRecordRetrieveUpdateDestroyAPIView.as_view(), name='health-record-detail'),
    path('calves/', views.CalfListCreateAPIView.as_view(), name='calf-list-create'),
    path('calves/<int:pk>/', views.CalfRetrieveUpdateDestroyAPIView.as_view(), name='calf-detail'),
    path('notifications/', views.NotificationListCreateView.as_view(), name='notifications'),

]