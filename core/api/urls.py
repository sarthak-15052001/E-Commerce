from django.urls import path
from core.api import views



urlpatterns = [
    path("api/user/dashboard/", views.UserDashboardAPIView.as_view(), name="user-dashboard"),
    path("api/user/order-list/", views.UserOrderListAPIView.as_view(), name="user-order-list"),
    path("api/user/order-detail/", views.UserOrderDetailAPIView.as_view(), name="user-order-detail"),
]