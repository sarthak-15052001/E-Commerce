from django.urls import path, include
from userauths.api import views
from rest_framework.routers import DefaultRouter
from userauths.api.views import AdminCustomerViewSet, AdminOrderViewSet, AdminOrderDetailViewSet


router = DefaultRouter()
router.register(r"admin_customers", AdminCustomerViewSet, basename="customers")
router.register(r"admin_orders", AdminOrderViewSet, basename="orders")
router.register(r"admin_orders_detail", AdminOrderDetailViewSet, basename="orderdetail")


urlpatterns = [
    # User AUths Urls Starts From Here
    path("api/userauth/signup", views.SignupView.as_view(), name="signup"),
    path("api/token/", views.LoginView.as_view(), name="login"),
    path("api/token/refresh/", views.CustomTokenRefreshView.as_view(), name="token_refresh"),
    path("api/userauth/verify-email/<str:token>", views.VerifyEmailView.as_view(), name="verify-email"),
    path("api/userauth/change-password/", views.ChangePassword.as_view(), name="changepassword"),
    path("api/userauth/forgotpassword/", views.ForgetPasswordView.as_view(), name="forgotpassword",),
    path("api/userauth/reset-password/<str:token>", views.ResetPasswordView.as_view(), name="resetpassword",),
    path("api/userauth/signout/", views.SignoutView.as_view(), name="signout"),
    

    # Admin Urls Starts From Here
    path("api/admin/profile/", views.AdminProfileView.as_view(), name='admin-profile'),
    path("api/admin/dashboard/", views.AdminDasboardAPIView.as_view(), name="dashboard"),
    path("api/admin/categories/", views.AdminCategoryListCreateView.as_view(), name='admin-category-list-create'),
    path("api/admin/categories/<int:pk>/", views.AdminCategoryRetrievUpdateDeleteView.as_view(), name="admin-category-detail"),
    path("api/admin/products/", views.AdminProductListCreateView.as_view(), name='admin-product-list-create'),
    path("api/admin/products/<int:pk>/", views.AdminProductRetrieveUpdateDeletelView.as_view(), name='admin-detail'),
   
   
   
    path("api/", include(router.urls)),
]