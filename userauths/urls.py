from django.urls import path
from userauths import views
from userauths.forms import *

app_name = "userauths"

urlpatterns = [
    path('sign-up/', views.SignupView.as_view(), name="sign-up"),
    # path('sign-in/', views.LoginView.as_view(), name='sign-in'),
    path('accounts/login/', views.LoginView.as_view(), name="sign-in"),
    path('sign-out/', views.LogoutView.as_view(), name='sign-out'),
    path('changepassword/', views.ChangePasswordView.as_view(), name='changepassword'),
    path('passwordchangedone/', views.MyPasswordChangeDoneView.as_view(), name='passwordchangedone'),
    path('passwordreset/', views.MyPasswordResetView.as_view(), name="passwordreset"),
    path('passwordresetdone/', views.MyPasswordResetDoneView.as_view(), name='passwordresetdone'),
    path('passwordresetconfirm/<uidb64>/<token>/', views.MyPasswordResetConfirmView.as_view(), name='passwordresetconfirm'),
    path('passwordresetcomplete/', views.MyPasswordResetCompleteView.as_view(), name='passwordresetcomplete'),
    path('myadmin/', views.AdminDashboardTemplateView.as_view(), name="myadmin"),
    path('myadminprofile/', views.MyadminProfileTemplateView.as_view(), name="myadminprofile"),
    path('profileupdate/<int:pk>', views.MyadminProfileUpdateView.as_view(), name="profileupdate"),
    path('addcategory/', views.CategoryCreateView.as_view(), name="addcategory"),
    path('categorylist/', views.CategoryListView.as_view(), name="categorylist"),
    path('categoryupdate/<int:pk>/', views.CategoryUpdateView.as_view(), name="categoryupdate"),
    path('categorydelete/<int:pk>', views.CategoryDeleteView.as_view(), name="caregorydelete"),
    path('addproduct/', views.ProductCreateView.as_view(), name='addproduct'),
    path('productlist/', views.ProductListView.as_view(), name="productlist"),
    path('productupdate/<int:pk>/', views.ProductUpdateView.as_view(), name="productupdate"),
    path('productdelete/<int:pk>/', views.ProductDeleteView.as_view(), name="productdelete"),
    path('customerlist/', views.CustomerListView.as_view(), name="customerlist"),
    path('orderlist/', views.OrderListView.as_view(), name="orderlist"),
    path('invoicedetail/<int:pk>', views.MyadminInvoiceDetailView.as_view(), name="invoicedetail"),
]