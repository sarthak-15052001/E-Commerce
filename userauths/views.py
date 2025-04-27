from django.db.models.query import QuerySet
from django.shortcuts import render, redirect
from django.contrib.auth.views import LoginView, LogoutView, PasswordChangeView, PasswordChangeDoneView, PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from .forms import *
from .models import *
from core.models import *
from core.forms import *
from django.views.generic import TemplateView, CreateView, ListView, DetailView, UpdateView, View, DeleteView
from django.urls import reverse_lazy
from django.db.models import Q


# Create your views here.
     
#<-------------------------------------Signup View Starts From Here------------------------------>
class SignupView(CreateView):
    template_name = 'userauths/sign-up.html'
    form_class = UserRegistrationForm   
    success_url = reverse_lazy("userauths:sign-up")

    def form_valid(self, form):
        messages.success(self.request, 'Registration Done Successfully !!')
        return super().form_valid(form)
    
#<------------------------------Login View Starts from Here------------------------------------->
class LoginView(LoginView):
    template_name = 'userauths/sign-in.html'
    Authentication_Form = UserLoginForm


    def get_success_url(self):
        if self.request.user.is_superuser:
            return reverse_lazy('userauths:myadmin')  # Redirect superusers to admin page
        else:
            return reverse_lazy('core:home')

    
#<------------------------------Logout View Starts From Here-------------------------------------->
class LogoutView(LogoutView):
    def dispatch(self, request, *args, **kwargs):
        if request.method == 'GET':
           logout(request)
           messages.success(request, "You have been logged out !!")
           return redirect("userauths:sign-in")
        return super().dispatch(request, *args, **kwargs)
    
#<------------------------------Password Change View Starts From Here----------------------------->
class ChangePasswordView(PasswordChangeView):
    template_name = 'userauths/password-change.html'
    form_class = PasswordChangeForm
    success_url = reverse_lazy('userauths:passwordchangedone')


#<------------------------------Password Change Done View Starts From Here------------------------------>
class MyPasswordChangeDoneView(PasswordChangeDoneView):
    template_name = 'userauths/password-change-done.html'


#<---------------------------Password Reset View Starts From Here----------------------------------->
class MyPasswordResetView(PasswordResetView):
    template_name = 'userauths/password-reset.html'
    form_class = MyPasswordResetForm
    success_url = reverse_lazy('userauths:passwordresetdone')   


#<-------------------------------Password Reset Done View Starts From Here--------------------------->
class  MyPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'userauths/password-reset-done.html'


#<-------------------------------Password reset confirm View Starts From Here------------------------->
class MyPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'userauths/password-reset-confirm.html'
    form_class = MySetPasswordForm
    success_url = reverse_lazy('userauths:passwordresetcomplete')


#<-------------------------------Password Reset Complete View Starts From Here------------------------->
class MyPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'userauths/password-reset-complete.html'

  

#<----------------------------Admin Dashboard Template View Starts From Here------------------------->
class AdminDashboardTemplateView(TemplateView):
    template_name = 'userauths/admin-dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        total_category = Category.objects.count()
        total_products = Product.objects.count()
        total_customers = User.objects.filter(is_active=True, is_staff=False).count()
        total_orders = Order.objects.count()
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None

        context['total_category'] = total_category
        context['total_products'] = total_products
        context['total_customers'] = total_customers
        context['total_orders'] = total_orders
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context

#<----------------------Myadmin Profile View Starts From Here----------------------------------------->
class MyadminProfileTemplateView(TemplateView):
    template_name = 'userauths/admin-profile.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Fetch user profile if it exists
        try:
            user_profile = UserProfile.objects.get(user=self.request.user)
            context['user_profile'] = user_profile
        except UserProfile.DoesNotExist:
            pass
        
        context['user'] = self.request.user
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        # context['profile_form'] = UserProfileForm(instance=user_profile)
        return context
    

    

# <------------------------Myadmin Profile Update View Starts From Here------------------------------>
class MyadminProfileUpdateView(UpdateView):
    model = UserProfile
    form_class = UserProfileForm
    template_name = 'userauths/edit-profile.html'
    success_url = reverse_lazy('userauths:myadminprofile')


    def get_object(self, queryset=None):
        try:
            return self.request.user.userprofile
        except UserProfile.DoesNotExist:
            new_profile = UserProfile(user=self.request.user)
            new_profile.save()
            return new_profile
        

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user_form'] = UserForm(instance=self.request.user)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context
    
    def form_valid(self, form):
        user_form = UserForm(self.request.POST, instance=self.request.user)
        if user_form.is_valid():
            user_form.save()
        return super().form_valid(form)

#<---------------------Myadmin Add Category Create View Starts From Here--------------------------->
class CategoryCreateView(CreateView):
    model = Category
    fields = ['title', 'category_image']
    template_name = 'userauths/add-category.html'
    success_url = reverse_lazy('userauths:categorylist')


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context
    



#<------------------------Myadmin Category List View Starts From Here-------------------------------->
class CategoryListView(ListView):
    model = Category
    template_name = 'userauths/category-list.html'
    context_object_name = "categories"


    def get_queryset(self):
      qs = self.request.GET.get('search', '')

      queryset = Category.objects.filter(
        Q(title__icontains=qs)
      )
      return queryset
    

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context


#<----------------------------Myadmin Category Update View Starts Form Here------------------------>
class CategoryUpdateView(UpdateView):
    model = Category
    fields = ['title', 'category_image']
    template_name = 'userauths/update-category.html'
    success_url = reverse_lazy('userauths:categorylist')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context


#<---------------------------Myadmin Category Delete View Starts From Here-------------------------->
class CategoryDeleteView(DeleteView):
    model = Category
    template_name = 'userauths/delete-category.html'
    success_url = reverse_lazy('userauths:categorylist')


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context


#<---------------------------Myadmin Product Create View Starts From Here----------------------------->
class ProductCreateView(CreateView):
    model = Product
    form_class = ProductForm
    template_name = 'userauths/add-product.html'
    success_url = reverse_lazy('userauths:productlist')



    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context




#<----------------------------Myadmin Product List View Starts From Here------------------------------>
class ProductListView(ListView):
    model = Product
    template_name = 'userauths/product-list.html'
    context_object_name = 'products'


    def get_queryset(self):
      qs = self.request.GET.get('search', '')

      queryset = Product.objects.filter(
        Q(title__icontains=qs) |
        Q(brand__icontains=qs) |
        Q(discounted_price__icontains=qs)
      )
      return queryset
    

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context

#<----------------------------Myadmin Product Update View Starts From Here------------------------------>
class ProductUpdateView(UpdateView):
    model = Product
    form_class = ProductForm
    template_name = 'userauths/update-product.html'
    success_url = reverse_lazy('userauths:productlist')


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context


#<----------------------------Myadmin Product Delete View Starts From Here-------------------------------->
class ProductDeleteView(DeleteView):
    model = Product
    template_name = 'userauths/delete-product.html'
    success_url = reverse_lazy("userauths:productlist")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context


#<----------------------------Myadmin Customer ListView Starts From Here----------------------------------->
class CustomerListView(ListView):
    model = UserProfile
    template_name = 'userauths/customer-list.html'
    context_object_name = "customers"


    def get_queryset(self):
        qs = super().get_queryset().filter(user__is_superuser=False)
        search_query = self.request.GET.get('search', None)
        if search_query:
            qs = UserProfile.objects.filter(
                Q(user__first_name__icontains=search_query) | 
                Q(user__phone_number__icontains=search_query) |
                Q(city__icontains=search_query) |
                Q(state__icontains=search_query)|
                Q(bio__icontains=search_query)
            )
        return qs
    

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context
    

#<---------------------------Myadmin Order List View Starts From Here------------------------------------>
class OrderListView(ListView):
    model = Payment
    template_name = 'userauths/order-list.html'
    context_object_name = 'orders'


    def get_queryset(self):
      qs = self.request.GET.get('search', '')

      queryset = Payment.objects.filter(
        Q(order_id__icontains=qs) |
        Q(orderproduct__Order__first_name__icontains=qs) |
        Q(orderproduct__Order__phone_number__icontains=qs)
      )
      return queryset
    

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context



#<--------------------------Myadmin Invoice Detail View Starts From Here----------------------------------->
class MyadminInvoiceDetailView(DetailView):
    model = Payment
    template_name = 'userauths/invoice-detail.html'
    context_object_name = 'payments'  


    def get_object(self, queryset=None):
        return Payment.objects.get(pk=self.kwargs["pk"])

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        payment = self.object
        order_products = OrderProduct.objects.filter(Order=payment.orderproduct.Order)

        user = self.request.user
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None

        context['payments'] = [payment]
        context['order_products'] = order_products
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context