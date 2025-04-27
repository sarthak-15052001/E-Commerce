from django.conf import settings
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import TemplateView, CreateView, ListView, DetailView, UpdateView, View
import stripe.error
from .models import *
from .forms import *
from userauths.forms import *
from userauths.models import *
from django.contrib import messages
from django.db.models import Prefetch
from django.db import connection
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.db.models import Sum, F
from core.utils import render_to_pdf
from django.views.decorators.csrf import csrf_exempt
import stripe
from django.conf import settings


stripe.api_key = settings.STRIPE_SECRET_KEY
endpoint_secret = settings.STRIPE_WEBHOOK_SECRET_KEY

# Create your views here.


#<-----------------------------------Home Template View Starts From Here--------------------------->
class HomeTemplateView(TemplateView):
  template_name = 'core/home.html'   


#   def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         categories_with_products = []

#         # Fetching jeans category and its products
#         jeans_category = Category.objects.get(title='Jeans')
#         jeans_category_data = {
#             'category': jeans_category,
#             'products': Product.objects.filter(category=jeans_category)
#         }
#         categories_with_products.append(jeans_category_data)

#         # Fetching T-shirt category and its products
#         tshirt_category = Category.objects.get(title='Tshirts')
#         tshirt_category_data = {
#             'category': tshirt_category,
#             'products': Product.objects.filter(category=tshirt_category)
#         }
#         categories_with_products.append(tshirt_category_data)

#         context['categories_with_products'] = categories_with_products
#         return context


  def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Fetching all categories along with their products using prefetch_related
        categories_with_products = Category.objects.prefetch_related(
            Prefetch('product_set', queryset=Product.objects.order_by('?'))
        )

        for category in categories_with_products:
            # print(f"Category: {category.title}")
            for product in category.product_set.all():
                print(f" - Product: {product.title}")

        
        # Print the generated SQL query
        # print(connection.queries)
        context['categories_with_products'] = categories_with_products
        return context 
  

#<-----------------------------------Store Template View Starts From Here---------------------->
class StoretemplateView(TemplateView):
  template_name = 'core/store.html'

  def get_context_data(self, **kwargs):
    context = super().get_context_data(**kwargs)
    category_title = self.kwargs.get('category_title')
    brand_name = self.request.GET.get('brand')
    min_price = self.request.GET.get('min_price')
    max_price = self.request.GET.get('max_price')

    # Base Queryset for products
    products = Product.objects.all()

    # Apply Filters based on category and brand
    if category_title:
      products = products.filter(category__title=category_title)
      if brand_name and brand_name != 'all':
        products = products.filter(brand=brand_name)
      if min_price:
                products = products.filter(selling_price__gte=min_price)
      if max_price:
                products = products.filter(selling_price__lte=max_price)

    # Filter brands based on selected category
    if category_title:
      context["brands"] = Product.objects.filter(category__title=category_title).values('brand').distinct()
    else:
      context["brands"] = Product.objects.values('brand').distinct()
    
    context["products"] = products
    # context["categories"] = Category.objects.all()
    return context
  


#<------------------------------------Product Detail View Starts From Here--------------------------->
class ProductDetailView(DetailView):
  model = Product
  template_name = 'core/productdetail.html'
  context_object_name = "products"


  def get_context_data(self, **kwargs):
      context = super().get_context_data(**kwargs)
      product = self.object
      item_already_exits_in_cart = False
      if self.request.user.is_authenticated:
          item_already_exits_in_cart = Cart.objects.filter(Q(product=product.id) & Q(user=self.request.user)).exists()
      context['item_already_exits_in_cart'] = item_already_exits_in_cart
      # print(">>>>>>>>>>>>>>>>>>>>", context['item_already_exits_in_cart'])
      return context


#<------------------------------Add To Cart View Starts From Here------------------------>
class AddToCartTemplateView(TemplateView):
   template_name = 'core/addtocart.html'

   def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        product_id = self.request.GET.get('prod_id')
        if product_id is not None:
          product = Product.objects.get(id=product_id)
          cart = Cart.objects.get_or_create(user=user, product=product)
        carts = Cart.objects.filter(user=user)
        amount = 0.0
        shipping_amount = 70.0
        total_amount = 0.0
        temp_amount = 0.0
        cart_product = [p for p in Cart.objects.all() if p.user == user]
        if cart_product:
           for p in  cart_product:
              temp_amount = (p.quantity * p.product.discounted_price)
              amount += temp_amount
              total_amount = amount + shipping_amount

        
        context['carts'] = carts 
        context['amount'] = amount
        context['temp_amount'] = temp_amount
        context['shipping_amount'] = shipping_amount
        context['total_amount'] = total_amount

        # print("------>>>>>>>>>", context['carts'])
        return context


#<------------------------Plus Cart Ajax View Starts From Here--------------------------->
def plus_cart(request):
   if request.method == 'GET':
      prod_id = request.GET.get('prod_id')
      product = Product.objects.get(pk=prod_id)
      c, create = Cart.objects.get_or_create(product=product, user=request.user)
      c.quantity += 1
      c.save()
      amount = 0.0
      shipping_amount = 70.0
      total_amount = 0.0
      temp_amount = 0.0
      product_price = c.quantity * c.product.discounted_price
      cart_id = c.id
      
      cart_product = [p for p in Cart.objects.all() if p.user == request.user]
      for p in  cart_product:
            temp_amount = (p.quantity * p.product.discounted_price)
            amount+= temp_amount
            total_amount = amount + shipping_amount
      data = {
         'quantity': c.quantity,
         'amount': amount,
         'total_amount': total_amount,
         'product_price':product_price,
         "cart_id":cart_id
        #  'temp_amount': temp_amount 
      }
      return JsonResponse(data)
   

#<--------------------------------Minus  Cart Ajax View Starts From Here----------------------->
def minus_cart(request):
   if request.method == 'GET':
      prod_id = request.GET.get('prod_id')
      product = Product.objects.get(pk=prod_id)
      c, create = Cart.objects.get_or_create(product=product, user=request.user)

      if c.quantity > 0:
        c.quantity -= 1
        c.save()

      amount = 0.0
      shipping_amount = 70.0
      total_amount = 0.0
      temp_amount = 0.0
      
      product_price = c.quantity * c.product.discounted_price
      cart_id = c.id
      cart_product = [p for p in Cart.objects.all() if p.user == request.user]
      for p in  cart_product:
            temp_amount = (p.quantity * p.product.discounted_price)
            amount+= temp_amount
            # total_amount = amount + shipping_amount

      if amount == 0:
          shipping_amount = 0

      total_amount = amount + shipping_amount

      data = {
         'quantity': c.quantity,
         'amount': amount,
         'total_amount': total_amount,
        #  'cart_product':  cart_product,
         'product_price':product_price,
         "cart_id":cart_id
        #  'temp_amount': temp_amount 
      }
      return JsonResponse(data)
   

#<----------------------------Remove Cart Ajax View Starts From Here---------------------------->
def remove_cart(request):
   if request.method == 'GET':
      prod_id = request.GET.get('prod_id')
      product = Product.objects.get(pk=prod_id)
      c, create = Cart.objects.get_or_create(product=product, user=request.user)
      c.delete()
      amount = 0.0
      shipping_amount = 70.0
      total_amount = 0.0
      temp_amount = 0.0
      cart_product = [p for p in Cart.objects.all() if p.user == request.user]
      for p in  cart_product:
            temp_amount = (p.quantity * p.product.discounted_price)
            amount+= temp_amount
            total_amount = amount + shipping_amount
      data = {
         'amount': amount,
         'total_amount': total_amount,
        #  'temp_amount': temp_amount 
      }
      return JsonResponse(data)


#<---------------------------Checkout View Starts From Here----------------------->
class CheckoutCreateView(CreateView):
   model = Order
   form_class = CustomerProfileForm
   template_name = 'core/checkout.html'  
   success_url = reverse_lazy('core:checkout')


   def form_valid(self, form):
      form.instance.user = self.request.user
      data = form.save()
      cart_items = Cart.objects.filter(user=self.request.user)

      shipping_charge = 70.0
      order_product_id = None

      # Calculate total amount for all products combined
      total_amount = cart_items.aggregate(total_amount=Sum(F('product__discounted_price') * F('quantity')))['total_amount'] or 0

      if cart_items:
          for item in cart_items:
              order_product = OrderProduct.objects.create(
                  Order=data,
                  product=item.product,
                  quantity=item.quantity,
                  amount=total_amount,
                  total_amount=total_amount + shipping_charge
              )
              order_product_id = order_product.id   

      data.total_amount = total_amount + shipping_charge
      data.save()

      cart_items.delete()

      # return super(CheckoutCreateView, self).form_valid(form)
      return redirect(reverse("core:payment", kwargs={'pk': order_product_id}))



   def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        if user.is_authenticated:
                
            context['cart_items'] = Cart.objects.filter(user=user)
            context["user"] = self.request.user
            # print('----------->>>>>>>>>>>>', context['cart_items'])
        return context
   
#<-------------------------Payment(COD) Page Starts From Here---------------------------------------->
class PaymentCreateView(CreateView):
    model = Payment
    form_class = PaymentForm
    template_name = 'core/payment.html'

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        order_product_id = self.kwargs['pk']
        order_product = OrderProduct.objects.get(id=order_product_id)
        kwargs['total_amount'] = order_product.total_amount
        return kwargs

    def form_valid(self, form):
        payment = form.save(commit=False)
        order_product_id = self.kwargs['pk']
        order_product = OrderProduct.objects.get(id=order_product_id)
        payment = form.save(commit=False)
        payment.orderproduct = order_product
        payment.user = self.request.user
        payment.payment_status = "Paid"
        # print("----------------", payment)
        payment.save()
        return redirect('core:paymentsuccess')


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        order_product_id = self.kwargs.get('pk')
        order_product = get_object_or_404(OrderProduct, pk=order_product_id)
        context['order_product'] = order_product
        context['order'] = order_product.Order
        # context['key'] = settings.STRIPE_PUBLISHABLE_KEY
        return context



#<--------------------------------Checkout Session View Starts From Here--------------------------->
class CreateCheckoutSessionView(View):
    def post(self, request,*args, **kwargs):

        order_product_id = self.request.POST.get('orderproduct-id')
        if not order_product_id:
            print("Missing orderproduct-id")

        try:
            order_product = OrderProduct.objects.get(id=order_product_id)
            total_amount = int(order_product.total_amount * 100)
            # print('------------>>>>>>>>>>> ', total_amount)
        except OrderProduct.DoesNotExist:
            print("Invalid orderproduct-id:", order_product_id)

        host = self.request.get_host()



        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price_data': {
                        'currency': 'inr',
                        'unit_amount': total_amount,
                        'product_data': {
                            'name': order_product.id,
                            # 'images':
                        },
                    },
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url="http://{}{}".format(host, reverse('core:paymentsuccess')),
            cancel_url="http://{}{}".format(host, reverse('core:paymentcancel')),
            )
        return redirect(checkout_session.url, code=303)




#<-------------------------------Payment Successful Page starts From Here--------------------------->
class PaymentSuccessView(TemplateView):
    template_name = 'core/payment-success.html'
    

#<---------------------------------Payment Cancel Template View Starts From Here----------------->
class PaymentCancelView(TemplateView):
    template_name = 'core/payment-cancel.html'


#<---------------------------------Payment Webhook Page starts from here-------------------------->
@csrf_exempt
def my_webhook_view(request):
    payload = request.body
    sig_header = request.META['HTTP_STRIPE_SIGNATURE']
    event = None

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        # print("------------", event)
    except ValueError as e:
        # Invalid payload
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return HttpResponse(status=400)

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        payment_intent = stripe.PaymentIntent.retrieve(session['payment_intent'])

        if payment_intent['status'] == 'succeeded':
            # Fetch line item details
            line_items = stripe.checkout.Session.list_line_items(session['id'], limit=1).data
            line_item = line_items[0]
            order_product_id = line_item['description']

            # Retrieve the OrderProduct instance
            try:
                order_product = OrderProduct.objects.get(id=order_product_id)
            except OrderProduct.DoesNotExist:
                return HttpResponse(status=404)

            # Create Payment object
            payment = Payment(
                payment_type='Card',  # Assuming payment type
                user=order_product.Order.user,  # Assuming OrderProduct has a 'user' attribute
                orderproduct=order_product,
                total_amount=order_product.total_amount,
                payment_status='Paid'  # Assuming payment status
            )
            payment.save()

    # Respond with a 200 status to acknowledge receipt of the event
    return HttpResponse(status=200)

#<---------------------------------Invoice Page starts From Here----------------------------------->
class InvoiceDetailView(DetailView):
    model = Payment
    template_name = 'core/invoice.html'
    context_object_name = 'payments'


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        payment = self.get_object()
        order_products = OrderProduct.objects.filter(Order=payment.orderproduct.Order)
        context['order_products'] = order_products
        return context


 
    
#<----------------------Customer Dashboard Template View Starts From Here------------------------->
class CustomerDashboardTemplateView(TemplateView):
    template_name = 'core/customer-dashboard.html'


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        # Fetch user profile
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None


        # Fetch email and phone number from User model
        email = user.email
        phone_number = user.phone_number

        # Fetch total orders and latest order
        total_orders = Order.objects.filter(user=user).count()
        latest_order = None

        try:
            latest_order = Order.objects.filter(user=user).latest('id')
        except Order.DoesNotExist:
            pass  # Handle the case where no orders exist

        context['total_orders'] = total_orders
        context['email'] = email
        context['phone_number'] = phone_number
        context['profile_picture'] = user_profile.profile_picture if user_profile else None
        return context
    
#<---------------------Customers Orders List View Starts From Here---------------------------->
class CustomerOrdersListView(ListView):
    model = Payment
    template_name = "core/customer-orders-list.html"
    context_object_name = 'payments'


    def get_queryset(self):
        user = self.request.user
        queryset = super().get_queryset().filter(orderproduct__Order__user=user)
        return queryset

#<------------------------Customer Profile Template View Starts From Here------------------------>
class CustomerProfileTemplateView(TemplateView):
    template_name = 'core/profile.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Fetch user profile if it exists
        try:
            user_profile = UserProfile.objects.get(user=self.request.user)
            context['user_profile'] = user_profile
        except UserProfile.DoesNotExist:
            pass
        
        context['user'] = self.request.user
        return context
    
        

  
#<------------------------Customer Edit Profile View Starts From Here---------------------------->
class CustomerProfileUpdateView(UpdateView):
    model = UserProfile
    form_class = UserProfileForm
    template_name = 'core/customer-edit-profile.html'
    success_url = reverse_lazy('core:customerprofile')
    # pk_url_kwarg = 'pk'

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
        # print("--------->>>>>>", context['user_form'])
        return context
    
    def form_valid(self, form):
        user_form = UserForm(self.request.POST, instance=self.request.user)
        if user_form.is_valid():
            user_form.save()
        return super().form_valid(form)
    

#<------------------------Invoice PDF Generate View Starts From Here--------------------------->
class GeneratePdf(DetailView):
    model = Payment
    template_name = 'pdf/invoice.html'
    context_object_name = "payments"

    def get_object(self, queryset=None):
        return Payment.objects.get(pk=self.kwargs["pk"])

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        payment = self.object
        order_products = OrderProduct.objects.filter(Order=payment.orderproduct.Order)
        context['payments'] = [payment]
        context['order_products'] = order_products
        return context

    def render_to_response(self, context, **response_kwargs):
        pdf = render_to_pdf('pdf/invoice.html', context)
        return HttpResponse(pdf, content_type='application/pdf')