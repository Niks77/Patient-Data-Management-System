
from django.contrib import admin
from django.urls import path, include
from fcs_project import settings 
from django.conf.urls.static import static
from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('signup',views.signup, name="signup"),
    path('signupOrg',views.signupOrg, name="signupOrg"),
    path('signin',views.signin, name="signin"),
    path('signout',views.signout, name="signout"),
    path('changepassword',views.change_password, name="change_password"),
    path('ajax/load-dropdown/', views.load_dropdown, name='ajax_load_dropdown'),
    path('upload', views.upload_files, name='upload'),
    path('your_docs', views.your_docs, name='your_docs'),
    path('shared_docs', views.shared_docs, name='shared_docs'),
    path('change_password', views.change_password, name='change_password'), 
    path('verify',views.verify, name="verify"), 
    path('delete',views.delete, name="delete"),
    path('activate/<username>/<token>', views.activate, name='activate'),
    path('reset/<username>/<token>', views.reset, name='reset'),
    path('search',views.search, name="search"),
    path('product/<int:product_id>/<slug:product_slug>/',
        views.show_product, name='product_detail'),
    path('cart/', views.show_cart, name='show_cart'),
    path('checkout/', views.checkout, name='checkout'),
    path('process-payment/', views.process_payment, name='process_payment'),
    path('payment-done/', views.payment_done, name='payment_done'),
    path('payment-cancelled/', views.payment_canceled, name='payment_cancelled'),
    path('forgot_password', views.forgotpassword, name='forgot'),
    path('sharefile', views.sharefile,name='sharefile')

]
if settings.DEBUG:
        urlpatterns += static(settings.MEDIA_URL,
                              document_root=settings.MEDIA_ROOT)