from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from . import views
from .views import register_user, verify_email
from .views import webex_login, webex_callback
from api.views import SendPasswordResetEmailView, APIChangePasswordView, UserPasswordResetView
from rest_framework_simplejwt.views import TokenRefreshView
#from .views import ImageUploadView


#from .views import WebexOpenIDCallbackView
#from .views import ProfileView
from .views import UserProfilePictureView



   

urlpatterns = [ 
    path('logout/', views.LogoutView.as_view(), name ='logout') , 
     path('login/', views.user_login, name='login'),
     path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
  # path('register',RegisterUser.as_view()),
     path('home/', views.HomeView.as_view(), name ='home'),
     path('register/', register_user, name='register_user'),
    path('verify/', verify_email, name='verify_email'),
      path('webex/login/', webex_login, name='webex_login'),
    path('webex/callback/', webex_callback, name='webex_callback'),
    path('changepassword/', APIChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
   #  path('upload/', ImageUploadView.as_view(), name='image-upload'),
   # path('profile/', ProfileView.as_view(), name='profile'),
   # path('profile/', ProfileView.as_view(), name='profile'),
    path('upload/', UserProfilePictureView.as_view(), name='user_profile_picture'),
    path('info/', views.create_work_info, name='work_Info_View'),
    #path('getinfo/', views.workget, name='work_Info_View'),
    path('update/<int:auto_increment_id>/', views.ChecklistUpdateView.as_view(), name='checklist Updation'),
    path('main_detail/<int:auto_increment_id>/', views.MainDetailView, name='main detail'),
    #path('date_exists/<str:work_start_end_date>/', views.DateView.as_view(), name='main detail'),
    path('alldata/', views.AllView, name='All detail'),
    # path('evedata_exists/<str:work_start_end_date>/', views.EveDateView.as_view(), name='main detail'),
    path('zohoproject/', views.ZohoProjectsView.as_view(), name='zoho projects'),
    path('complete_form/<int:auto_increment_id>/', views.get_checklist_with_completeness, name='checklist-with-completeness'),
     path('exitformdate/', views.get_checklists_for_current_date, name='all-checklists-completeness'),
     path('exitform/', views.get_checklist_data, name='all-checklists-completeness'),
     path('zohoprojects/', views.ZohoProjects.as_view(), name='zoho projects'),

    
]


