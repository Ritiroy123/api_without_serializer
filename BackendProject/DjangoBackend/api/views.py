from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from django.db import models
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from rest_framework.permissions import AllowAny
from api.serializers import RegisterSerializer,EmailVerificationSerializer
from django.contrib.auth import get_user_model
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics
from django.shortcuts import redirect
from django.urls import reverse
from django.http import JsonResponse,HttpResponse
import requests
from requests import request
from rest_framework.generics import UpdateAPIView
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from api.serializers import SendPasswordResetEmailSerializer, UserPasswordChangeSerializer, UserPasswordResetSerializer,workInfoSerializer,getidSerializer,detailsSerializer,AllSerializer
from django.contrib.auth import authenticate
from rest_framework.parsers import MultiPartParser, FormParser
#from .models import Profile
#from .serializers import ProfileSerializer
from .serializers import CustomUserSerializer
from .models import checklist,User
import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.core import serializers
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags


from django.forms.models import model_to_dict
from django.core.cache import cache
  

User = get_user_model()


class UserProfilePictureView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request, *args, **kwargs):
        # Get the profile picture of the authenticated user
        try:
            user = User.objects.get(pk=request.user.pk)
            serializer = CustomUserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def post(self, request, *args, **kwargs):
        # Update the profile picture of the authenticated user
        try:
            user = User.objects.get(pk=request.user.pk)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # Update the profile picture with the request data
        serializer = CustomUserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
class HomeView(APIView):
     
   permission_classes = (IsAuthenticated, )
   def get(self, request):
       content = {'message': 'Welcome to the JWT Authentication page using React Js and Django!' }
                   
       return Response(content) 
   

class LogoutView(APIView):
     permission_classes = (IsAuthenticated,)
     def post(self, request):
          
          try:
               refresh_token = request.data["refresh_token"]
               token = RefreshToken(refresh_token)
               token.blacklist()
               return Response(status=status.HTTP_205_RESET_CONTENT)
          except Exception as e:
               return Response(status=status.HTTP_400_BAD_REQUEST)


# Class based view to Get User Details using Token Authentication
# class UserLoginView(APIView):
#   def post(self, request, format=None):
#     serializer = UserLoginSerializer(data=request.data)
#     serializer.is_valid(raise_exception=True)
#     email = serializer.data.get('email')
#     password = serializer.data.get('password')
#     user = authenticate(email=email, password=password)
#     if user is not None:
#       token = get_tokens_for_user(user)
#       return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
#     else:
#       return Response({'login failed.'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def user_login(request):
    if request.method == 'POST':
        try:
            data = request.data
            email = data['email']
            password = data['password']
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials.'}, status=401)
        except Exception as e:
            return Response({'error': str(e)}, status=400)
    else:
        return Response({'error': 'Only POST requests are allowed.'}, status=405)    
    

# @api_view(['POST'])
# def register_user(request):
#     if request.method == 'POST':
#         serializer = RegisterSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response({'message': 'Registered successfully.'}, status=status.HTTP_201_CREATED)
#         return Response({'message': 'Email already exists.'}, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        try: 
            data = request.data
            email = data['email']
            name = data['name']
            phone_number = data['phone_number']
            password = data['password']
            password2 = data['password2']

            # Check if password and password2 match
            if password != password2:
                return Response({'error': 'Passwords do not match.'}, status=400)

            # Check if a user with the same email already exists
            if User.objects.filter(email=email).exists():
                return Response({'error': 'Email is already registered.'}, status=400)

            # Create the user
            user = User.objects.create_user(email=email, password=password, name=name, phone_number=phone_number)
            return Response({'message': 'User registered successfully.'})
        except Exception as e:
            return Response({'error': str(e)}, status=400)
    else:
        return Response({'error': 'Only POST requests are allowed.'}, status=405)

@api_view(['POST'])
def verify_email(request):
    if request.method == 'POST':
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    
    


class APIChangePasswordView(UpdateAPIView):
    serializer_class = UserPasswordChangeSerializer
    model = User # your user model
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        return self.request.user
class SendPasswordResetEmailView(APIView):
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
  






def webex_login(request):
    authorize_url = f"{settings.WEBEX_AUTHORIZATION_URL}?client_id={settings.WEBEX_CLIENT_ID}&response_type=code&redirect_uri={settings.WEBEX_REDIRECT_URI}&scope=spark%3Aall%20spark%3Akms"
    return JsonResponse({'url': authorize_url})

def webex_callback(request):
    code = request.GET.get('code')
    access_token_response = requests.post(
        settings.WEBEX_ACCESS_TOKEN_URL,
        data={
            'grant_type': 'authorization_code',
            'client_id': settings.WEBEX_CLIENT_ID,
            'client_secret': settings.WEBEX_CLIENT_SECRET,
            'code': code,
            'redirect_uri': settings.WEBEX_REDIRECT_URI,
        }
    )

    if access_token_response.status_code == 200:
        access_token_data = access_token_response.json()
        access_token = access_token_data['access_token']
        # Handle the access_token, store it in session, or authenticate the user
        # For example:
        # request.session['access_token'] = access_token
        # or
        # Authenticate the user based on the access_token

        return JsonResponse({'message': 'Authentication successful.'})

    return JsonResponse({'error': 'Authentication failed.'}, status=400)




# class workInfoView(APIView):
  
  
#   def get(self,request,*args, **kwargs):
      
#        try:
                
#                # user = User.objects.get(id=user_id)
#                 checklists = checklist.objects.all()
#                 serializer = workInfoSerializer(checklists, many=True)
#                 return Response(serializer.data, status=status.HTTP_200_OK)
#        except User.DoesNotExist:
#                 return Response(status=status.HTTP_404_NOT_FOUND)

        
  
#   def post(self, request, *args, **kwargs):
#         serializer = workInfoSerializer(data=request.data)
#         try:
#             if serializer.is_valid(raise_exception=True):
#                 if request.user.is_authenticated:
#                     user = request.user
#                 else:
#                     return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

#                 # Remove the check for 'user' in serializer.validated_data
#                 # This allows users to post multiple times without overwriting the 'user' field
#                 serializer.validated_data['user'] = user

#                 work_info_instance = serializer.save()

#                 user_email = work_info_instance.user.email

#                 subject = 'New Worker Information'
#                 message = "new work"
#                 from_email = 'ritiroy85257@gmail.com'
#                 recipient_list = [user_email]

#                 # Generate HTML content from the template
#                 email_template = 'template.html'
#                 email_context = {
#                     'post_details': serializer.data
#                 }
#                 html_message = render_to_string(email_template, email_context)
#                 plain_message = strip_tags(html_message)  # Strip HTML for plain text version

#                 send_mail(subject, plain_message, from_email, recipient_list, html_message=html_message, fail_silently=False)

#                 return Response(serializer.data, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def create_work_info(request):
    try:
        user = request.user
        if not user.is_authenticated:
            return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
        data = request.data
        work_info_instance = checklist(
            user=user,
            project_number =data.get('project_number'),
            subcontractor_name =data.get('subcontractor_name'),
            supervisor_name =data.get('supervisor_name'),
            project_location =data.get('project_location'),
            worker_name =data.get('worker_name'),
            work_start_end_date =data.get('work_start_end_date'),
            log_book_material =data.get('log_book_material'),
            before_entry_bag_check =data.get('before_entry_bag_check'),
            before_entry_clothing_and_appearance =data.get('before_entry_clothing_and_appearance'),
            before_entry_tools_and_equipments_check =data.get('before_entry_tools_and_equipments_check'),
            physical_health =data.get('physical_health'),
            mental_health =data.get('mental_health'),
            before_entry_safety_helmet_check =data.get('before_entry_safety_helmet_check'),
            before_entry_safety_shoes_check =data.get('before_entry_safety_shoes_check'),
            before_entry_safety_jackets_check =data.get('before_entry_safety_jackets_check'),
            before_entry_tobacco_and_alcohol =data.get('before_entry_tobacco_and_alcohol'),
            before_entry_ladders_health_check =data.get('before_entry_ladders_health_check'),
            material_logbook_check =data.get('material_logbook_check'),
            before_entry_remark =data.get('before_entry_remark'),
        )
        work_info_instance.save()
        user_email = work_info_instance.user.email
        subject = 'New Worker Information'
        message = "New work"
        from_email = 'ritiroy85257@gmail.com'
        recipient_list = [user_email]
        # Generate HTML content from the template (if needed)
        email_template = 'template.html'
        email_context = {
            'post_details': data,
        }
        html_message = render_to_string(email_template, email_context)
        plain_message = strip_tags(html_message)  # Strip HTML for plain text version
        # Send email
        send_mail(subject, plain_message, from_email, recipient_list, html_message=html_message, fail_silently=False)

        return Response(data, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)      
#b=User(email="riti2345679@gmail.com",name="riti",phone_number="93546737")   
#b.save() 
#a = checklist(project_name="qq",project_name1="a",project_location="a",project_location1="a",supervisor_name="q", subcontractor_name="a",work_start_date="2023-08-07",work_start_date1="2023-08-07",work_completion_date="2023-08-07",work_completion_date1="2023-08-07",wcp_esic_verification="Yes",aadhar_card_verification="Yes",before_entry_body_scanning="Yes",before_entry_bag_check="Yes",physical_appearance="Yes",before_entry_bag_tales_and_tool_check="Yes",before_entry_bag_mental_health_check="Yes",physical_health_check="Yes",before_entry_bag_behavioral_check="Yes",before_entry_bag_safety_helmet_check="Yes",before_entry_bag_safety_shoes_check="Yes",before_entry_bag_safety_jackets_check="Yes",ladders_health_check="Yes",work_place_check="Yes",work_place_cleanliness_check="Yes",balance_material_on_specified_area_check="Yes",ladders_placement_check="Yes",before_exit_body_scanning="Yes",before_exit_bag_check="Yes",before_exit_bag_tales_and_tool_check="Yes",before_exit_bag_mental_health_check="Yes",before_exit_bag_behavioral_check="Yes",before_exit_bag_safety_helmet_check="Yes",before_exit_bag_safety_shoes_check="Yes",before_exit_bag_safety_jackets_check="Yes",remark="ddd",user=b)
#a =checklist.objects.filter(duplicate_id=0).count()
#a= checklist.objects.get(pk = 1)
#a.save()
#print(b)
#a=checklist.objects.all()
#print(a)
# @api_view(['GET'])
# def workget(request,*args,**kwargs):
   
#         checklists = checklist.objects.all()
        
#         data = list(checklists)
        
#         return Response(data)
        
    

   

@api_view(['GET'])
def get_checklists_for_current_date(request):
    current_date = timezone.now() - timedelta(days=0)
    checklists = checklist.objects.filter(work_start_end_date=current_date)
    
    completeness_data = []

    for Checklist in checklists:
        fields = Checklist._meta.get_fields()
        is_all_filled = all(
            getattr(Checklist, field.name) or isinstance(field, models.BooleanField)
            for field in fields if isinstance(field, (models.TextField, models.BooleanField))
        )
        serializer = getidSerializer(Checklist)
        completeness_data.append({
            'data': serializer.data,
            'completeness_status': is_all_filled
        })

    return Response(completeness_data)

    

class ChecklistUpdateView(APIView):
        
    def put(self, request, *args, **kwargs):
            auto_increment_id = self.kwargs['auto_increment_id']
           
            checklists = checklist.objects.get(auto_increment_id=auto_increment_id)
            serializer = detailsSerializer(checklists, data=request.data)
            other_serializer = workInfoSerializer(checklists,data=request.data)  # Replace with the actual serializer you're using
            try:
                if serializer.is_valid() and other_serializer.is_valid():
                    if request.user.is_authenticated:
                        user = request.user
                    else:
                        return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)

                    if 'user' not in serializer.validated_data:
                       serializer.validated_data['user'] = user

                    work_info_instance = serializer.save()

                    user_email = work_info_instance.user.email

                    subject = 'New Work Information'
                    message = "new work"
                    from_email = 'ritiroy85257@gmail.com'
                    recipient_list = [user_email]

                    # Generate HTML content from the template
                    email_template = 'alldetail.html'
                    email_context = {
                        'evening_details': serializer.data,
                        'morning_details':other_serializer.data
                    }
                    html_message = render_to_string(email_template, email_context)
                    plain_message = strip_tags(html_message)  # Strip HTML for plain text version

                    send_mail(subject, plain_message, from_email, recipient_list, html_message=html_message, fail_silently=False)

                    return Response(serializer.data, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            

@api_view(['GET'])
def MainDetailView(request,auto_increment_id):
        try:
            item = checklist.objects.get(auto_increment_id=auto_increment_id)

            # Retrieve all fields from the checklist model
            data = {field.name: getattr(item, field.name) for field in checklist._meta.fields}

            # Remove the 'user' field from the data dictionary
            data.pop('user', None)

            return Response(data)
        except checklist.DoesNotExist:
            return Response({"message": "Item not found"}, status=status.HTTP_404_NOT_FOUND)


# class DateView(APIView):
#   def get(self, request, work_start_end_date, format=None):
#         try:
#             item = checklist.objects.get(work_start_end_date=work_start_end_date)
#             serializer = workInfoSerializer(item)
#             return Response(serializer.data)
#         except checklist.DoesNotExist:
#             return Response({"message": "date not found"}, status=status.HTTP_404_NOT_FOUND)
        


# class EveDateView(APIView):
#   def get(self, request, work_start_end_date, format=None):
#         try:
#             item = checklist.objects.get(work_start_end_date=work_start_end_date)
#             serializer = detailsSerializer(item)
#             return Response(serializer.data)
#         except checklist.DoesNotExist:
#             return Response({"message": "date not found"}, status=status.HTTP_404_NOT_FOUND)        
@api_view(['GET'])
def AllView(request):
        if request.user.is_authenticated:
            authenticated_user = request.user

            # Retrieve checklists associated with the authenticated user
            checklists = checklist.objects.filter(user=authenticated_user)

            # Check if any checklists were found
            if checklists.exists():
                # Create a dictionary to represent the data
                checklists_data = checklists.values()

                return Response(checklists_data, status=200)
            else:
                return Response({"message": "No checklists found for this user."}, status=204)
        else:
            return Response({"message": "Authentication required."}, status=401)
      
# storing the JSON response 
# from url in data

  
# print the json response
#print(data_json)


#print(response.json())

class ZohoProjectsView(APIView):
    def generate_access_token(self, refresh_token):
        url = "https://accounts.zoho.com/oauth/v2/token"
        payload={'grant_type': 'refresh_token',
            'client_id': '1000.4D0LT5YLPOKPGZ5IFJNVNYTP8IEVFN',
            'client_secret': '5addc71050ce2b59934d7ba04d977c3bca5e9e6b6e',
            'redirect_uri': 'https://www.google.com/',
            'refresh_token': '1000.37614442538599aa9ee078f097c04422.b8e995b721dd851709c3cd2c53bee7ec'}
        response = requests.post(url, data=payload)
        data = response.json()
        if 'access_token' in data:
            return data['access_token']
        return None

    def get(self, request, *args, **kwargs):
        zoho_api_url = "https://projectsapi.zoho.com/restapi/portal/687895858/projects/"
        refresh_token = "1000.37614442538599aa9ee078f097c04422.b8e995b721dd851709c3cd2c53bee7ec"

        access_token = cache.get('zoho_access_token')
        project_info = cache.get('project_info')

        if access_token is None:
            access_token = self.generate_access_token(refresh_token)
            cache.set('zoho_access_token', access_token, timeout=7200)  # cache for 1 hour

        if project_info is None:
            headers = {
                'Authorization': f'Bearer {access_token}',
                "Content-Type": "application/json"
            }
            start = 0
            size = 200
            total_projects = []

            while True:
                params = {
                    "index": start,
                    "range": size
                }

                response = requests.get(zoho_api_url, headers=headers, params=params)
                data = response.json()
                total_projects.extend(data["projects"])

                if len(data["projects"]) < size:
                    break
                else:
                    start += size

            active_projects = [
                {"name": project["name"], "owner_name": project["owner_name"]}
                for project in total_projects if project["status"] == "active"
            ]
            
            project_info = {"projects": active_projects}
            cache.set('project_info', project_info, timeout=7200)  # cache for 1 hour

        return Response(project_info)




@api_view(['GET'])
def get_checklist_with_completeness(request, auto_increment_id):

    try:
        checklist_item = checklist.objects.get(auto_increment_id=auto_increment_id)
    except checklist.DoesNotExist:
        return Response({'error': 'Checklist not found'}, status=404)

    fields = checklist_item._meta.get_fields()

    is_all_filled = all(
        getattr(checklist_item, field.name, '') or isinstance(field, models.BooleanField)
        for field in fields if isinstance(field, (models.TextField, models.BooleanField))
    )
    
    completeness_status = 'true' if is_all_filled else 'false'

    checklist_dict =  checklist_item.values()
    response_data = {
        'data': checklist_dict,
        'all_fields_filled': completeness_status
    }
    
    return Response(response_data)


@api_view(['GET'])
def get_checklist_data(request):
    checklists = checklist.objects.all()
    serialized_checklists = []

    for Checklist in checklists:
        checklist_data = getidSerializer(Checklist).data
        all_fields = [
            field.attname for field in Checklist._meta.fields
            if field.attname not in ['auto_increment_id', 'created_at', 'updated_at', 'user', 'is_true']
        ]
        checklist_data['is_true'] = all(
            getattr(Checklist, field, None) for field in all_fields
        )
        serialized_checklists.append(checklist_data)

    return Response(serialized_checklists)



