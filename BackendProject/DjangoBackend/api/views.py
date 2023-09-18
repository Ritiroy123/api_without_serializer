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
from django.core.mail import EmailMessage


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
        # if not user.is_authenticated:
        #     return Response({"error": "User is not authenticated."}, status=status.HTTP_401_UNAUTHORIZED)
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
    if request.user.is_staff:
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
    else:
        current_date = timezone.now() - timedelta(days=0)
        checklists = checklist.objects.filter(work_start_end_date=current_date).filter(user=request.user)
        
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
    is_staff = request.user.is_staff

    if is_staff:
        checklists = checklist.objects.all().values()
    else:
        checklists = checklist.objects.filter(user=request.user).values()

    user_id_to_email = {}

    for checklist_data in checklists:
        user_id = checklist_data['user_id']
        user = User.objects.filter(id=user_id).first()
        if user:
            user_id_to_email[user_id] = user.email
        else:
            user_id_to_email[user_id] = None

    # Include is_staff in each checklist item
    checklists_with_email = [
        {
            'is_staff': is_staff,  # Include is_staff
            'user_email': user_id_to_email[checklist_data['user_id']],
            **checklist_data
        }
        for checklist_data in checklists
    ]

    response_data = {
        "checklists": checklists_with_email,
    }

    return Response(response_data, status=200)
            
            
    # try:
    #             # Retrieve all data from the checklist model
    #             checklists = checklist.objects.all()
    #             serializer = AllSerializer(checklists,many=True)
    #             return Response(serializer.data, status=status.HTTP_200_OK)
    # except checklist.DoesNotExist:
    #             return Response(status=status.HTTP_404_NOT_FOUND)
        # if request.user.is_authenticated:
        #     authenticated_user = request.user

           
            
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



# class ZohoProjectsView(APIView):
#     def generate_access_token(self, refresh_token):
#         # Your existing code for generating the access token

#     def get(self, request, *args, **kwargs):
#         # Your existing code for retrieving the access token and project info
        
#         # Additional URI for CRM data
#         crm_uri = "https://www.zohoapis.com/crm/v3/Accounts?fields=Master_Customer_Id,Account_Name"  # Replace with the actual URI
        
#         # Make a request to the CRM URI to fetch CRM data
#         headers_crm = {
#             'Authorization': f'Bearer {access_token_for_crm}',  # Replace with the CRM access token
#         }
#         response_crm = requests.get(crm_uri, headers=headers_crm)
#         data_crm = response_crm.json() if response_crm.status_code == 200 else {}

#         # Create a set to store Master_Customer_Ids from CRM data
#         master_customer_ids = set()
#         for item in data_crm.get("data", []):
#             master_customer_id = item.get("Master_Customer_Id")
#             if master_customer_id:
#                 master_customer_ids.add(master_customer_id)

#         # Continue with your existing code to fetch and process the Zoho Projects data
#         active_projects = []

#         for project in total_projects:
#             for custom_field in project["custom_fields"]:
#                 if "Customer ID" in custom_field:
#                     customer_id = custom_field["Customer ID"]
#                     if project["status"] == "active" and customer_id in master_customer_ids:
#                         project_info = {
#                             "name": project["name"],
#                             "owner_name": project["owner_name"],
#                             "Customer ID": customer_id
#                         }
#                         active_projects.append(project_info)

#         project_info = {"projects": active_projects}
#         cache.set('project_info', project_info, timeout=7200)  # Cache for 1 hour

#         return Response(project_info)



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
    checklists_data = checklist.objects.filter(auto_increment_id=auto_increment_id).values().first()
    
    completeness_status = 'true' if is_all_filled else 'false'

    
    response_data = {
        'data': checklists_data,
        
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


# class ZohoProjects(APIView):
#     def generate_access_token(self, refresh_token):
#         url = "https://accounts.zoho.com/oauth/v2/token"
#         payload={'grant_type': 'refresh_token',
#             'client_id': '1000.4D0LT5YLPOKPGZ5IFJNVNYTP8IEVFN',
#             'client_secret': '5addc71050ce2b59934d7ba04d977c3bca5e9e6b6e',
#             'redirect_uri': 'https://www.google.com/',
#             'refresh_token': '1000.37614442538599aa9ee078f097c04422.b8e995b721dd851709c3cd2c53bee7ec'}
#         response = requests.post(url, data=payload)
#         data = response.json()
#         if 'access_token' in data:
#             return data['access_token']
#         return None
#     def get(self, request, *args, **kwargs):
#             zoho_api_url = "https://projectsapi.zoho.com/restapi/portal/687895858/projects/"
#             refresh_token = "1000.37614442538599aa9ee078f097c04422.b8e995b721dd851709c3cd2c53bee7ec"

    
        
#             headers = {
#                 'Authorization': f'Bearer {refresh_token}',
#                 "Content-Type": "application/json"
#             }
#             start = 0
#             size = 200
#             total_projects = []

#             while True:
#                 params = {
#                     "index": start,
#                     "range": size
#                 }

#                 response = requests.get(zoho_api_url, headers=headers, params=params)
#                 data = response.json()
#                 total_projects.extend(data["projects"])

#                 if len(data["projects"]) < size:
#                     break
#                 else:
#                     start += size

#             active_projects = [
#                 {"name": project["name"], "owner_name": project["owner_name"]}
#                 for project in total_projects if project["status"] == "active"
#             ]
            
#             project_info = {"projects": active_projects}
           

#             return Response(project_info)




# def retrieve_data_from_api(api_url, api_params, api_token):
#     # Set up the headers with the authorization token
#     headers = {
#         "Authorization": f"Zoho-oauthtoken 1000.eedbd8bf57afc9d78df60e3f1b8953e8.89d8415d986795b29561adfe46d2a53c"
#     }

#     # Initialize a list to store all the records
#     all_records = []

#     # Variable to track the current page
#     page = 1

#     while True:
#         # Set the page number in the parameters
#         api_params["page"] = page

#         # Make a GET request to retrieve the records for the current page
#         response = requests.get(api_url, params=api_params, headers=headers)

#         # Check if the request was successful
#         if response.status_code == 200:
#             data = response.json()
#             records = data.get("data")

#             if records:
#                 all_records.extend(records)
#                 page += 1
#             else:
#                 # No more records to retrieve
#                 break
#         else:
#             print("no data found")
#             break

#     # Now, all_records contains all the retrieved records
#     return all_records

# # Example usage:
# api_url = "https://www.zohoapis.com/crm/v3/Accounts"
# api_params = {
#     "fields": "id,Master_Customer_Id",
#     "per_page": 200
# }
# api_token = "1000.eedbd8bf57afc9d78df60e3f1b8953e8.89d8415d986795b29561adfe46d2a53c"

# result = retrieve_data_from_api(api_url, api_params, api_token)
# print(f"Total Records Retrieved: {len(result)}")





# def fetch_records(api_url, api_params, api_token):
#     all_records = []

#     headers = {
#         "Authorization": f"Zoho-oauthtoken 1000.2639509691cb1955c534b35a12c81b10.2463b4a35cce87eb6f78b95fdbd9d464"
#     }

    
#     while True:
#         # Make a GET request to retrieve data
#         response = requests.get(api_url, params=api_params, headers=headers)

#         # Check if the request was successful
#         if response.status_code == 200:
#             data = response.json()
#             records = data.get("data")

#             if records:
#                 all_records.extend(records)

#             # Check for the presence of next_page_token
#             next_page_token = data.get("next_page_token")

#             if not next_page_token:
#                 break

#             # Use the next_page_token for the next request
#             api_params["page_token"] = next_page_token
#         else:
#             print(f"Error: {response.status_code}")
#             break

#     return all_records

# # Example usage:
# api_url = "https://www.zohoapis.com/crm/v3/Accounts"
# api_params = {
#     "fields": "id,Master_Customer_Id",
#     "per_page": 200
# }
# api_token = "1000.eedbd8bf57afc9d78df60e3f1b8953e8.89d8415d986795b29561adfe46d2a53c"
# result = fetch_records(api_url, api_params, api_token)
# print(f"Total Records Retrieved: {len(result)}")




# url = "https://www.zohoapis.com/crm/v3/Accounts"

# # Initialize a list to store all the retrieved data
# all_data = []
# headers = {
#     "Authorization": "Zoho-oauthtoken 1000.2639509691cb1955c534b35a12c81b10.2463b4a35cce87eb6f78b95fdbd9d464"
# }

# next_page_token = None

# while True:  # Changed to an infinite loop since we'll break when there's no more data
#     params = {
#         "fields": "Master_Customer_Id,Account_Name",  
#         "per_page": 200
#     }

#     if next_page_token:
#         params["page_token"] = next_page_token

#     response = requests.get(url, params=params, headers=headers)

#     if response.status_code != 200:
#         print(f"Error: {response.status_code}")
#         break

#     data = response.json()
#     records = data.get("data", [])

#     if not records:
#         break  # No more data to retrieve, break out of the loop

#     all_data.extend(records)
#     page_token = data.get("info", {}).get("next_page_token")

# # print(f"Total records retrieved: {len(all_data)}")
# url = "https://www.zohoapis.com/crm/v3/Accounts"

# # Set up your API key or authorization header
# headers = {
#     "Authorization": "Zoho-oauthtoken 1000.2639509691cb1955c534b35a12c81b10.2463b4a35cce87eb6f78b95fdbd9d464"  # Replace with your actual access token
# }

# all_records = []

# # Start with the first page
# page_token = None

# while True:
#     # Set up the parameters for the API request
#     params = {
#         "fields": "Master_Customer_Id,Account_Name",
#         "per_page": 200
        
#     }

#     # If there's a page token, include it in the request
#     if page_token:
#         params["page_token"] = page_token

#     # Make the API request
#     response = requests.get(url, headers=headers, params=params)

#     # Check for errors in the response
#     if response.status_code != 200:
#         print(f"Error: {response.status_code} - {response.text}")
#         break

#     # Parse the JSON response
#     data = response.json()

#     # Extract the records from the current page
#     records = data.get("data", [])

#     # Add the records to the result
#     all_records.extend(records)

#     # Check if there are more pages to fetch
#     if not data.get("info", {}).get("more_records"):
#         break

#     # Get the next page token for the next iteration
#     page_token = data.get("info", {}).get("next_page_token")

class ZohoProjects(APIView):
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
    def generate_second_access_token(self, refresh_token):
        
        url = "https://accounts.zoho.com/oauth/v2/token"
        payload={'grant_type': 'refresh_token',
            'client_id': '1000.ZF49BE98RN6NJIHNX612AVTPY3O4DH',
            'client_secret': 'bf3a0afb93f143160bf19e0020e094bff43f509b6f',
            'redirect_uri': 'https://www.google.com/',
            'refresh_token': '1000.348aa66b79cf3f1e32b635061bbf737c.3356f2bb63ce20071ccb2706413cb3c8'}
        response = requests.post(url, data=payload)
        data = response.json()
        if 'access_token' in data:
            return data['access_token']
        return None

       

    def merge_data(self, zoho_crm_url, zoho_projects_url, access_token,access_tokend):
    # Retrieve data from Zoho CRM API
        headers = {
            "Authorization": f"Zoho-oauthtoken {access_tokend}"
        }
        all_records = []

        page_token = None

        while True:
            params = {
                "fields": "Master_Customer_Id,Account_Name",
                "per_page": 200
            }

            if page_token:
                params["page_token"] = page_token

            response = requests.get(zoho_crm_url, headers=headers, params=params)

            if response.status_code != 200:
                print(f"Error: {response.status_code} - {response.text}")
                break

            data = response.json()
            records = data.get("data", [])
            all_records.extend(records)
           

            if not data.get("info", {}).get("more_records"):
                break

            page_token = data.get("info", {}).get("next_page_token")
           

        # Extract master_customer_ids from CRM data
       

        
        # Retrieve data from Zoho Projects API
        headers = {
            "Authorization": f"Bearer {access_token}",
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

            response = requests.get(zoho_projects_url, headers=headers, params=params)
            data = response.json()
            total_projects.extend(data["projects"])

            if len(data["projects"]) < size:
                break
            else:
                start += size

        # Filter and merge relevant project data
        master_customer_ids = set()
        account_names = {}  # Store account names in a dictionary

        for item in all_records:
            master_customer_id = item.get("Master_Customer_Id")
            account_name = item.get("Account_Name")
            if master_customer_id:
                master_customer_ids.add(master_customer_id)
                # Store the account_name corresponding to the master_customer_id
                if account_name:
                    account_names[master_customer_id] = account_name

        # Filter and merge relevant project data
        merged_data = []
        for project in total_projects:
            for custom_field in project["custom_fields"]:
                if "Customer ID" in custom_field:
                    customer_id = custom_field["Customer ID"]
                    if (
                        project["status"] == "active"
                        and customer_id in master_customer_ids
                        
                    ):
                        project_info = {
                            "name": project["name"],
                            "owner_name": project["owner_name"],
                            "Customer ID": customer_id,
                            "Account_Name": account_names.get(customer_id, "")
                        }
                        merged_data.append(project_info)

        return merged_data

    def get(self, request, *args, **kwargs):
        zoho_crm_url = "https://www.zohoapis.com/crm/v3/Accounts"
        zoho_projects_url = "https://projectsapi.zoho.com/restapi/portal/687895858/projects/"
        refresh_token = "1000.37614442538599aa9ee078f097c04422.b8e995b721dd851709c3cd2c53bee7ec"
        refresh_tokend = "1000.348aa66b79cf3f1e32b635061bbf737c.3356f2bb63ce20071ccb2706413cb3c8"
        access_token_cache_key = 'zoho_access_token'
        access_tokend_cache_key = 'zoho_second_access_token'

        # Attempt to retrieve access tokens from cache
        access_token = cache.get(access_token_cache_key)
        access_tokend = cache.get(access_tokend_cache_key)

        if access_token is None:
            # If not in cache, fetch a new access token and store it in cache
            access_token = self.generate_access_token(refresh_token)
        else:
                cache.set(access_token_cache_key, access_token, timeout=3600)  # Cache for 1 hour

        if access_tokend is None:
            # If not in cache, fetch a new access token and store it in cache
            access_tokend = self.generate_second_access_token(refresh_tokend)
        else:
                cache.set(access_tokend_cache_key, access_tokend, timeout=3600)  # Cache for 1 hour

        
        if access_token and access_tokend:
            merged_data = self.merge_data(zoho_crm_url, zoho_projects_url,access_token,access_tokend)
            project_info = {"projects": merged_data}
            cache.set('project_info', project_info, timeout=7200)
            return Response(project_info)
        else:
            return Response({"error": "Failed to obtain access token"})
        
        