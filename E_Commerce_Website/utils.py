from rest_framework import status
from rest_framework.views import exception_handler
from userauths import models as userauthsapi_models      # Adjust if `adminapi` is not the correct path


def custom_exception_handler(exc, context):
    """
    Custom exception handler to provide more user-friendly error messages.
    """
    # Call the default exception handler first
    response = exception_handler(exc, context)

    if response is not None:
        # Customize the response format
        if response.status_code == status.HTTP_401_UNAUTHORIZED:
            response.data = {
                "success": False,
                "message": "Authentication credentials were not provided.",
                "data": None,
            }
        elif response.status_code == status.HTTP_403_FORBIDDEN:
            response.data = {
                "success": False,
                "message": "You do not have permission to perform this action.",
                "data": None,
            }

    return response