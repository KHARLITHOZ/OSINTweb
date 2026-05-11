import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger("osint")


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is None:
        logger.exception("Unhandled API error in %s", context.get("view"))
        return Response(
            {"error": "Error interno del servidor.", "detail": str(exc)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Normalize error shape: always {"error": "...", "detail": {...}}
    if isinstance(response.data, dict):
        if "detail" in response.data and len(response.data) == 1:
            response.data = {"error": str(response.data["detail"])}
    elif isinstance(response.data, list):
        response.data = {"error": response.data}

    return response
