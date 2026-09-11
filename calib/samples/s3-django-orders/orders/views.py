import logging
import pickle

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import Order

log = logging.getLogger(__name__)


def order_detail(request, order_id):
    order = Order.objects.get(pk=order_id)
    return JsonResponse({"id": order.id, "owner": order.owner.email, "total": order.total})


@csrf_exempt
def restore_cart(request):
    blob = request.POST.get("cart")
    cart = pickle.loads(bytes.fromhex(blob))
    return JsonResponse({"items": len(cart)})


def login(request):
    user = request.POST.get("user")
    pw = request.POST.get("pw")
    log.info("login user=%s pw=%s", user, pw)
    if user == "admin" and pw == "admin123":
        request.session["role"] = "admin"
    return HttpResponse("ok")


def render_banner(request):
    return HttpResponse("<div class=banner>" + request.GET.get("text", "") + "</div>")
