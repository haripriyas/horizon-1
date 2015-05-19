from django.http import HttpResponse
from django.template import RequestContext, loader
from openstack_dashboard.views import get_user_home,callKeystone
from django import shortcuts
from horizon import exceptions
import logging

LOG = logging.getLogger(__name__)

def index(request):
    """
    Function to show the OTP page.
    @param : request
    @return : HTTP response
    """
#    request.session['otp_invalid'] = False
    if not request.user.is_authenticated():
        LOG.info("User not autenticated ")
        raise exceptions.NotAuthenticated()

    template = loader.get_template('auth/otp.html')
    context = RequestContext(request, {
        'otpVal': "test",
    })

    return HttpResponse(template.render(context))

def otpSubmit(request) :
	"""
	OTP submit call. This will get the submitted OTP from request and call keystone for OTP validation.
	@param : request object
	"""	 
	res = callKeystone(request)
	if res :
		response = shortcuts.redirect(get_user_home(request.user))
		return response
	else :
		response = shortcuts.redirect('/otp')
                return response

def backToLogin(request):
	"""
	Function to destroy session and move back to login screen.
	"""
	request.session.flush()
	return shortcuts.redirect("/auth/login")
