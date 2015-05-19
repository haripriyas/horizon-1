# Copyright 2012 Nebula, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from django import shortcuts
import django.views.decorators.vary

import horizon
from horizon import base
from horizon import exceptions
import logging

LOG = logging.getLogger(__name__)
LOG.info(__name__)
def get_user_home(user):
    dashboard = None
    if user.is_superuser:
        try:
            dashboard = horizon.get_dashboard('admin')
        except base.NotRegistered:
            pass

    if dashboard is None:
        dashboard = horizon.get_default_dashboard()
    return dashboard.get_absolute_url()


@django.views.decorators.vary.vary_on_cookie
def splash(request):
    LOG.info("In splash function")
    if not request.user.is_authenticated():
	LOG.info("User not autenticated ")
        raise exceptions.NotAuthenticated()

    #check whether otp page is shown, if not show.
    if not 'otp_shown' in request.session :
	response = shortcuts.redirect('/otp')
    else :
	if not request.session['otp_shown']:
		response = shortcuts.redirect('/otp')
    response = shortcuts.redirect('/otp')
    if 'logout_reason' in request.COOKIES:
        response.delete_cookie('logout_reason')
    #response.delete_cookie('sessionid')
    return response

def callKeystone(request):
	"""
	Function to call keystone API for OTP authentication.
	This will call keystone API and do the current token authentication and will send the submitted OTP for validation.
	@param : request
	"""
	try :
		import urllib2
		otpVal = request.GET.get("otp","")
		data = '{ "auth": { "identity":{ "otp": {"otp_value": "' + otpVal + '"}, "methods": ["token","otp"],"token": { "id":"' + request.user.token.id +'"}   } }  }'

		url = 'http://localhost:5000/v3/auth/tokens'
		req = urllib2.Request(url, data, {'Content-Type': 'application/json','X-Auth-Token':request.user.token.id})
		try :
			f = urllib2.urlopen(req)
			for x in f:
			    print(x)
			    request.session['otp_valid'] = True
			    request.session['otp_invalid'] = False
			f.close()
		except Exception, e :
			# Authentication failed case
			request.session['otp_invalid'] = True
			request.session['otp_valid'] = False
			LOG.info(e)
			return False
		response = shortcuts.redirect(horizon.get_user_home(request.user))
		return response
	except Exception,e:
		LOG.debug("Error occured while connecting to Keystone")
		response = shortcuts.redirect('/otp')
	        return response

