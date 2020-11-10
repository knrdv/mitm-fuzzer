""" TODO: Description """

# Imports
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import command
from mitmproxy import net
import mitmproxy.addonmanager
import os.path
from bs4 import BeautifulSoup
import logging
from utils import SuccessDetector

# NEW
from utils import Attack


PARAMETER_PREFIX = "fuzz_"
PREFIX_LEN = len(PARAMETER_PREFIX)
DBS_DIR = "./dbs/"
LOGFILE = "./formfuzz.log"

logger = logging.getLogger("formfuzz")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOGFILE)
formatter = logging.Formatter("%(name)s:%(levelname)s:%(message)s")
fh.setFormatter(formatter)
logger.addHandler(fh)
open(LOGFILE, "w").close()


class FormFuzz:

	# CLASS METHODS

	def __init__(self):
		self.host_monitors: list = ["192.168.100.17"]
		self.host_filter_string = ["~d"]

		# NEW
		self.attack = Attack()

	def checkPOST(self, flow: http.HTTPFlow) -> bool:
		fuzz = False
		parameters = flow.request.urlencoded_form
		for parameter in parameters:
			value = parameters[parameter]
			if value.startswith(PARAMETER_PREFIX):
				fuzz = True
				break
		return fuzz

# MITM COMMANDS

	# Add new host monitor
	@command.command("formfuzz.addhostmon")
	def addhostmon(self, host: str) -> None:
		self.host_monitors.append(host)
		self.host_filter_string.append(host)
		ctx.log.info("FormFuzz: successfully added new host monitor: " + host)
		ctx.master.commands.call("view.filter.set", ' '.join(self.host_filter_string))


# MITM EVENTS

	# Addon successfully loaded
	def load(self, entry: mitmproxy.addonmanager.Loader):
		#print("FormFuzz addon loaded successfully.")
		ctx.log.info("FormFuzz: addon loaded successfully")
		self.host_filter_string.append(self.host_monitors[0])
		ctx.master.commands.call("view.filter.set", ' '.join(self.host_filter_string))

	# Listen on requests and detect forms from specified hosts
	def request(self, flow: http.HTTPFlow) -> None:
		if self.attack.isRunning():
			self.attack.handleRequest(flow)
		else:
			if flow.request.method == "POST" and flow.request.host in self.host_monitors and not flow.is_replay:
				if self.checkPOST(flow):
					self.attack.start(flow)




	#def request(self, flow: http.HTTPFlow) -> None:
	#	if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
	#		self.last_used_token = flow.request.urlencoded_form["user_token"]
	#		logger.info("SPENT CSRF TOKEN: " + self.last_used_token)
	#	if flow.is_replay == "request":
	#		return
	#	if flow.request.method == "POST" and flow.request.host in self.host_monitors and not flow.is_replay == "request":
	#		#ctx.log.info("FormFuzz: form data detected from " + str(flow.request.host))
	#		self.formHandler(flow)
	#	if flow.request.method == "GET" and flow.request.url == self.fuzzed_url:
	#		logger.info("GOT GET REQUEST FROM CLIENT " + str(flow))
	#		#ctx.master.commands.call("replay.client", [flow])

	#	if flow.request.method == "GET":
	#		return

	def response(self, flow: http.HTTPFlow) -> None:
		if self.attack.isRunning():
			self.attack.handleResponse(flow)

	#def response(self, flow: http.HTTPFlow):
	#	if flow.request.method == "GET" and flow.request.host in self.host_monitors:
	#		#logger.info("FormFuzz: RECEIVED NEW GET RESPONSE FROM SERVER: " + str(flow.response.text))

	#		if self.fuzz_in_progress:
	#			creds = self.SD.detector(flow)
	#			if creds:
	#				self.fuzz_in_progress = False
	#				logger.info("Credentials: " + str(creds))
	#				return

		# 		self.fresh_token = self.extractCSRF(flow)
		# 		#logger.info("GOT FRESH TOKEN: " + self.fresh_token)
		# 		self.fuzz_flows["GET"] = flow.copy()

		# 		post_flow = self.fuzz_flows["POST"].copy()
		# 		post_flow.request.urlencoded_form["user_token"] = self.fresh_token
		# 		for param in post_flow.request.urlencoded_form:
		# 			if param in self.fuzz_inputs:
		# 				if self.fuzz_inputs[param]:
		# 					post_flow.request.urlencoded_form[param] = self.fuzz_inputs[param].pop()
		# 					self.SD.setCredentials({param:post_flow.request.urlencoded_form[param]})
		# 					break
		# 				else:
		# 					logger.info("Fuzzing done, nothing found")
		# 					self.fuzz_in_progress = False
		# 					return
		# 		logger.info("FROM response REPLAYING POST REQUEST FORM WITH PARAMETERS " + str(post_flow.request.urlencoded_form))
		# 		ctx.master.commands.call("replay.client", [post_flow])

		# if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
		# 	#logger.info("RECEIVED POST RESPONSE FROM SERVER " + str(flow.response.status_code))
		# 	self.fuzz_flows["POST"] = flow.copy()
		# 	if flow.response.status_code == 302 and self.fuzz_in_progress and self.fuzz_flows["GET"]:
		# 		get_flow = self.fuzz_flows["GET"].copy()
		# 		redirect_location = flow.response.headers["Location"]
		# 		logger.info("PATH COMPONENTS: " + str(get_flow.request.path_components))
		# 		get_flow.request.path_components = get_flow.request.path_components[:-1] + (redirect_location, )
		# 		logger.info("NEW PATH COMPONENTS:" + str(get_flow.request.path_components))
		# 		logger.info("NEW LOCATION IS: " + redirect_location)
		# 		logger.info("GET FLOW FROM 302: " + str(get_flow.request))
		# 		ctx.master.commands.call("replay.client", [get_flow])
		# 		#ctx.master.commands.call("replay.server", [flow])
		# 		logger.info("REPLAYED 302 TO SERVER")



addons = [
	FormFuzz()
]