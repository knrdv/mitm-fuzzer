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
		#self.forms_list: list = []
		self.fuzzdbs: dict = {"default":str(DBS_DIR + "default")}
		self.fuzz_inputs: dict = {}
		self.host_monitors: list = ["192.168.100.17"]
		self.host_filter_string = ["~d"]						# TODO: Change to list
		self.last_used_token = None
		self.fresh_token = None
		self.fuzzed_url = None
		self.fuzz_flows = {"POST":None, "GET":None}
		self.fuzz_in_progress = False

		self.SD = SuccessDetector()
		self.SD.setSuccessString("have logged in")

	# Handle detected form, returns dict 
	def formHandler(self, flow: http.HTTPFlow) -> None:
		to_fuzz = self.mapFuzzDict(flow.request)
		if to_fuzz:
			ctx.log.info("FormFuzz: fuzzing parameters were detected, starting fuzzing")
			self.fuzz_flows["POST"] = flow.copy()
			self.fuzzed_url = flow.request.url
			self.loadFuzzInputs()
			self.fuzz_in_progress = True


	# Identify and map fuzzed parameters to fuzz files
	def mapFuzzDict(self, parameters: net.http.request) -> bool:
		fuzz = False
		parameters = parameters.urlencoded_form
		for parameter in parameters:
			value = parameters[parameter]
			if value.startswith(PARAMETER_PREFIX):
				self.fuzzdbs[parameter] = DBS_DIR + value[PREFIX_LEN:]
				if not os.path.exists(self.fuzzdbs[parameter]):
					ctx.log.error("FormFuzz: fuzz database " + self.fuzzdbs[parameter] + " does not exist")
				else:
					ctx.log.info("FormFuzz: fuzzing db choice " + str(parameter) + " => " + self.fuzzdbs[parameter])
					fuzz = True
		return fuzz

	def loadFuzzInputs(self) -> None:
		for parameter in self.fuzzdbs:
			inputs = self.loadFuzzParameters(parameter)
			self.fuzz_inputs[parameter] = inputs
			logger.info("LOADED FUZZ INPUTS FOR " + parameter)

	# Load fuzz parameters from file into a dict
	def loadFuzzParameters(self, parameter: str) -> list:
		param_path = self.fuzzdbs[parameter]
		if not os.path.exists(param_path):
			ctx.log.info(param_path)
			ctx.log.warn("FormFuzz: path " + param_path + " for parameter " + parameter + " does not exist")
		with open(param_path, "r") as f:
			fuzz_params = [x.strip() for x in f]
		return fuzz_params

	def extractCSRF(self, flow: http.HTTPFlow) -> str:
		if not flow.response:
			logger.info("ERROR: TRYING TO EXTRACT TOKEN FROM AN EMPTY RESPONSE")
		parsed_html = BeautifulSoup(flow.response.content, features="html.parser")
		csrf_token = parsed_html.body.find("input", attrs={"name":"user_token"}).get("value")
		return csrf_token

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
		ctx.master.commands.call("view.filter.set", "~d 192.168.100.17")

	# Listen on requests and detect forms from specified hosts
	def request(self, flow: http.HTTPFlow) -> None:
		if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
			self.last_used_token = flow.request.urlencoded_form["user_token"]
			logger.info("SPENT CSRF TOKEN: " + self.last_used_token)
		if flow.is_replay == "request":
			return
		if flow.request.method == "POST" and flow.request.host in self.host_monitors and not flow.is_replay == "request":
			#ctx.log.info("FormFuzz: form data detected from " + str(flow.request.host))
			self.formHandler(flow)
		if flow.request.method == "GET" and flow.request.url == self.fuzzed_url:
			logger.info("GOT GET REQUEST FROM CLIENT " + str(flow))
			#ctx.master.commands.call("replay.client", [flow])

		if flow.request.method == "GET":
			return

	
	def response(self, flow: http.HTTPFlow):
		if flow.request.method == "GET" and flow.request.host in self.host_monitors:
			#logger.info("FormFuzz: RECEIVED NEW GET RESPONSE FROM SERVER: " + str(flow.response.text))

			if self.fuzz_in_progress:
				creds = self.SD.detector(flow)
				if creds:
					self.fuzz_in_progress = False
					logger.info("Credentials: " + str(creds))
					return

				self.fresh_token = self.extractCSRF(flow)
				#logger.info("GOT FRESH TOKEN: " + self.fresh_token)
				self.fuzz_flows["GET"] = flow.copy()

				post_flow = self.fuzz_flows["POST"].copy()
				post_flow.request.urlencoded_form["user_token"] = self.fresh_token
				for param in post_flow.request.urlencoded_form:
					if param in self.fuzz_inputs:
						if self.fuzz_inputs[param]:
							post_flow.request.urlencoded_form[param] = self.fuzz_inputs[param].pop()
							self.SD.setCredentials({param:post_flow.request.urlencoded_form[param]})
							break
						else:
							logger.info("Fuzzing done, nothing found")
							self.fuzz_in_progress = False
							return
				logger.info("FROM response REPLAYING POST REQUEST FORM WITH PARAMETERS " + str(post_flow.request.urlencoded_form))
				ctx.master.commands.call("replay.client", [post_flow])

		if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
			#logger.info("RECEIVED POST RESPONSE FROM SERVER " + str(flow.response.status_code))
			self.fuzz_flows["POST"] = flow.copy()
			if flow.response.status_code == 302 and self.fuzz_in_progress and self.fuzz_flows["GET"]:
				get_flow = self.fuzz_flows["GET"].copy()
				redirect_location = flow.response.headers["Location"]
				logger.info("PATH COMPONENTS: " + str(get_flow.request.path_components))
				get_flow.request.path_components = get_flow.request.path_components[:-1] + (redirect_location, )
				logger.info("NEW PATH COMPONENTS:" + str(get_flow.request.path_components))
				logger.info("NEW LOCATION IS: " + redirect_location)
				logger.info("GET FLOW FROM 302: " + str(get_flow.request))
				ctx.master.commands.call("replay.client", [get_flow])
				#ctx.master.commands.call("replay.server", [flow])
				logger.info("REPLAYED 302 TO SERVER")



addons = [
	FormFuzz()
]