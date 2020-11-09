""" TODO: Description """

# Imports
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import command
from mitmproxy import net
from mitmproxy.script import concurrent
import mitmproxy.addonmanager
import os.path
import requests
from bs4 import BeautifulSoup
import time


PARAMETER_PREFIX = "fuzz_"
PREFIX_LEN = len(PARAMETER_PREFIX)


class FormFuzz:

	# CLASS METHODS

	def __init__(self):
		#self.forms_list: list = []
		self.fuzzdbs: dict = {"default":"./default_fuzz_db"}
		self.fuzz_inputs: dict = {}
		self.host_monitors: list = ["192.168.100.17"]
		self.host_filter_string = ["~d"]						# TODO: Change to list
		self.logfile = "./formfuzz.log"
		open(self.logfile, "w").close()
		self.last_used_token = None

		self.fresh_token = None
		self.fuzzed_url = None
		self.fuzz_flows = {"POST":None, "GET":None}
		self.fuzz_in_progress = False


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
				self.fuzzdbs[parameter] = value[PREFIX_LEN:]
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
			self.filelog("LOADED FUZZ INPUTS FOR " + parameter)

	# Load fuzz parameters from file into a dict
	def loadFuzzParameters(self, parameter: str) -> list:
		param_path = self.fuzzdbs[parameter]
		if not os.path.exists(param_path):
			ctx.log.warning("FormFuzz: path " + param_path + " for parameter " + parameter + " does not exist")
		with open(param_path, "r") as f:
			fuzz_params = [x.strip() for x in f]
		return fuzz_params


	def filelog(self, line: str) -> None:
		with open(self.logfile, "a") as f:
			f.write(line + "\n\n")

	def extractCSRF(self, flow: http.HTTPFlow) -> str:
		if not flow.response:
			self.filelog("ERROR: TRYING TO EXTRACT TOKEN FROM AN EMPTY RESPONSE")
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
			self.filelog("SPENT CSRF TOKEN: " + self.last_used_token)
		if flow.is_replay == "request":
			return
		if flow.request.method == "POST" and flow.request.host in self.host_monitors and not flow.is_replay == "request":
			#ctx.log.info("FormFuzz: form data detected from " + str(flow.request.host))
			self.formHandler(flow)
		if flow.request.method == "GET" and flow.request.url == self.fuzzed_url:
			self.filelog("GOT GET REQUEST FROM CLIENT " + str(flow))
			#ctx.master.commands.call("replay.client", [flow])

		if flow.request.method == "GET":
			return

	
	def response(self, flow: http.HTTPFlow):
		if flow.request.method == "GET" and flow.request.path == "/dvwa/index.php":
			returnq
		if flow.request.method == "GET" and flow.request.host in self.host_monitors:
			self.filelog("FormFuzz: RECEIVED NEW GET RESPONSE FROM SERVER: " + str(flow.response.text))

			if self.fuzz_in_progress:
				self.fresh_token = self.extractCSRF(flow)
				#self.filelog("GOT FRESH TOKEN: " + self.fresh_token)
				self.fuzz_flows["GET"] = flow.copy()

				post_flow = self.fuzz_flows["POST"].copy()
				post_flow.request.urlencoded_form["user_token"] = self.fresh_token
				for param in post_flow.request.urlencoded_form:
					if param in self.fuzz_inputs:
						if self.fuzz_inputs[param]:
							post_flow.request.urlencoded_form[param] = self.fuzz_inputs[param].pop()
							break
						else:
							self.filelog("FUZZING DONE")
							self.fuzz_in_progress = False
							return
				self.filelog("FROM response REPLAYING POST REQUEST FORM WITH PARAMETERS " + str(post_flow.request.urlencoded_form))
				ctx.master.commands.call("replay.client", [post_flow])

		if flow.request.method == "POST" and flow.request.url == self.fuzzed_url:
			self.filelog("RECEIVED POST RESPONSE FROM SERVER " + str(flow.response.status_code))
			self.fuzz_flows["POST"] = flow.copy()
			if flow.response.status_code == 302 and self.fuzz_in_progress and self.fuzz_flows["GET"]:
				get_flow = self.fuzz_flows["GET"].copy()
				redirect_location = flow.response.headers["Location"]
				self.filelog("PATH COMPONENTS: " + str(get_flow.request.path_components))
				get_flow.request.path_components = get_flow.request.path_components[:-1] + (redirect_location, )
				self.filelog("NEW PATH COMPONENTS:" + str(get_flow.request.path_components))
				self.filelog("NEW LOCATION IS: " + redirect_location)
				self.filelog("GET FLOW FROM 302: " + str(get_flow.request))
				ctx.master.commands.call("replay.client", [get_flow])
				#ctx.master.commands.call("replay.server", [flow])
				self.filelog("REPLAYED 302 TO SERVER")



addons = [
	FormFuzz()
]