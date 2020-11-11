""" Fuzzing addon for mitmproxy

This mitmproxy addon implements simple fuzzing functionality for POST forms.
Usage: Choose one parameter in the fuzz as: 'fuzz_DBNAME' where DBNAME is 
the list of fuzz inputs contained inside a file in the DBS_DIR.
"""
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import command
from mitmproxy import net
import mitmproxy.addonmanager
import logging
from utils import Attack

PARAMETER_PREFIX = "fuzz_"
PREFIX_LEN = len(PARAMETER_PREFIX)
DBS_DIR = "./dbs/"
LOGFILE = "./formfuzz.log"
TEST_HOST = "127.0.0.2"

logger = logging.getLogger("formfuzz")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(LOGFILE)
formatter = logging.Formatter("%(name)s:%(levelname)s:%(message)s")
fh.setFormatter(formatter)
logger.addHandler(fh)
open(LOGFILE, "w").close()

class FormFuzz:
	"""A class with purpose of detection of attack-trigger parameters."""

	def __init__(self):
		self.host_monitors: list = [TEST_HOST]
		self.host_filter_string = ["~d"]
		self.attack = Attack()

	def detectFuzzParams(self, flow: http.HTTPFlow) -> bool:
		"""Checks POST request for trigger parameters."""
		#if not flow.request.method == "POST": logger.error("Not a POST request.")
		if flow.request.method == "POST":
			parameters = flow.request.urlencoded_form
		elif flow.request.method == "GET":
			parameters = flow.request.query
		else:
			logger.warning("Triggering parameters not detected in the request.")
		fuzz = False
		for parameter in parameters:
			if parameters[parameter].startswith(PARAMETER_PREFIX):
				fuzz = True
				break
		return fuzz


# MITM COMMANDS

	@command.command("formfuzz.addhostmon")
	def addhostmon(self, host: str) -> None:
		"""Adds host to the list of monitored hosts."""

		self.host_monitors.append(host)
		self.host_filter_string.append(host)
		ctx.log.info("FormFuzz: successfully added new host monitor: " + host)
		ctx.master.commands.call("view.filter.set", ' '.join(self.host_filter_string))

	@command.command("formfuzz.setsuccess")
	def setsuccess(self, success_string: str) -> None:
		"""Sets a string which determines a successful use of credentials."""
		
		self.attack.setSuccessString(success_string)
		logger.log("Success string set to: " + success_string)


# MITM EVENTS

	def load(self, entry: mitmproxy.addonmanager.Loader):
		"""Triggers after mitmproxy addon has been loaded."""

		ctx.log.info("FormFuzz: addon loaded successfully")
		self.host_filter_string.append(self.host_monitors[0])
		ctx.master.commands.call("view.filter.set", ' '.join(self.host_filter_string))

	def request(self, flow: http.HTTPFlow) -> None:
		"""Triggers an attack when correct parameters are detected."""

		if self.attack.isRunning():
			self.attack.handleRequest(flow)
		elif flow.request.host in self.host_monitors and not flow.is_replay:
			if self.detectFuzzParams(flow):
				self.attack.start(flow)

	def response(self, flow: http.HTTPFlow) -> None:
		"""Forwards responses."""
		if self.attack.isRunning():
			self.attack.handleResponse(flow)

addons = [
	FormFuzz()
]